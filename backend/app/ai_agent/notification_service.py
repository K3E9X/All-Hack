"""
Notification Service for sending email notifications when scans complete
Supports multiple notification channels (email, webhook, Slack, etc.)
"""

import logging
import smtplib
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any, List
from datetime import datetime

import aiohttp

from app.models.scan import ScanResult
from app.config import settings

logger = logging.getLogger(__name__)


class NotificationService:
    """
    Service for sending notifications when scans complete
    Supports: Email, Webhooks, Slack
    """

    def __init__(self):
        """Initialize notification service with configuration"""
        self.email_enabled = self._check_email_config()
        self.webhook_enabled = hasattr(settings, 'NOTIFICATION_WEBHOOK_URL')
        self.slack_enabled = hasattr(settings, 'SLACK_WEBHOOK_URL')

        if self.email_enabled:
            logger.info("✉️  Email notifications enabled")
        if self.webhook_enabled:
            logger.info("🔔 Webhook notifications enabled")
        if self.slack_enabled:
            logger.info("💬 Slack notifications enabled")

    def _check_email_config(self) -> bool:
        """Check if email configuration is complete"""
        required = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USERNAME', 'SMTP_PASSWORD', 'NOTIFICATION_EMAIL_FROM']
        return all(hasattr(settings, attr) for attr in required)

    async def notify_scan_complete(self, scan_result: ScanResult,
                                  recipients: Optional[List[str]] = None,
                                  summary: Optional[str] = None) -> bool:
        """
        Send notification when scan completes

        Args:
            scan_result: Completed scan result
            recipients: Email addresses to notify (if None, uses settings.NOTIFICATION_EMAIL_TO)
            summary: Optional custom summary text

        Returns:
            True if notification sent successfully
        """
        success = False

        # Email notification
        if self.email_enabled:
            email_sent = await self._send_email_notification(scan_result, recipients, summary)
            success = success or email_sent

        # Webhook notification
        if self.webhook_enabled:
            webhook_sent = await self._send_webhook_notification(scan_result)
            success = success or webhook_sent

        # Slack notification
        if self.slack_enabled:
            slack_sent = await self._send_slack_notification(scan_result, summary)
            success = success or slack_sent

        if not success:
            logger.warning("⚠️  No notification channels enabled or all failed")

        return success

    async def _send_email_notification(self, scan_result: ScanResult,
                                      recipients: Optional[List[str]] = None,
                                      summary: Optional[str] = None) -> bool:
        """Send email notification"""
        try:
            # Get recipients
            if not recipients:
                recipients = getattr(settings, 'NOTIFICATION_EMAIL_TO', [])
                if isinstance(recipients, str):
                    recipients = [recipients]

            if not recipients:
                logger.warning("⚠️  No email recipients configured")
                return False

            # Build email content
            subject = f"🎯 Pentest Complete: {scan_result.target_url}"

            # Generate HTML email
            html_content = self._generate_email_html(scan_result, summary)
            text_content = summary or self._generate_text_summary(scan_result)

            # Create message
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = settings.SMTP_USERNAME
            message['To'] = ', '.join(recipients)

            # Attach text and HTML versions
            text_part = MIMEText(text_content, 'plain')
            html_part = MIMEText(html_content, 'html')

            message.attach(text_part)
            message.attach(html_part)

            # Send email
            await self._send_smtp_email(message, recipients)

            logger.info(f"✅ Email notification sent to {len(recipients)} recipient(s)")
            return True

        except Exception as e:
            logger.error(f"❌ Failed to send email notification: {e}")
            return False

    async def _send_smtp_email(self, message: MIMEMultipart, recipients: List[str]):
        """Send email via SMTP (runs in thread pool to avoid blocking)"""

        def _send():
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                if hasattr(settings, 'SMTP_USE_TLS') and settings.SMTP_USE_TLS:
                    server.starttls()

                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.send_message(message)

        # Run in thread pool to avoid blocking async loop
        await asyncio.get_event_loop().run_in_executor(None, _send)

    def _generate_text_summary(self, scan_result: ScanResult) -> str:
        """Generate plain text summary"""
        critical = len([v for v in scan_result.vulnerabilities if v.severity.value == 'critical'])
        high = len([v for v in scan_result.vulnerabilities if v.severity.value == 'high'])
        medium = len([v for v in scan_result.vulnerabilities if v.severity.value == 'medium'])
        low = len([v for v in scan_result.vulnerabilities if v.severity.value == 'low'])

        duration = scan_result.end_time - scan_result.start_time if scan_result.end_time else "In progress"

        summary = f"""
Penetration Test Complete!

Target: {scan_result.target_url}
Scan ID: {scan_result.scan_id}
Mode: {scan_result.mode.value}
Duration: {duration}

Vulnerabilities Found:
  Critical: {critical}
  High: {high}
  Medium: {medium}
  Low: {low}

  Total: {len(scan_result.vulnerabilities)}

Endpoints Discovered: {len(scan_result.discovered_endpoints)}
Technologies Detected: {len(scan_result.detected_technologies)}

View full results: {getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')}/results?scan_id={scan_result.scan_id}
"""

        # Add critical vulnerabilities
        critical_vulns = [v for v in scan_result.vulnerabilities if v.severity.value == 'critical']
        if critical_vulns:
            summary += "\n\nTop Critical Vulnerabilities:\n"
            for idx, vuln in enumerate(critical_vulns[:5], 1):
                summary += f"\n{idx}. {vuln.title}\n"
                summary += f"   URL: {vuln.affected_url}\n"
                summary += f"   Category: {vuln.category.value}\n"

        return summary.strip()

    def _generate_email_html(self, scan_result: ScanResult, summary: Optional[str] = None) -> str:
        """Generate HTML email content"""
        critical = len([v for v in scan_result.vulnerabilities if v.severity.value == 'critical'])
        high = len([v for v in scan_result.vulnerabilities if v.severity.value == 'high'])
        medium = len([v for v in scan_result.vulnerabilities if v.severity.value == 'medium'])
        low = len([v for v in scan_result.vulnerabilities if v.severity.value == 'low'])

        # Determine overall risk level
        if critical > 0:
            risk_level = "CRITICAL"
            risk_color = "#dc2626"
        elif high > 0:
            risk_level = "HIGH"
            risk_color = "#f97316"
        elif medium > 0:
            risk_level = "MEDIUM"
            risk_color = "#eab308"
        else:
            risk_level = "LOW"
            risk_color = "#22c55e"

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .content {{ background: #f8fafc; padding: 30px; border-radius: 0 0 10px 10px; }}
        .stats {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin: 20px 0; }}
        .stat-box {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-box h3 {{ margin: 0 0 10px 0; font-size: 14px; color: #64748b; text-transform: uppercase; }}
        .stat-box .value {{ font-size: 32px; font-weight: bold; color: #1e293b; }}
        .risk-badge {{ display: inline-block; padding: 8px 16px; border-radius: 20px; font-weight: bold; background: {risk_color}; color: white; }}
        .vuln-list {{ background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .vuln-item {{ padding: 15px; border-left: 4px solid #dc2626; margin: 10px 0; background: #fef2f2; }}
        .btn {{ display: inline-block; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0; }}
        .footer {{ text-align: center; padding: 20px; color: #64748b; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Penetration Test Complete</h1>
            <p>Your automated security scan has finished</p>
        </div>

        <div class="content">
            <h2>Target: {scan_result.target_url}</h2>
            <p><strong>Scan ID:</strong> {scan_result.scan_id}</p>
            <p><strong>Overall Risk:</strong> <span class="risk-badge">{risk_level}</span></p>

            <div class="stats">
                <div class="stat-box">
                    <h3>Total Vulnerabilities</h3>
                    <div class="value">{len(scan_result.vulnerabilities)}</div>
                </div>
                <div class="stat-box">
                    <h3>Critical</h3>
                    <div class="value" style="color: #dc2626;">{critical}</div>
                </div>
                <div class="stat-box">
                    <h3>High</h3>
                    <div class="value" style="color: #f97316;">{high}</div>
                </div>
                <div class="stat-box">
                    <h3>Medium</h3>
                    <div class="value" style="color: #eab308;">{medium}</div>
                </div>
            </div>

            <div class="stats">
                <div class="stat-box">
                    <h3>Endpoints</h3>
                    <div class="value">{len(scan_result.discovered_endpoints)}</div>
                </div>
                <div class="stat-box">
                    <h3>Technologies</h3>
                    <div class="value">{len(scan_result.detected_technologies)}</div>
                </div>
            </div>
"""

        # Add critical vulnerabilities
        critical_vulns = [v for v in scan_result.vulnerabilities if v.severity.value == 'critical']
        if critical_vulns:
            html += """
            <div class="vuln-list">
                <h3>⚠️ Critical Vulnerabilities</h3>
"""
            for vuln in critical_vulns[:5]:
                html += f"""
                <div class="vuln-item">
                    <strong>{vuln.title}</strong><br>
                    <small>URL: {vuln.affected_url}</small><br>
                    <small>Category: {vuln.category.value}</small>
                </div>
"""
            html += """
            </div>
"""

        # Add view results button
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')
        html += f"""
            <a href="{frontend_url}/results?scan_id={scan_result.scan_id}" class="btn">
                View Full Results 📊
            </a>

            <div class="footer">
                <p>This is an automated notification from your Penetration Testing Tool</p>
                <p>Scan completed at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
            </div>
        </div>
    </div>
</body>
</html>
"""

        return html

    async def _send_webhook_notification(self, scan_result: ScanResult) -> bool:
        """Send webhook notification"""
        try:
            webhook_url = getattr(settings, 'NOTIFICATION_WEBHOOK_URL', None)
            if not webhook_url:
                return False

            payload = {
                "scan_id": scan_result.scan_id,
                "target_url": scan_result.target_url,
                "status": scan_result.status,
                "vulnerability_count": len(scan_result.vulnerabilities),
                "critical_count": len([v for v in scan_result.vulnerabilities if v.severity.value == 'critical']),
                "timestamp": datetime.utcnow().isoformat()
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, timeout=10) as response:
                    if response.status == 200:
                        logger.info("✅ Webhook notification sent")
                        return True
                    else:
                        logger.warning(f"⚠️  Webhook returned status {response.status}")
                        return False

        except Exception as e:
            logger.error(f"❌ Failed to send webhook notification: {e}")
            return False

    async def _send_slack_notification(self, scan_result: ScanResult, summary: Optional[str] = None) -> bool:
        """Send Slack notification"""
        try:
            slack_url = getattr(settings, 'SLACK_WEBHOOK_URL', None)
            if not slack_url:
                return False

            critical = len([v for v in scan_result.vulnerabilities if v.severity.value == 'critical'])
            high = len([v for v in scan_result.vulnerabilities if v.severity.value == 'high'])

            # Determine emoji based on severity
            if critical > 0:
                emoji = "🚨"
            elif high > 0:
                emoji = "⚠️"
            else:
                emoji = "✅"

            payload = {
                "text": f"{emoji} *Pentest Complete: {scan_result.target_url}*",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*{emoji} Penetration Test Complete*\n\n*Target:* `{scan_result.target_url}`\n*Scan ID:* `{scan_result.scan_id}`"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Total Vulns:*\n{len(scan_result.vulnerabilities)}"},
                            {"type": "mrkdwn", "text": f"*Critical:*\n{critical}"},
                            {"type": "mrkdwn", "text": f"*High:*\n{high}"},
                            {"type": "mrkdwn", "text": f"*Endpoints:*\n{len(scan_result.discovered_endpoints)}"}
                        ]
                    }
                ]
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(slack_url, json=payload, timeout=10) as response:
                    if response.status == 200:
                        logger.info("✅ Slack notification sent")
                        return True
                    else:
                        logger.warning(f"⚠️  Slack webhook returned status {response.status}")
                        return False

        except Exception as e:
            logger.error(f"❌ Failed to send Slack notification: {e}")
            return False
