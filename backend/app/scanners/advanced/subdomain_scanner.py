"""
Subdomain Enumeration Scanner
"""
import asyncio
import logging
import dns.resolver
import dns.exception
from typing import List, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class SubdomainScanner:
    """Enumerate subdomains for target domain"""

    # Common subdomains
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'webdisk', 'ns', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
        'api', 'dev', 'staging', 'test', 'qa', 'uat', 'prod', 'production',
        'admin', 'portal', 'dashboard', 'app', 'mobile', 'm', 'blog', 'shop',
        'store', 'cdn', 'static', 'assets', 'images', 'img', 'media',
        'files', 'download', 'downloads', 'support', 'help', 'docs',
        'vpn', 'remote', 'access', 'secure', 'ssl', 'gateway',
        'beta', 'alpha', 'demo', 'preview', 'stage', 'backup',
        'db', 'database', 'sql', 'mysql', 'postgres', 'mongo',
        'redis', 'cache', 'queue', 'worker', 'jobs',
        'mail1', 'mail2', 'email', 'exchange', 'imap', 'pop3',
        'git', 'gitlab', 'github', 'bitbucket', 'jenkins', 'ci', 'cd',
        'monitoring', 'metrics', 'grafana', 'kibana', 'elastic',
        'status', 'health', 'ping', 'probe',
        'old', 'new', 'legacy', 'v1', 'v2', 'v3',
        'web', 'web1', 'web2', 'www1', 'www2',
        'cloud', 'paas', 'iaas', 'saas',
        'internal', 'intranet', 'extranet', 'corp', 'corporate',
    ]

    def __init__(self, target_url: str):
        parsed = urlparse(target_url)
        self.target_domain = parsed.hostname
        self.discovered_subdomains: Set[str] = set()

    async def scan(self) -> List[dict]:
        """
        Enumerate subdomains

        Returns:
            List of discovered subdomains with their IPs
        """
        results = []

        if not self.target_domain:
            return results

        logger.info(f"Enumerating subdomains for {self.target_domain}...")

        # Try to get domain from hostname (remove subdomain if present)
        parts = self.target_domain.split('.')
        if len(parts) > 2:
            # Has subdomain, extract root domain
            root_domain = '.'.join(parts[-2:])
        else:
            root_domain = self.target_domain

        # Test common subdomains
        tasks = []
        for subdomain in self.COMMON_SUBDOMAINS:
            full_domain = f"{subdomain}.{root_domain}"
            tasks.append(self._check_subdomain(full_domain))

        subdomain_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in subdomain_results:
            if isinstance(result, dict) and result.get('exists'):
                results.append(result)
                self.discovered_subdomains.add(result['subdomain'])

        logger.info(f"Found {len(results)} subdomains")

        return results

    async def _check_subdomain(self, subdomain: str) -> dict:
        """Check if subdomain exists via DNS lookup"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2

            # Try A record
            try:
                answers = resolver.resolve(subdomain, 'A')
                ips = [str(rdata) for rdata in answers]

                logger.info(f"Found subdomain: {subdomain} -> {ips}")

                return {
                    'exists': True,
                    'subdomain': subdomain,
                    'ips': ips,
                    'record_type': 'A'
                }
            except dns.exception.DNSException:
                pass

            # Try CNAME record
            try:
                answers = resolver.resolve(subdomain, 'CNAME')
                cnames = [str(rdata) for rdata in answers]

                return {
                    'exists': True,
                    'subdomain': subdomain,
                    'cnames': cnames,
                    'record_type': 'CNAME'
                }
            except dns.exception.DNSException:
                pass

        except Exception as e:
            logger.debug(f"Error checking subdomain {subdomain}: {e}")

        return {'exists': False, 'subdomain': subdomain}
