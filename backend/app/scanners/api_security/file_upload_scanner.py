"""
File Upload Vulnerability Scanner
Tests for malicious file upload, extension bypass, MIME type manipulation, and path traversal
"""

import io
import hashlib
import asyncio
from typing import List, Optional, Dict, Any, Tuple
import logging

from app.models.scan import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.http.client import PentestHTTPClient

logger = logging.getLogger(__name__)


class FileUploadScanner:
    """Scanner for file upload vulnerabilities"""

    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = [
        # Web shells
        ".php", ".php3", ".php4", ".php5", ".phtml",
        ".asp", ".aspx", ".jsp", ".jspx",
        ".py", ".rb", ".pl", ".cgi",

        # Executable
        ".exe", ".bat", ".sh", ".com",

        # Double extension tricks
        ".php.jpg", ".php.png", ".php.gif",
        ".asp.jpg", ".jsp.png",

        # Null byte (will be handled separately)
        ".php%00.jpg", ".asp%00.png",

        # Case manipulation
        ".pHp", ".PhP", ".PHP",
        ".AsP", ".jSp"
    ]

    # MIME types for testing
    TEST_MIME_TYPES = [
        "image/jpeg",
        "image/png",
        "image/gif",
        "text/plain",
        "application/octet-stream",
        "application/x-php",
        "application/x-httpd-php"
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        "../shell.php",
        "../../shell.php",
        "../../../shell.php",
        "..\\shell.php",
        "....//shell.php",
        "....\\\\shell.php",
        "%2e%2e%2fshell.php",
        "%2e%2e%5cshell.php",
        "..%2fshell.php"
    ]

    # Simple webshell content for testing
    WEBSHELL_CONTENT = b'<?php echo "VULNERABLE"; ?>'
    SAFE_TEST_CONTENT = b'GIF89a'  # GIF header (safe for testing)

    def __init__(self, client: PentestHTTPClient, scan_depth: str = "balanced", progress_callback=None):
        self.client = client
        self.scan_depth = scan_depth
        self.progress_callback = progress_callback

        # Adjust depth
        if scan_depth == "quick":
            self.extension_limit = 5
            self.mime_limit = 3
            self.test_path_traversal = False
            self.test_overwrite = False
        elif scan_depth == "balanced":
            self.extension_limit = 10
            self.mime_limit = 5
            self.test_path_traversal = True
            self.test_overwrite = False
        else:  # deep
            self.extension_limit = len(self.DANGEROUS_EXTENSIONS)
            self.mime_limit = len(self.TEST_MIME_TYPES)
            self.test_path_traversal = True
            self.test_overwrite = True

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """Scan for file upload vulnerabilities"""
        vulnerabilities = []

        if self.progress_callback:
            await self.progress_callback(f"📤 Starting File Upload Security Testing on {len(endpoints)} endpoints...")

        # Discover upload endpoints
        upload_endpoints = await self._discover_upload_endpoints(endpoints)

        if not upload_endpoints:
            if self.progress_callback:
                await self.progress_callback("ℹ️  No file upload endpoints discovered")
            return vulnerabilities

        if self.progress_callback:
            await self.progress_callback(f"🎯 Found {len(upload_endpoints)} upload endpoints, starting security tests...")

        # Test each upload endpoint
        for idx, (endpoint, field_name) in enumerate(upload_endpoints, 1):
            if self.progress_callback:
                await self.progress_callback(f"🔍 Testing upload endpoint {idx}/{len(upload_endpoints)}: {endpoint[:60]}...")

            try:
                # Test extension bypass
                vulns = await self._test_extension_bypass(endpoint, field_name)
                vulnerabilities.extend(vulns)

                # Test MIME type bypass
                vulns = await self._test_mime_type_bypass(endpoint, field_name)
                vulnerabilities.extend(vulns)

                # Test path traversal
                if self.test_path_traversal:
                    vulns = await self._test_path_traversal(endpoint, field_name)
                    vulnerabilities.extend(vulns)

                # Test file size limits
                vulns = await self._test_file_size_limits(endpoint, field_name)
                vulnerabilities.extend(vulns)

                if vulnerabilities and self.progress_callback:
                    await self.progress_callback(f"✅ Found file upload vulnerabilities on {endpoint[:60]}")

            except Exception as e:
                logger.error(f"Error testing file upload on {endpoint}: {e}")
                if self.progress_callback:
                    await self.progress_callback(f"⚠️  Error testing upload on {endpoint[:60]}: {str(e)[:50]}")

        return vulnerabilities

    async def _discover_upload_endpoints(self, endpoints: List[str]) -> List[Tuple[str, str]]:
        """Discover file upload endpoints"""
        upload_endpoints = []

        # Keywords that suggest upload functionality
        upload_keywords = ['upload', 'file', 'avatar', 'profile', 'image', 'photo', 'document', 'attachment', 'media']

        for endpoint in endpoints:
            # Check if URL suggests file upload
            if any(keyword in endpoint.lower() for keyword in upload_keywords):
                # Try to identify the upload field name
                # Common field names: file, upload, image, avatar, document
                upload_endpoints.append((endpoint, "file"))
                logger.info(f"Potential upload endpoint: {endpoint}")

        return upload_endpoints

    async def _test_extension_bypass(self, endpoint: str, field_name: str) -> List[Vulnerability]:
        """Test for extension-based upload bypass"""
        vulnerabilities = []

        try:
            # Test dangerous extensions
            for ext in self.DANGEROUS_EXTENSIONS[:self.extension_limit]:
                filename = f"test{ext}"

                # Try uploading with this extension
                success, response_info = await self._attempt_upload(
                    endpoint=endpoint,
                    field_name=field_name,
                    filename=filename,
                    content=self.SAFE_TEST_CONTENT,
                    mime_type="image/gif"
                )

                if success:
                    # Check if file was actually saved with the dangerous extension
                    if await self._verify_upload_accepted(response_info, filename):
                        vulnerabilities.append(Vulnerability(
                            id=f"file_upload_ext_{hashlib.md5((endpoint + ext).encode()).hexdigest()[:8]}",
                            title=f"Unrestricted File Upload - Dangerous Extension Allowed ({ext})",
                            description=f"The application accepts file uploads with dangerous extension '{ext}'. This could allow attackers to upload web shells or malicious executables.",
                            severity=SeverityLevel.CRITICAL if ext in ['.php', '.asp', '.aspx', '.jsp'] else SeverityLevel.HIGH,
                            category=VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                            affected_url=endpoint,
                            affected_parameter=field_name,
                            proof_of_concept=f"Successfully uploaded file 'test{ext}' to {endpoint}. Server accepted the dangerous extension without proper validation.",
                            payload=f"filename: test{ext}",
                            remediation="""
                            1. Implement a strict whitelist of allowed file extensions (e.g., only .jpg, .png, .pdf)
                            2. Validate file type based on content (magic bytes), not just extension
                            3. Rename uploaded files to remove original extension
                            4. Store uploaded files outside web root
                            5. Set proper file permissions (non-executable)
                            6. Use Content-Disposition: attachment for downloads
                            7. Implement virus scanning for uploaded files
                            """,
                            cwe_id="CWE-434",
                            owasp_category="A04:2021 – Insecure Design",
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                                "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files"
                            ]
                        ))
                        logger.warning(f"Dangerous file extension {ext} accepted on {endpoint}")
                        break  # Found vulnerability, no need to test all extensions

        except Exception as e:
            logger.debug(f"Extension bypass test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_mime_type_bypass(self, endpoint: str, field_name: str) -> List[Vulnerability]:
        """Test if MIME type validation can be bypassed"""
        vulnerabilities = []

        try:
            # Try uploading PHP code with image MIME type
            filename = "test.php"

            for mime_type in ["image/jpeg", "image/png", "image/gif"][:self.mime_limit]:
                success, response_info = await self._attempt_upload(
                    endpoint=endpoint,
                    field_name=field_name,
                    filename=filename,
                    content=self.WEBSHELL_CONTENT,
                    mime_type=mime_type
                )

                if success and await self._verify_upload_accepted(response_info, filename):
                    vulnerabilities.append(Vulnerability(
                        id=f"file_upload_mime_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="File Upload MIME Type Validation Bypass",
                        description=f"The application only validates MIME type but not actual file content. Uploaded PHP file with MIME type '{mime_type}' and it was accepted.",
                        severity=SeverityLevel.HIGH,
                        category=VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                        affected_url=endpoint,
                        affected_parameter=field_name,
                        proof_of_concept=f"Uploaded 'test.php' with spoofed MIME type '{mime_type}'. Server accepted the file based solely on MIME type without validating content.",
                        payload=f"filename: test.php, MIME: {mime_type}",
                        remediation="Validate file content using magic bytes/file signatures, not just MIME type or extension. MIME types can be easily spoofed.",
                        cwe_id="CWE-434",
                        owasp_category="A04:2021 – Insecure Design",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
                        ]
                    ))
                    logger.warning(f"MIME type validation bypass on {endpoint}")
                    break

        except Exception as e:
            logger.debug(f"MIME type bypass test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_path_traversal(self, endpoint: str, field_name: str) -> List[Vulnerability]:
        """Test for path traversal in filename"""
        vulnerabilities = []

        try:
            for traversal_filename in self.PATH_TRAVERSAL_PATTERNS[:5]:
                success, response_info = await self._attempt_upload(
                    endpoint=endpoint,
                    field_name=field_name,
                    filename=traversal_filename,
                    content=self.SAFE_TEST_CONTENT,
                    mime_type="image/gif"
                )

                if success:
                    # Check response for indicators that path traversal worked
                    if await self._check_path_traversal_success(response_info, traversal_filename):
                        vulnerabilities.append(Vulnerability(
                            id=f"file_upload_path_traversal_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                            title="File Upload Path Traversal Vulnerability",
                            description="The application does not properly sanitize uploaded filenames, allowing path traversal. Attackers could write files to arbitrary locations on the server.",
                            severity=SeverityLevel.CRITICAL,
                            category=VulnerabilityCategory.PATH_TRAVERSAL,
                            affected_url=endpoint,
                            affected_parameter=field_name,
                            proof_of_concept=f"Successfully uploaded file with traversal path: {traversal_filename}. Server did not sanitize the filename.",
                            payload=f"filename: {traversal_filename}",
                            remediation="Sanitize filenames: remove path separators, use basename() function, generate random filenames, validate against whitelist patterns.",
                            cwe_id="CWE-22",
                            owasp_category="A01:2021 – Broken Access Control",
                            references=[
                                "https://owasp.org/www-community/attacks/Path_Traversal",
                                "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
                            ]
                        ))
                        logger.warning(f"Path traversal in file upload on {endpoint}")
                        break

        except Exception as e:
            logger.debug(f"Path traversal test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_file_size_limits(self, endpoint: str, field_name: str) -> List[Vulnerability]:
        """Test for missing or inadequate file size limits"""
        vulnerabilities = []

        try:
            # Try uploading a large file (10MB)
            large_content = b'A' * (10 * 1024 * 1024)  # 10 MB

            success, response_info = await self._attempt_upload(
                endpoint=endpoint,
                field_name=field_name,
                filename="large_file.jpg",
                content=large_content,
                mime_type="image/jpeg"
            )

            if success:
                vulnerabilities.append(Vulnerability(
                    id=f"file_upload_size_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                    title="File Upload - Insufficient Size Limits",
                    description="The application accepts very large file uploads (10+ MB) without proper restrictions. This could lead to DoS attacks through storage exhaustion.",
                    severity=SeverityLevel.MEDIUM,
                    category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                    affected_url=endpoint,
                    affected_parameter=field_name,
                    proof_of_concept="Successfully uploaded a 10MB file without restrictions. Attackers could exhaust server storage.",
                    payload="file_size: 10MB",
                    remediation="Implement reasonable file size limits based on application needs (e.g., 5MB for images, 10MB for documents). Enforce limits on both client and server side.",
                    cwe_id="CWE-400",
                    owasp_category="A05:2021 – Security Misconfiguration"
                ))
                logger.warning(f"No file size limit on {endpoint}")

        except Exception as e:
            logger.debug(f"File size limit test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _attempt_upload(self, endpoint: str, field_name: str, filename: str,
                            content: bytes, mime_type: str) -> Tuple[bool, Dict[str, Any]]:
        """Attempt to upload a file"""
        try:
            # Create file-like object
            file_obj = io.BytesIO(content)

            # Prepare multipart form data
            files = {field_name: (filename, file_obj, mime_type)}

            # Attempt upload
            response = await self.client.post(endpoint, files=files)

            if hasattr(response, 'status_code'):
                status_code = response.status_code
                # 200, 201, 202 indicate successful upload
                success = status_code in [200, 201, 202]

                response_info = {
                    'status_code': status_code,
                    'body': response.text if hasattr(response, 'text') else '',
                    'headers': dict(response.headers) if hasattr(response, 'headers') else {}
                }

                return success, response_info

        except Exception as e:
            logger.debug(f"Upload attempt failed: {e}")

        return False, {}

    async def _verify_upload_accepted(self, response_info: Dict[str, Any], filename: str) -> bool:
        """Verify if upload was actually accepted by checking response"""
        try:
            status_code = response_info.get('status_code', 0)

            # Check status code
            if status_code not in [200, 201, 202]:
                return False

            # Check response body for success indicators
            body = response_info.get('body', '').lower()
            success_keywords = ['success', 'uploaded', 'saved', 'completed', filename.lower()]
            error_keywords = ['error', 'failed', 'invalid', 'not allowed', 'rejected']

            has_success = any(keyword in body for keyword in success_keywords)
            has_error = any(keyword in body for keyword in error_keywords)

            return has_success and not has_error

        except Exception:
            return False

    async def _check_path_traversal_success(self, response_info: Dict[str, Any], filename: str) -> bool:
        """Check if path traversal was successful"""
        try:
            body = response_info.get('body', '')

            # Look for the traversal path in response
            # If server echoes back the original filename with traversal, it might be vulnerable
            if '..' in body or filename in body:
                return True

            # If we got a success status, assume it worked
            return response_info.get('status_code') in [200, 201, 202]

        except Exception:
            return False
