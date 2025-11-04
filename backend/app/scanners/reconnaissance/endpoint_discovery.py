"""
Endpoint discovery and enumeration
"""
import asyncio
import logging
from typing import List, Set
from urllib.parse import urljoin, urlparse
from app.models import EndpointInfo
from app.utils import PentestHTTPClient, extract_links, parse_robots_txt

logger = logging.getLogger(__name__)

class EndpointDiscovery:
    """Discover endpoints through crawling, fuzzing, and analysis"""

    # Common endpoints to check
    COMMON_ENDPOINTS = [
        # API endpoints
        '/api', '/api/v1', '/api/v2', '/graphql', '/swagger', '/api-docs',
        '/v1', '/v2', '/rest', '/api/users', '/api/auth', '/api/login',

        # Admin panels
        '/admin', '/administrator', '/admin.php', '/wp-admin', '/phpmyadmin',
        '/cpanel', '/admin/login', '/admin/dashboard',

        # Authentication
        '/login', '/signin', '/auth', '/authenticate', '/oauth', '/sso',
        '/logout', '/register', '/signup', '/forgot-password', '/reset-password',

        # Common files
        '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
        '/humans.txt', '/crossdomain.xml',

        # Configuration files (often exposed)
        '/.env', '/config.php', '/config.json', '/web.config', '/application.properties',
        '/.git/config', '/.git/HEAD', '/.svn/entries', '/.DS_Store',

        # Backups (potential exposure)
        '/backup', '/backups', '/backup.zip', '/backup.sql', '/db.sql',
        '/dump.sql', '/backup.tar.gz', '/old', '/temp',

        # Documentation
        '/docs', '/documentation', '/api/docs', '/swagger-ui', '/redoc',

        # Debug/Test
        '/debug', '/test', '/phpinfo.php', '/info.php', '/server-status',
        '/server-info', '/trace', '/actuator', '/health', '/metrics',

        # File uploads
        '/upload', '/uploads', '/files', '/media', '/images', '/assets',

        # User data
        '/users', '/user', '/profile', '/account', '/settings',
        '/dashboard', '/panel',
    ]

    # Common file extensions
    COMMON_EXTENSIONS = [
        '.php', '.asp', '.aspx', '.jsp', '.do', '.action',
        '.json', '.xml', '.txt', '.bak', '.old', '.backup',
        '.sql', '.db', '.log', '.zip', '.tar.gz'
    ]

    def __init__(self, client: PentestHTTPClient, max_depth: int = 3):
        self.client = client
        self.max_depth = max_depth
        self.discovered_endpoints: Set[str] = set()
        self.visited_urls: Set[str] = set()

    async def discover(self, enable_fuzzing: bool = True) -> List[EndpointInfo]:
        """Main discovery process"""
        endpoints = []

        # 1. Check robots.txt
        await self._check_robots_txt()

        # 2. Check common endpoints
        common_results = await self._check_common_endpoints()
        endpoints.extend(common_results)

        # 3. Crawl the application
        crawled_results = await self._crawl()
        endpoints.extend(crawled_results)

        # 4. Fuzzing (if enabled)
        if enable_fuzzing:
            fuzzed_results = await self._fuzz_endpoints()
            endpoints.extend(fuzzed_results)

        return endpoints

    async def _check_robots_txt(self):
        """Check robots.txt for hidden endpoints"""
        try:
            response = await self.client.get('/robots.txt')
            if response and response.status_code == 200:
                parsed = parse_robots_txt(response.text)

                # Add disallowed paths to discovery list
                for path in parsed['disallowed']:
                    self.discovered_endpoints.add(path)

                # Check sitemaps
                for sitemap_url in parsed['sitemaps']:
                    # Could parse sitemap XML here
                    self.discovered_endpoints.add(sitemap_url)

                logger.info(f"Found {len(parsed['disallowed'])} paths in robots.txt")
        except Exception as e:
            logger.error(f"Error checking robots.txt: {e}")

    async def _check_common_endpoints(self) -> List[EndpointInfo]:
        """Check common endpoints"""
        endpoints = []
        tasks = []

        for path in self.COMMON_ENDPOINTS:
            tasks.append(self._check_endpoint(path))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, EndpointInfo):
                endpoints.append(result)

        logger.info(f"Found {len(endpoints)} common endpoints")
        return endpoints

    async def _check_endpoint(self, path: str) -> EndpointInfo | None:
        """Check if an endpoint exists"""
        try:
            response = await self.client.get(path)
            if not response:
                return None

            # Consider it found if status is not 404
            if response.status_code != 404:
                self.discovered_endpoints.add(path)

                return EndpointInfo(
                    url=str(response.url),
                    method='GET',
                    status_code=response.status_code,
                    requires_auth=response.status_code in [401, 403],
                    headers=dict(response.headers)
                )
        except Exception as e:
            logger.debug(f"Error checking {path}: {e}")

        return None

    async def _crawl(self, start_url: str = "/", depth: int = 0) -> List[EndpointInfo]:
        """Crawl the application to discover endpoints"""
        if depth > self.max_depth or start_url in self.visited_urls:
            return []

        self.visited_urls.add(start_url)
        endpoints = []

        try:
            response = await self.client.get(start_url)
            if not response or response.status_code == 404:
                return []

            # Add current endpoint
            endpoints.append(EndpointInfo(
                url=str(response.url),
                method='GET',
                status_code=response.status_code,
                requires_auth=response.status_code in [401, 403],
                headers=dict(response.headers)
            ))

            # Extract and follow links
            if response.status_code == 200 and response.text:
                links = extract_links(response.text, self.client.base_url)

                # Crawl discovered links (limited to avoid infinite loops)
                for link in list(links)[:10]:  # Limit to 10 links per page
                    path = urlparse(link).path
                    if path not in self.visited_urls:
                        sub_endpoints = await self._crawl(path, depth + 1)
                        endpoints.extend(sub_endpoints)

        except Exception as e:
            logger.error(f"Error crawling {start_url}: {e}")

        return endpoints

    async def _fuzz_endpoints(self) -> List[EndpointInfo]:
        """Fuzz for additional endpoints"""
        endpoints = []

        # Simple fuzzing - try variations of discovered endpoints
        fuzz_targets = []

        for endpoint in list(self.discovered_endpoints)[:20]:  # Limit fuzzing
            # Try with different extensions
            for ext in self.COMMON_EXTENSIONS:
                if not endpoint.endswith(ext):
                    fuzz_targets.append(f"{endpoint}{ext}")

            # Try backup variations
            fuzz_targets.append(f"{endpoint}.bak")
            fuzz_targets.append(f"{endpoint}.old")
            fuzz_targets.append(f"{endpoint}~")

        # Check fuzzed targets
        tasks = [self._check_endpoint(target) for target in fuzz_targets[:100]]  # Limit
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, EndpointInfo):
                endpoints.append(result)

        logger.info(f"Fuzzing found {len(endpoints)} additional endpoints")
        return endpoints

    async def discover_authenticated_endpoints(self) -> List[EndpointInfo]:
        """
        GREY BOX EXCLUSIVE: Discover authenticated endpoints

        When we have authentication (grey_box mode), we can access user-specific
        endpoints that are not visible in black_box mode. This dramatically
        increases the attack surface.
        """
        logger.info("🔓 GREY BOX: Discovering authenticated endpoints")

        # Authenticated endpoints to check
        AUTHENTICATED_ENDPOINTS = [
            # User profile & settings
            '/profile', '/profile/edit', '/profile/settings', '/my-profile',
            '/account', '/account/settings', '/account/profile', '/account/security',
            '/settings', '/settings/profile', '/settings/privacy', '/settings/security',
            '/user/profile', '/user/settings', '/user/account',
            '/me', '/my-account', '/my-settings',

            # Dashboard & Management
            '/dashboard', '/dashboard/home', '/dashboard/overview', '/dashboard/stats',
            '/panel', '/panel/home', '/control-panel',
            '/home', '/user/home', '/user/dashboard',

            # User-specific data
            '/orders', '/my-orders', '/order-history', '/purchases',
            '/documents', '/my-documents', '/files', '/my-files',
            '/invoices', '/my-invoices', '/billing',
            '/messages', '/my-messages', '/inbox', '/notifications',
            '/favorites', '/bookmarks', '/saved',
            '/history', '/activity', '/logs',

            # Admin/Management (if user has admin role)
            '/admin/users', '/admin/settings', '/admin/config',
            '/manage/users', '/manage/settings',
            '/moderator', '/staff', '/management',

            # API endpoints for authenticated users
            '/api/me', '/api/user', '/api/user/profile',
            '/api/account', '/api/account/settings',
            '/api/dashboard', '/api/dashboard/stats',
            '/api/v1/me', '/api/v1/user', '/api/v1/profile',
            '/api/v2/me', '/api/v2/user', '/api/v2/profile',

            # Upload/File management
            '/upload', '/file/upload', '/media/upload',
            '/upload/profile', '/upload/document',

            # Security & Auth management
            '/auth/sessions', '/security/sessions', '/active-sessions',
            '/auth/devices', '/security/devices', '/trusted-devices',
            '/auth/2fa', '/security/2fa', '/two-factor',
            '/api-keys', '/tokens', '/oauth/apps',

            # Payments & Subscription (if applicable)
            '/payment-methods', '/cards', '/wallet',
            '/subscription', '/plan', '/billing/subscription',

            # Social features
            '/friends', '/followers', '/following',
            '/posts', '/my-posts', '/content',
        ]

        endpoints = []

        logger.info(f"Checking {len(AUTHENTICATED_ENDPOINTS)} potential authenticated endpoints...")

        # Check all authenticated endpoints
        tasks = [self._check_endpoint(path) for path in AUTHENTICATED_ENDPOINTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, EndpointInfo):
                # In grey box, a 200 means we found an authenticated endpoint
                if result.status_code == 200:
                    endpoints.append(result)
                    logger.info(f"✓ Found authenticated endpoint: {result.url}")

        logger.info(f"🎯 Discovered {len(endpoints)} authenticated endpoints (GREY BOX)")

        return endpoints
