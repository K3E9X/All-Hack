"""
Advanced Directory and File Fuzzing (Gobuster equivalent)
"""
import asyncio
import logging
from typing import List, Set
from pathlib import Path
from app.models import EndpointInfo
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class DirectoryFuzzer:
    """
    Advanced directory and file fuzzing with comprehensive wordlists
    """

    # Extensive wordlist for deep fuzzing
    DIRECTORIES = [
        # Admin panels
        'admin', 'administrator', 'admin_area', 'admin-panel', 'adminpanel',
        'admin1', 'admin2', 'admin3', 'admin4', 'admin5',
        'moderator', 'webadmin', 'adminarea', 'bb-admin', 'adminLogin',
        'admin_login', 'panel-admin', 'instadmin', 'memberadmin',
        'administratorlogin', 'adm', 'admin/account.php', 'admin/index.php',
        'admin/login.php', 'admin/admin.php', 'admin_area/admin.php',
        'admin_area/login.php', 'siteadmin/login.php', 'siteadmin/index.php',
        'admin/account.html', 'admin/index.html', 'admin/login.html',
        'panel', 'control', 'cp', 'manage', 'management', 'staff',

        # API endpoints
        'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'restapi',
        'graphql', 'swagger', 'api-docs', 'swagger-ui', 'api/swagger',
        'api/docs', 'api/documentation', 'api-explorer', 'apidocs',

        # Common directories
        'backup', 'backups', 'bak', 'old', 'tmp', 'temp', 'test', 'demo',
        'dev', 'development', 'staging', 'prod', 'production', '_old',
        'upload', 'uploads', 'files', 'file', 'userfiles', 'user_files',
        'media', 'images', 'img', 'css', 'js', 'javascript', 'assets',
        'static', 'content', 'data', 'includes', 'include', 'inc',
        'lib', 'library', 'libs', 'vendor', 'node_modules', 'bower_components',
        'scripts', 'script', 'src', 'source', 'public', 'private',
        'internal', 'external', 'app', 'application', 'apps',

        # Authentication
        'login', 'signin', 'logout', 'signout', 'auth', 'authenticate',
        'registration', 'register', 'signup', 'join', 'subscribe',
        'forgot-password', 'reset-password', 'password-reset',
        'recover', 'recovery', 'account', 'user', 'users', 'profile',
        'dashboard', 'portal', 'member', 'members', 'my-account',

        # Configuration
        'config', 'configuration', 'settings', 'setting', 'preferences',
        'options', 'setup', 'install', 'installation', 'installer',

        # Database
        'db', 'database', 'sql', 'mysql', 'mssql', 'oracle', 'postgres',
        'phpmyadmin', 'pma', 'dbadmin', 'adminer', 'sqladmin',

        # Documentation
        'docs', 'doc', 'documentation', 'manual', 'help', 'faq',
        'readme', 'changelog', 'license',

        # Monitoring/Debug
        'debug', 'trace', 'test', 'phpinfo', 'info', 'console',
        'logs', 'log', 'status', 'health', 'metrics', 'monitor',
        'actuator', 'actuator/health', 'actuator/metrics', 'actuator/env',

        # Version control
        '.git', '.svn', '.hg', '.bzr', 'CVS',
        '.git/config', '.git/HEAD', '.git/logs/HEAD',
        '.svn/entries', '.svn/wc.db',

        # Frameworks
        'wp-admin', 'wp-content', 'wp-includes', 'wordpress',
        'joomla', 'drupal', 'sites/default/files',
        'sites/default', 'administrator',

        # Cloud/Container
        'kubernetes', 'docker', '.docker', 'containers',
        '.kube', '.aws', '.azure',

        # Security
        'security', 'secure', 'ssl', 'cert', 'certificate',
        'keys', 'key', 'token', 'tokens', 'oauth', 'saml',
    ]

    FILES = [
        # Configuration files
        '.env', '.env.local', '.env.production', '.env.development',
        '.env.backup', '.env.old', 'env', 'env.example',
        'config.php', 'config.inc.php', 'config.json', 'config.yml',
        'config.yaml', 'configuration.php', 'settings.php', 'settings.json',
        'database.yml', 'database.json', 'db.php', 'db.json',
        'web.config', 'Web.config', 'app.config', 'application.properties',
        'application.yml', 'application.yaml', 'appsettings.json',
        '.htaccess', '.htpasswd', 'htaccess.txt', 'wp-config.php',

        # Backup files
        'backup.zip', 'backup.tar', 'backup.tar.gz', 'backup.sql',
        'backup.bak', 'db.sql', 'database.sql', 'dump.sql',
        'mysqldump.sql', 'db_backup.sql', 'backup.7z', 'backup.rar',
        'site.zip', 'www.zip', 'web.zip', 'website.zip',
        'backup.tar.bz2', 'backup.tgz',

        # Debug/Info files
        'phpinfo.php', 'info.php', 'test.php', 'debug.php',
        'console.php', 'shell.php', 'adminer.php', 'phpmyadmin.php',

        # Documentation
        'README.md', 'README.txt', 'README', 'readme.md', 'readme.txt',
        'CHANGELOG.md', 'CHANGES.txt', 'TODO.txt', 'LICENSE',
        'INSTALL.txt', 'INSTALL.md',

        # Logs
        'error.log', 'error_log', 'errors.log', 'access.log',
        'debug.log', 'app.log', 'application.log', 'laravel.log',
        'production.log', 'development.log',

        # API docs
        'swagger.json', 'swagger.yaml', 'openapi.json', 'openapi.yaml',
        'api-docs.json', 'postman_collection.json',

        # Git files
        '.git/HEAD', '.git/config', '.git/description', '.git/index',
        '.gitignore', '.gitmodules', '.gitattributes',

        # Docker
        'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
        '.dockerignore',

        # Node/JS
        'package.json', 'package-lock.json', 'yarn.lock',
        'node_modules', '.npmrc', '.yarnrc',

        # Python
        'requirements.txt', 'Pipfile', 'Pipfile.lock', 'setup.py',
        'poetry.lock', '__init__.py',

        # Ruby
        'Gemfile', 'Gemfile.lock',

        # Security
        'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
        'security.txt', '.well-known/security.txt',

        # Other
        'favicon.ico', 'humans.txt', 'ads.txt',
    ]

    EXTENSIONS = [
        '', '.php', '.asp', '.aspx', '.jsp', '.html', '.htm',
        '.do', '.action', '.json', '.xml', '.txt', '.bak',
        '.old', '.backup', '.zip', '.tar.gz', '.sql', '.log',
        '.conf', '.config', '.inc', '.yml', '.yaml'
    ]

    def __init__(self, client: PentestHTTPClient):
        self.client = client
        self.found_endpoints: Set[str] = set()

    async def fuzz(self, aggressive: bool = True) -> List[EndpointInfo]:
        """
        Perform directory and file fuzzing

        Args:
            aggressive: If True, use full wordlist. If False, use reduced list.

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        # Directories to test
        dirs_to_test = self.DIRECTORIES if aggressive else self.DIRECTORIES[:100]

        # Files to test
        files_to_test = self.FILES if aggressive else self.FILES[:50]

        logger.info(f"Fuzzing {len(dirs_to_test)} directories and {len(files_to_test)} files...")

        # Fuzz directories
        dir_tasks = [self._test_path(f"/{directory}/") for directory in dirs_to_test]
        dir_results = await asyncio.gather(*dir_tasks, return_exceptions=True)

        for result in dir_results:
            if isinstance(result, EndpointInfo):
                endpoints.append(result)

        # Fuzz files
        file_tasks = [self._test_path(f"/{file}") for file in files_to_test]
        file_results = await asyncio.gather(*file_tasks, return_exceptions=True)

        for result in file_results:
            if isinstance(result, EndpointInfo):
                endpoints.append(result)

        # Fuzz with extensions on directories (e.g., /admin.php)
        if aggressive:
            logger.info("Fuzzing directories with extensions...")
            ext_tasks = []
            for directory in dirs_to_test[:50]:  # Limit to avoid too many requests
                for ext in self.EXTENSIONS[:5]:  # Most common extensions
                    ext_tasks.append(self._test_path(f"/{directory}{ext}"))

            ext_results = await asyncio.gather(*ext_tasks, return_exceptions=True)

            for result in ext_results:
                if isinstance(result, EndpointInfo):
                    endpoints.append(result)

        logger.info(f"Fuzzing discovered {len(endpoints)} new endpoints")
        return endpoints

    async def _test_path(self, path: str) -> EndpointInfo | None:
        """Test if a path exists"""
        # Skip if already found
        if path in self.found_endpoints:
            return None

        try:
            response = await self.client.get(path)

            if not response:
                return None

            # Consider found if not 404
            if response.status_code not in [404, 410]:
                self.found_endpoints.add(path)

                # Determine if auth is required
                requires_auth = response.status_code in [401, 403]

                # Log interesting findings
                if response.status_code == 200:
                    logger.info(f"Found: {path} (200 OK)")
                elif response.status_code in [301, 302]:
                    logger.info(f"Found: {path} (Redirect to {response.headers.get('Location', 'unknown')})")
                elif requires_auth:
                    logger.info(f"Found: {path} (Auth required)")

                return EndpointInfo(
                    url=str(response.url),
                    method='GET',
                    status_code=response.status_code,
                    requires_auth=requires_auth,
                    headers=dict(response.headers)
                )

        except Exception as e:
            logger.debug(f"Error testing {path}: {e}")

        return None

    async def fuzz_parameters(self, endpoint: str) -> List[str]:
        """
        Fuzz for hidden parameters on an endpoint

        Returns:
            List of discovered parameters
        """
        common_params = [
            'id', 'user_id', 'userid', 'uid', 'user',
            'email', 'username', 'name', 'password', 'pass',
            'token', 'api_key', 'apikey', 'key', 'secret',
            'admin', 'debug', 'test', 'action', 'method',
            'callback', 'redirect', 'url', 'next', 'return',
            'page', 'p', 'q', 'query', 'search', 's',
            'file', 'filename', 'path', 'dir', 'folder',
            'data', 'value', 'val', 'param', 'parameter',
            'limit', 'offset', 'sort', 'order', 'filter',
        ]

        discovered_params = []

        # Get baseline response
        baseline = await self.client.get(endpoint)
        if not baseline:
            return discovered_params

        baseline_length = len(baseline.text)
        baseline_code = baseline.status_code

        # Test each parameter
        for param in common_params:
            response = await self.client.get(endpoint, params={param: 'test'})

            if response:
                # Parameter exists if response differs significantly
                if (response.status_code != baseline_code or
                    abs(len(response.text) - baseline_length) > 100):
                    discovered_params.append(param)
                    logger.info(f"Discovered parameter: {param} on {endpoint}")

        return discovered_params
