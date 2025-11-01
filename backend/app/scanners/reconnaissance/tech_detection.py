"""
Technology detection and fingerprinting
"""
import re
import logging
from typing import List, Dict, Any
from app.models import TechnologyInfo
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class TechnologyDetector:
    """Detect web technologies, frameworks, and servers"""

    # Technology signatures
    SIGNATURES = {
        # Frameworks
        'React': {
            'headers': {},
            'html': [r'react', r'_react', r'data-reactroot'],
            'scripts': [r'react\.', r'react-dom']
        },
        'Vue.js': {
            'headers': {},
            'html': [r'v-for=', r'v-if=', r'v-model=', r'data-v-'],
            'scripts': [r'vue\.js', r'vue\.min\.js']
        },
        'Angular': {
            'headers': {},
            'html': [r'ng-app', r'ng-controller', r'ng-model'],
            'scripts': [r'angular\.js', r'angular\.min\.js']
        },
        'Django': {
            'headers': {},
            'html': [r'csrfmiddlewaretoken'],
            'cookies': ['csrftoken', 'sessionid']
        },
        'Laravel': {
            'headers': {},
            'html': [r'laravel'],
            'cookies': ['laravel_session']
        },
        'Express': {
            'headers': {'X-Powered-By': r'Express'},
            'html': [],
            'cookies': ['connect.sid']
        },
        'Flask': {
            'headers': {},
            'html': [],
            'cookies': ['session']
        },
        'Spring': {
            'headers': {},
            'html': [],
            'cookies': ['JSESSIONID']
        },

        # Servers
        'Nginx': {
            'headers': {'Server': r'nginx'},
            'html': [],
        },
        'Apache': {
            'headers': {'Server': r'Apache'},
            'html': [],
        },
        'IIS': {
            'headers': {'Server': r'Microsoft-IIS'},
            'html': [],
        },
        'Cloudflare': {
            'headers': {'Server': r'cloudflare'},
            'html': [],
        },

        # CMS
        'WordPress': {
            'headers': {},
            'html': [r'wp-content', r'wp-includes'],
            'scripts': [r'wp-']
        },
        'Drupal': {
            'headers': {'X-Generator': r'Drupal'},
            'html': [r'Drupal'],
        },
        'Joomla': {
            'headers': {},
            'html': [r'/components/com_', r'Joomla'],
        },

        # Others
        'jQuery': {
            'headers': {},
            'html': [],
            'scripts': [r'jquery']
        },
        'Bootstrap': {
            'headers': {},
            'html': [r'bootstrap'],
            'scripts': [r'bootstrap']
        }
    }

    async def detect(self, client: PentestHTTPClient) -> List[TechnologyInfo]:
        """Detect technologies from the target"""
        technologies = []

        try:
            response = await client.get()
            if not response:
                return technologies

            # Check headers
            for tech_name, signatures in self.SIGNATURES.items():
                confidence = 0.0
                matches = []

                # Check HTTP headers
                if 'headers' in signatures:
                    for header, pattern in signatures['headers'].items():
                        header_value = response.headers.get(header, '')
                        if re.search(pattern, header_value, re.IGNORECASE):
                            confidence += 0.4
                            matches.append(f"Header: {header}")

                # Check HTML content
                if 'html' in signatures and response.text:
                    for pattern in signatures['html']:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            confidence += 0.3
                            matches.append(f"HTML pattern")
                            break

                # Check scripts
                if 'scripts' in signatures and response.text:
                    for pattern in signatures['scripts']:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            confidence += 0.3
                            matches.append(f"Script pattern")
                            break

                # Check cookies
                if 'cookies' in signatures:
                    for cookie_name in signatures['cookies']:
                        if cookie_name in response.cookies:
                            confidence += 0.3
                            matches.append(f"Cookie: {cookie_name}")

                if confidence > 0:
                    # Try to extract version
                    version = self._extract_version(tech_name, response)

                    technologies.append(TechnologyInfo(
                        name=tech_name,
                        version=version,
                        category=self._categorize_tech(tech_name),
                        confidence=min(confidence, 1.0)
                    ))

        except Exception as e:
            logger.error(f"Technology detection error: {e}")

        return technologies

    def _extract_version(self, tech_name: str, response) -> str | None:
        """Try to extract version from response"""
        version_patterns = {
            'React': r'react@([\d.]+)',
            'Vue.js': r'vue@([\d.]+)',
            'jQuery': r'jquery[/-]([\d.]+)',
            'Bootstrap': r'bootstrap[/-]([\d.]+)',
            'Nginx': r'nginx/([\d.]+)',
            'Apache': r'Apache/([\d.]+)',
        }

        if tech_name in version_patterns:
            # Check headers first
            for header_value in response.headers.values():
                match = re.search(version_patterns[tech_name], str(header_value), re.IGNORECASE)
                if match:
                    return match.group(1)

            # Check HTML content
            if response.text:
                match = re.search(version_patterns[tech_name], response.text, re.IGNORECASE)
                if match:
                    return match.group(1)

        return None

    def _categorize_tech(self, tech_name: str) -> str:
        """Categorize technology"""
        categories = {
            'React': 'framework',
            'Vue.js': 'framework',
            'Angular': 'framework',
            'Django': 'framework',
            'Laravel': 'framework',
            'Express': 'framework',
            'Flask': 'framework',
            'Spring': 'framework',
            'Nginx': 'server',
            'Apache': 'server',
            'IIS': 'server',
            'Cloudflare': 'cdn',
            'WordPress': 'cms',
            'Drupal': 'cms',
            'Joomla': 'cms',
            'jQuery': 'library',
            'Bootstrap': 'library'
        }
        return categories.get(tech_name, 'unknown')
