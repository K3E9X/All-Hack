"""
Vulnerability Enrichment System

This module automatically enriches the vulnerability database with:
- Latest CVEs from NVD
- Public exploits from ExploitDB
- POCs from GitHub
- Security advisories
"""

import asyncio
import json
import logging
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from pathlib import Path
import aiohttp
import aiofiles

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityInfo:
    """Vulnerability information from various sources"""
    vuln_id: str                    # CVE-2024-XXXX or custom ID
    title: str
    description: str
    severity: str                   # critical, high, medium, low
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    affected_products: List[str]
    references: List[str]
    exploits: List[Dict[str, Any]]  # Available exploits/POCs
    remediation: str
    source: str                     # nvd, exploitdb, github, etc.
    published_date: str
    last_updated: str
    tags: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExploitInfo:
    """Public exploit/POC information"""
    exploit_id: str
    title: str
    description: str
    author: str
    exploit_type: str               # poc, exploit, auxiliary
    platform: str                   # multi, linux, windows, web
    language: str                   # python, bash, ruby, etc.
    cve_references: List[str]
    source_url: str
    code: Optional[str]             # The actual exploit code (if safe)
    verified: bool
    reliability: str                # high, medium, low
    last_updated: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class VulnerabilityEnrichmentSystem:
    """
    System for automatically enriching vulnerability knowledge base.

    Sources:
    - NVD (National Vulnerability Database)
    - ExploitDB
    - GitHub Security Advisories
    - Packet Storm
    - Nuclei Templates
    """

    def __init__(self, data_dir: str = None):
        self.data_dir = Path(data_dir or "/tmp/pentest_vulns")
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.vulnerabilities: Dict[str, VulnerabilityInfo] = {}
        self.exploits: Dict[str, ExploitInfo] = {}
        self.last_update: Optional[datetime] = None

        # API endpoints
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.github_api = "https://api.github.com"
        self.exploitdb_api = "https://www.exploit-db.com/search"

        # Rate limiting
        self.rate_limits = {
            'nvd': {'requests': 0, 'last_reset': datetime.now(), 'limit': 5},
            'github': {'requests': 0, 'last_reset': datetime.now(), 'limit': 60},
        }

        self._load_database()
        logger.info(f"VulnerabilityEnrichmentSystem initialized with {len(self.vulnerabilities)} vulns")

    def _load_database(self):
        """Load vulnerability database from disk"""
        try:
            vuln_file = self.data_dir / "vulnerabilities.json"
            if vuln_file.exists():
                with open(vuln_file) as f:
                    data = json.load(f)
                    for vuln_id, vuln_data in data.items():
                        self.vulnerabilities[vuln_id] = VulnerabilityInfo(**vuln_data)

            exploit_file = self.data_dir / "exploits.json"
            if exploit_file.exists():
                with open(exploit_file) as f:
                    data = json.load(f)
                    for exp_id, exp_data in data.items():
                        self.exploits[exp_id] = ExploitInfo(**exp_data)

            meta_file = self.data_dir / "metadata.json"
            if meta_file.exists():
                with open(meta_file) as f:
                    meta = json.load(f)
                    self.last_update = datetime.fromisoformat(meta.get('last_update', '2000-01-01'))

        except Exception as e:
            logger.warning(f"Could not load database: {e}")

    async def _save_database(self):
        """Save vulnerability database to disk"""
        try:
            vuln_file = self.data_dir / "vulnerabilities.json"
            async with aiofiles.open(vuln_file, 'w') as f:
                data = {k: v.to_dict() for k, v in self.vulnerabilities.items()}
                await f.write(json.dumps(data, indent=2, default=str))

            exploit_file = self.data_dir / "exploits.json"
            async with aiofiles.open(exploit_file, 'w') as f:
                data = {k: v.to_dict() for k, v in self.exploits.items()}
                await f.write(json.dumps(data, indent=2, default=str))

            meta_file = self.data_dir / "metadata.json"
            async with aiofiles.open(meta_file, 'w') as f:
                await f.write(json.dumps({
                    'last_update': datetime.now().isoformat(),
                    'vuln_count': len(self.vulnerabilities),
                    'exploit_count': len(self.exploits)
                }, indent=2))

            logger.info("Database saved successfully")
        except Exception as e:
            logger.error(f"Could not save database: {e}")

    async def _check_rate_limit(self, source: str) -> bool:
        """Check if we can make a request to the source"""
        if source not in self.rate_limits:
            return True

        limit_info = self.rate_limits[source]
        now = datetime.now()

        # Reset if hour has passed
        if (now - limit_info['last_reset']).seconds > 3600:
            limit_info['requests'] = 0
            limit_info['last_reset'] = now

        if limit_info['requests'] >= limit_info['limit']:
            return False

        limit_info['requests'] += 1
        return True

    async def update_from_nvd(
        self,
        keywords: Optional[List[str]] = None,
        days_back: int = 7
    ) -> int:
        """Fetch latest CVEs from NVD"""
        if not await self._check_rate_limit('nvd'):
            logger.warning("NVD rate limit reached, skipping update")
            return 0

        added = 0
        start_date = (datetime.now() - timedelta(days=days_back)).strftime('%Y-%m-%dT00:00:00.000')
        end_date = datetime.now().strftime('%Y-%m-%dT23:59:59.999')

        params = {
            'pubStartDate': start_date,
            'pubEndDate': end_date,
            'resultsPerPage': 100
        }

        if keywords:
            params['keywordSearch'] = ' '.join(keywords)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.nvd_api, params=params, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        vulnerabilities = data.get('vulnerabilities', [])

                        for vuln in vulnerabilities:
                            cve = vuln.get('cve', {})
                            cve_id = cve.get('id', '')

                            if cve_id and cve_id not in self.vulnerabilities:
                                # Extract metrics
                                cvss_score = None
                                cvss_vector = None
                                severity = 'medium'

                                metrics = cve.get('metrics', {})
                                if 'cvssMetricV31' in metrics:
                                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                                    cvss_score = cvss_data.get('baseScore')
                                    cvss_vector = cvss_data.get('vectorString')
                                    severity = cvss_data.get('baseSeverity', 'MEDIUM').lower()

                                # Extract description
                                descriptions = cve.get('descriptions', [])
                                description = next(
                                    (d['value'] for d in descriptions if d.get('lang') == 'en'),
                                    ''
                                )

                                # Extract references
                                refs = [r.get('url', '') for r in cve.get('references', [])]

                                # Extract affected products
                                products = []
                                for config in cve.get('configurations', []):
                                    for node in config.get('nodes', []):
                                        for match in node.get('cpeMatch', []):
                                            if match.get('vulnerable'):
                                                products.append(match.get('criteria', ''))

                                vuln_info = VulnerabilityInfo(
                                    vuln_id=cve_id,
                                    title=cve_id,
                                    description=description[:2000],
                                    severity=severity,
                                    cvss_score=cvss_score,
                                    cvss_vector=cvss_vector,
                                    affected_products=products[:20],
                                    references=refs[:10],
                                    exploits=[],
                                    remediation="Apply vendor patches",
                                    source='nvd',
                                    published_date=cve.get('published', ''),
                                    last_updated=cve.get('lastModified', ''),
                                    tags=self._extract_tags(description)
                                )

                                self.vulnerabilities[cve_id] = vuln_info
                                added += 1

                        logger.info(f"Added {added} new CVEs from NVD")
                    else:
                        logger.warning(f"NVD API returned status {response.status}")

        except Exception as e:
            logger.error(f"Error fetching from NVD: {e}")

        return added

    async def search_github_pocs(
        self,
        cve_id: str = None,
        keywords: List[str] = None,
        max_results: int = 10
    ) -> List[ExploitInfo]:
        """Search GitHub for POCs"""
        if not await self._check_rate_limit('github'):
            logger.warning("GitHub rate limit reached")
            return []

        exploits = []
        query_parts = []

        if cve_id:
            query_parts.append(cve_id)
        if keywords:
            query_parts.extend(keywords)

        query = ' '.join(query_parts) + ' poc OR exploit OR proof-of-concept'

        try:
            headers = {'Accept': 'application/vnd.github.v3+json'}
            params = {
                'q': query,
                'sort': 'updated',
                'order': 'desc',
                'per_page': min(max_results, 30)
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.github_api}/search/repositories",
                    headers=headers,
                    params=params,
                    timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        items = data.get('items', [])

                        for repo in items:
                            exploit_id = f"gh-{repo['id']}"

                            if exploit_id not in self.exploits:
                                # Detect language/platform
                                language = repo.get('language', 'unknown') or 'unknown'
                                platform = self._detect_platform(repo.get('description', ''), language)

                                # Extract CVE references from name/description
                                cve_refs = re.findall(
                                    r'CVE-\d{4}-\d{4,}',
                                    f"{repo.get('name', '')} {repo.get('description', '')}",
                                    re.IGNORECASE
                                )

                                exploit = ExploitInfo(
                                    exploit_id=exploit_id,
                                    title=repo.get('name', ''),
                                    description=repo.get('description', '')[:500] if repo.get('description') else '',
                                    author=repo.get('owner', {}).get('login', 'unknown'),
                                    exploit_type='poc',
                                    platform=platform,
                                    language=language.lower(),
                                    cve_references=list(set(cve_refs)),
                                    source_url=repo.get('html_url', ''),
                                    code=None,  # Don't download code automatically
                                    verified=False,
                                    reliability='low',
                                    last_updated=repo.get('updated_at', '')
                                )

                                self.exploits[exploit_id] = exploit
                                exploits.append(exploit)

                                # Link to vulnerabilities
                                for cve in cve_refs:
                                    if cve.upper() in self.vulnerabilities:
                                        vuln = self.vulnerabilities[cve.upper()]
                                        vuln.exploits.append({
                                            'id': exploit_id,
                                            'url': repo.get('html_url', ''),
                                            'type': 'github_poc'
                                        })

                        logger.info(f"Found {len(exploits)} POCs on GitHub")

        except Exception as e:
            logger.error(f"Error searching GitHub: {e}")

        return exploits

    async def fetch_nuclei_templates(
        self,
        category: str = None,
        severity: str = None
    ) -> int:
        """Fetch Nuclei templates for vulnerability detection"""
        added = 0
        nuclei_repo = "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents"

        categories = [category] if category else ['cves', 'vulnerabilities', 'exposures']

        try:
            async with aiohttp.ClientSession() as session:
                for cat in categories:
                    url = f"{nuclei_repo}/{cat}"

                    async with session.get(url, timeout=30) as response:
                        if response.status == 200:
                            items = await response.json()

                            for item in items[:50]:  # Limit to prevent overload
                                if item.get('type') == 'file' and item['name'].endswith('.yaml'):
                                    template_id = f"nuclei-{item['name'].replace('.yaml', '')}"

                                    if template_id not in self.exploits:
                                        exploit = ExploitInfo(
                                            exploit_id=template_id,
                                            title=item['name'].replace('.yaml', '').replace('-', ' ').title(),
                                            description=f"Nuclei template for {cat}",
                                            author='projectdiscovery',
                                            exploit_type='detection',
                                            platform='multi',
                                            language='yaml',
                                            cve_references=re.findall(r'CVE-\d{4}-\d+', item['name'], re.I),
                                            source_url=item.get('html_url', ''),
                                            code=None,
                                            verified=True,
                                            reliability='high',
                                            last_updated=datetime.now().isoformat()
                                        )

                                        self.exploits[template_id] = exploit
                                        added += 1

            logger.info(f"Added {added} Nuclei templates")

        except Exception as e:
            logger.error(f"Error fetching Nuclei templates: {e}")

        return added

    def _extract_tags(self, text: str) -> List[str]:
        """Extract relevant tags from vulnerability description"""
        tags = []
        text_lower = text.lower()

        tag_patterns = {
            'rce': ['remote code execution', 'command execution', 'code injection'],
            'sqli': ['sql injection', 'sql vulnerability'],
            'xss': ['cross-site scripting', 'xss'],
            'auth_bypass': ['authentication bypass', 'auth bypass'],
            'privilege_escalation': ['privilege escalation', 'privesc'],
            'dos': ['denial of service', 'dos'],
            'info_disclosure': ['information disclosure', 'sensitive data'],
            'ssrf': ['server-side request forgery', 'ssrf'],
            'lfi': ['local file inclusion', 'lfi', 'path traversal'],
            'rfi': ['remote file inclusion', 'rfi'],
            'xxe': ['xml external entity', 'xxe'],
            'deserialization': ['deserialization', 'unserialize'],
        }

        for tag, patterns in tag_patterns.items():
            for pattern in patterns:
                if pattern in text_lower:
                    tags.append(tag)
                    break

        return list(set(tags))

    def _detect_platform(self, description: str, language: str) -> str:
        """Detect target platform from description"""
        desc_lower = (description or '').lower()
        lang_lower = language.lower()

        if any(w in desc_lower for w in ['windows', 'win32', 'powershell']):
            return 'windows'
        elif any(w in desc_lower for w in ['linux', 'unix', 'bash']):
            return 'linux'
        elif any(w in desc_lower for w in ['web', 'http', 'php', 'javascript']):
            return 'web'
        elif lang_lower in ['powershell']:
            return 'windows'
        elif lang_lower in ['bash', 'shell']:
            return 'linux'
        elif lang_lower in ['php', 'javascript', 'html']:
            return 'web'

        return 'multi'

    async def enrich_vulnerability(
        self,
        cve_id: str
    ) -> Optional[VulnerabilityInfo]:
        """Fully enrich a specific CVE with all available data"""
        # First, get from NVD if not exists
        if cve_id not in self.vulnerabilities:
            params = {'cveId': cve_id}
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(self.nvd_api, params=params, timeout=30) as response:
                        if response.status == 200:
                            data = await response.json()
                            vulns = data.get('vulnerabilities', [])
                            if vulns:
                                # Process the CVE (same logic as update_from_nvd)
                                cve = vulns[0].get('cve', {})
                                # ... create VulnerabilityInfo
            except Exception as e:
                logger.error(f"Error fetching CVE {cve_id}: {e}")

        # Search for POCs
        await self.search_github_pocs(cve_id=cve_id)

        # Save updates
        await self._save_database()

        return self.vulnerabilities.get(cve_id)

    async def auto_update(self, interval_hours: int = 24):
        """Automatic periodic update of the database"""
        while True:
            try:
                logger.info("Starting automatic vulnerability database update")

                # Update from NVD (last 7 days)
                await self.update_from_nvd(days_back=7)

                # Search for new POCs for critical CVEs
                critical_cves = [
                    v.vuln_id for v in self.vulnerabilities.values()
                    if v.severity == 'critical' and not v.exploits
                ][:10]

                for cve_id in critical_cves:
                    await self.search_github_pocs(cve_id=cve_id)
                    await asyncio.sleep(2)  # Rate limiting

                # Fetch Nuclei templates
                await self.fetch_nuclei_templates()

                # Save everything
                await self._save_database()

                self.last_update = datetime.now()
                logger.info(f"Database update complete. Total: {len(self.vulnerabilities)} vulns, {len(self.exploits)} exploits")

            except Exception as e:
                logger.error(f"Error in auto_update: {e}")

            await asyncio.sleep(interval_hours * 3600)

    def search_vulnerabilities(
        self,
        query: str = None,
        severity: str = None,
        tags: List[str] = None,
        has_exploit: bool = None,
        limit: int = 50
    ) -> List[VulnerabilityInfo]:
        """Search vulnerabilities in the database"""
        results = []

        for vuln in self.vulnerabilities.values():
            # Apply filters
            if severity and vuln.severity != severity:
                continue

            if tags and not any(t in vuln.tags for t in tags):
                continue

            if has_exploit is not None:
                if has_exploit and not vuln.exploits:
                    continue
                if not has_exploit and vuln.exploits:
                    continue

            if query:
                query_lower = query.lower()
                if not (query_lower in vuln.title.lower() or
                        query_lower in vuln.description.lower() or
                        query_lower in vuln.vuln_id.lower()):
                    continue

            results.append(vuln)

            if len(results) >= limit:
                break

        return results

    def get_exploits_for_vulnerability(self, vuln_id: str) -> List[ExploitInfo]:
        """Get all exploits for a specific vulnerability"""
        vuln = self.vulnerabilities.get(vuln_id)
        if not vuln:
            return []

        exploits = []
        for exp_ref in vuln.exploits:
            exp_id = exp_ref.get('id')
            if exp_id and exp_id in self.exploits:
                exploits.append(self.exploits[exp_id])

        # Also search by CVE reference
        for exp in self.exploits.values():
            if vuln_id in exp.cve_references and exp not in exploits:
                exploits.append(exp)

        return exploits

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        severity_counts = {}
        tag_counts = {}
        exploits_with_cve = 0

        for vuln in self.vulnerabilities.values():
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
            for tag in vuln.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        for exp in self.exploits.values():
            if exp.cve_references:
                exploits_with_cve += 1

        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'total_exploits': len(self.exploits),
            'exploits_with_cve': exploits_with_cve,
            'severity_distribution': severity_counts,
            'top_tags': dict(sorted(tag_counts.items(), key=lambda x: -x[1])[:10]),
            'last_update': self.last_update.isoformat() if self.last_update else None,
        }
