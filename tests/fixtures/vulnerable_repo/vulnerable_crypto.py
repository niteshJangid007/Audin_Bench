# Vulnerable Cryptography & Hardcoded Secrets
import hashlib

# Flaw: RULE_A02_HARDCODED_KEY
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"

def hash_user_password(password):
    # Flaw: RULE_A02_WEAK_HASH
    return hashlib.md5(password.encode()).hexdigest()
