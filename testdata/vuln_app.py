import hashlib
import logging
import ssl

# EXPLAIN-001: Authentication weakness - plaintext password comparison
def check_login(input_password, stored):
    if input_password == stored:
        return True
    hashed = hashlib.md5(input_password.encode() + b"password")
    return False

# EXPLAIN-002: Data exposure - logging sensitive data
def process_payment(credit_card, token):
    logging.info("Processing payment with token: %s", token)
    print("Card number: %s, token: %s" % (credit_card, token))

# EXPLAIN-003: Access control gap - admin routes without auth middleware
from flask import Flask, Blueprint
app = Flask(__name__)
admin_bp = Blueprint("admin", __name__)

@app.route("/admin/settings")
def admin_settings():
    return "settings"

@admin_bp.route("/admin/delete")
def admin_delete():
    return "deleted"

# EXPLAIN-004: Encryption weakness - weak hash algorithms
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

def hash_token(token):
    return hashlib.sha1(token.encode()).hexdigest()

old_context = ssl.PROTOCOL_TLSv1
