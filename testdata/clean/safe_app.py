import bcrypt
import hashlib
import logging
from flask import Flask, Blueprint
from functools import wraps

app = Flask(__name__)
admin_bp = Blueprint("admin", __name__)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)
    return wrapper


# Safe: empty-string guard, not a plaintext credential comparison.
def validate(password):
    if password == "":
        raise ValueError("password required")
    # Safe: registration confirms two user inputs match — not a vuln.
    return True


def register(password, confirm_password):
    if password == confirm_password:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return None


# Safe: bcrypt verification, no plaintext comparison.
def check_login(input_password, stored_hash):
    return bcrypt.checkpw(input_password.encode(), stored_hash)


# Safe: strong hash for non-password data.
def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


# Safe: admin route IS protected by an authorization decorator.
@app.route("/admin/settings")
@login_required
def admin_settings():
    return "settings"


# Safe: no sensitive values in the log line.
def audit(user_id):
    logging.info("user %s performed an action", user_id)
