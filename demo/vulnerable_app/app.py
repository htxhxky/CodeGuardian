"""
⚠️  INTENTIONALLY VULNERABLE APP — FOR TESTING CodeGuardian ONLY ⚠️
Do NOT deploy this. It contains known vulnerabilities on purpose.
"""

from flask import Flask, request, redirect
import sqlite3
import os
import hashlib
import pickle
import random

app = Flask(__name__)

# VULN: Hardcoded secret
SECRET_KEY = "super_secret_password_123"
app.config["SECRET_KEY"] = SECRET_KEY

# VULN: Debug mode on
app.run(debug=True)


def get_db():
    return sqlite3.connect("users.db")


@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.args.get("password")

    db = get_db()
    cursor = db.cursor()

    # VULN: SQL injection
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        # VULN: Timing attack — direct equality check on token
        token = request.args.get("token")
        if token == user["token"]:
            return "Login OK"
    return "Login failed"


@app.route("/profile")
def profile():
    # VULN: XSS — user input returned directly
    name = request.args.get("name")
    return f"<h1>Hello, {name}</h1>"


@app.route("/redirect")
def open_redirect():
    # VULN: Open redirect
    next_url = request.args.get("next")
    return redirect(next_url)


@app.route("/session")
def restore_session():
    # VULN: Unsafe pickle deserialization
    data = request.args.get("data")
    obj = pickle.loads(bytes.fromhex(data))
    return str(obj)


@app.route("/reset_token")
def reset_token():
    # VULN: Insecure random for security token
    token = random.randint(100000, 999999)
    return str(token)


@app.route("/hash_password")
def hash_password():
    pw = request.args.get("pw")
    # VULN: Weak MD5 hash
    return hashlib.md5(pw.encode()).hexdigest()


@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    # VULN: Command injection
    result = os.system(cmd)
    return str(result)
