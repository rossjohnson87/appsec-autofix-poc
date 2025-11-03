from flask import Flask, request, jsonify
from .db import init_db, get_user_by_email
from .http_client import fetch_url

app = Flask(__name__)
init_db()  # create a tiny sqlite DB on startup

@app.get("/user")
def user():
    email = request.args.get("email", "")
    row = get_user_by_email(email)  # INTENTIONAL SQLi risk
    return jsonify({"result": row})

@app.get("/fetch")
def fetch():
    url = request.args.get("url", "")
    content, status = fetch_url(url)  # INTENTIONAL SSRF risk
    return (content, status, {"Content-Type": "text/plain"})

if __name__ == "__main__":
    app.run(debug=True)
