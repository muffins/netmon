#!/usr/bin/env python3

import json
import os
from typing import Dict

from flask import Flask, jsonify, Response, redirect, session, url_for
from flask_dance.contrib.google import make_google_blueprint, google
from oauthlib.oauth2.rfc6749.errors import TokenExpiredError
import boto3

devices_table = "netmon_devices"
client = boto3.client("dynamodb")
boto3.resource("dynamodb")


def _get_secrets() -> Dict[str, str]:
    with open(".env.json", "r") as fin:
        return json.loads(fin.read().strip())


app = Flask(__name__)
secrets = _get_secrets()
app.secret_key = secrets.get("secret_key")
CLIENT_ID = secrets.get("google_client_id")
CLIENT_SECRET = secrets.get("google_client_secret")
AUTH_USERS = set(secrets.get("authenticated_users", []))

# Something about Google changing OAuth scopes?
# https://tinyurl.com/2p8nemdf
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"
# Unsafe TLS while we're developing, I love being a clown.
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

blueprint = make_google_blueprint(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    reprompt_consent=True,
    scope=["profile", "email"],
)
app.register_blueprint(blueprint=blueprint, url_prefix="/login")

FRONT = """
<html>
<head>
<style>
h1 {text-align: center;}
p {text-align: center;}
div {text-align: center;}
</style>
</head>
<body>
"""

END = """
</body>
</html>
"""

LOGIN_LINK = """<a href="/login">here</a>"""

NOT_AUTH_RESP = f"""
{FRONT}
<h1>Local Network Devices</h1>
<p>You are not authenticated, login {LOGIN_LINK}</p>
{END}
"""


@app.route("/")
def index() -> Response:
    devices = None
    user_info_endpoint = "/oauth2/v2/userinfo"
    if google.authorized:
        try:
            user = google.get(user_info_endpoint).json()
        except TokenExpiredError:
            return f"Your token has expired, please re-authenticate: {LOGIN_LINK}"

        if user.get("email") in AUTH_USERS:
            awsdevices = client.scan(TableName=devices_table)
            deserializer = boto3.dynamodb.types.TypeDeserializer()
            devices = [
                {k: deserializer.deserialize(v) for k, v in x.items()}
                for x in awsdevices["Items"]
            ]
            return jsonify(devices)
        else:
            return f"""
{FRONT}
<h1>Hello {user.get("name", "Anonymous")}!</h1>
<p>You're not allowed to see this content, sorry. Contact nanderson7@gmail.com 
if you'd like access.</p>
{END}
"""
    else:
        return NOT_AUTH_RESP


@app.route("/login")
def login():
    resp = redirect(url_for("google.login"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "-1"
    return resp


if __name__ == "__main__":
    app.run()
