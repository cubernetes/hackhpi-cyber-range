import os, datetime, requests, random, json, time, string
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, request, render_template, redirect, send_file, url_for, jsonify, session, flash, after_this_request
from flask_login import current_user, login_user, LoginManager, UserMixin, login_required, login_user, logout_user
from flask_mobility import Mobility
from flask_caching import Cache
from flask_ipban import IpBan
from device_detector import DeviceDetector
from flask_sslify import SSLify
from requests_oauthlib import OAuth2Session
from shutil import copyfile
from werkzeug.middleware.shared_data import SharedDataMiddleware
from oauthlib.oauth2 import WebApplicationClient
from discord_webhook import DiscordWebhook, DiscordEmbed

contact_support_dc_webhook = ""

app = Flask(__name__)

app.config.update(
    DEBUG=False,
    SECRET_KEY='secret_password_' + ''.join(str(random.choice(string.ascii_lowercase)) for i in range(20))
)

login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin):
    def __init__(self, id):
        self.id = id
        self.name = "user" + str(id)
        self.password = self.name + "_secret"

    def __repr__(self):
        return "%d/%s/%s" % (self.id, self.name, self.password)

@login_manager.user_loader
def load_user(userid):
    return User(userid)


def get_username(self):
    return self.username


@app.route('/')
def homepage():
    return redirect("/login")


# Error handling
@app.errorhandler(401)
def custom_401(error):
    return redirect("/")


@app.errorhandler(404)
def custom_404(error):
    return redirect("/")

if __name__ == '__main__':
    app.run(host='185.78.255.231', threaded=True,use_reloader=True, port=443, 
            ssl_context=('/etc/letsencrypt/live/cipherwatch.asdatindustries.com/fullchain.pem', '/etc/letsencrypt/live/cipherwatch.asdatindustries.com/privkey.pem'))