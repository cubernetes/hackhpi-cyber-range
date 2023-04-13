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



@app.route('/login', methods=['GET',"POST"])
def login_general():
    if request.method == "POST":
        commit_proper = True
        try:
            username = request.form['username']
            password_login = request.form['password_login']
            if username == "" and password_login == "":
                commit_proper = False
        except:
            commit_proper = False

        if commit_proper:
            all_user_files = os.listdir('database/users')
            matching_user_json = None
            for user_now in all_user_files:
                with open(f'database/users/{user_now}/user.json','r') as user_file:
                    user_json = json.load(user_file)
                if user_json["username"] == username or str(user_json["email"]).lower() == username.lower():
                    matching_user_json = user_json
            
            if not matching_user_json == None:
                if matching_user_json["password"] == password_login:
                    var_user_to_login = User(matching_user_json["id"])
                    login_user(var_user_to_login)
                    return redirect("/d1")
                else:
                    return render_template("login/invalid_credentials_noti.html")
            else:
                return render_template("login/invalid_credentials_noti.html")
        else:
            return render_template("login/invalid_credentials_noti.html")
    else:
        return render_template("login/main_login.html")


@app.route("/logout", methods=['GET']) #logout
def cpdashy_logout_main():
    try:
        logout_user()
    except:
        pass #prolly not even logged in
    return redirect("/login")



# Main Dashboard start

def cpdash_get_sidebar():
    with open('templates/sidebar.html','r') as f:
        sidebar = f.read()
    return(sidebar)

@app.route("/d1", methods=['GET']) #main manager dash
def cpdashy_1_main():
    if current_user.is_authenticated:
        userid = str(current_user.name).replace("user","").replace("User","").replace("USER","")
        with open(f'database/users/{userid}/user.json','r') as f:
            user_data = json.load(f)

        # Continue here -> log data reading

        return render_template("main/dashboard_main1.html",sidebar_html_insert=cpdash_get_sidebar().replace("active_state_class1","is-active"), profile_picture=user_data["picture"],profile_username=user_data["username"],profile_userid=user_data["userid"],profile_email=user_data["email"])

    else:
        return redirect('/login')


# Error handling
@app.errorhandler(401)
def custom_401(error):
    return redirect("/")


@app.errorhandler(404)
def custom_404(error):
    return redirect("/")

if __name__ == '__main__':
    app.run(host='185.78.255.231', threaded=True,use_reloader=True, port=443, ssl_context=('/etc/letsencrypt/live/network.kyudev.xyz/fullchain.pem', '/etc/letsencrypt/live/network.kyudev.xyz/privkey.pem'))