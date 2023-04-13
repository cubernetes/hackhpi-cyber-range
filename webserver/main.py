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
from base64 import b64decode

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
                    var_user_to_login = User(matching_user_json["userid"])
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
def extract_time(json):
    try:
        return int(int(json['timestamp'].split("m")[0])*60 + int(json['timestamp'].split("m")[1].replace("m","").replace("s","").replace(" ","").replace("&nbp;","")))
    except KeyError:
        return 0

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

        if not os.path.exists("database/temp/sim_running.txt"):
            sim_running = "False"
        else:
            with open("database/temp/sim_running.txt","r") as f:
                sim_running = f.read()

        if not os.path.exists("database/temp/sim_start.txt"):
            sim_start_timestamp = "0"
        else:
            with open("database/temp/sim_start.txt","r") as f:
                sim_start_timestamp_stamp = int(f.read().split(".")[0])
            
            min, sec = divmod(time.time() - int(sim_start_timestamp_stamp),60)
            sim_start_timestamp = str(int(min)) + "m&nbsp;" + str(int(round(sec,0))) + "s"


        if not os.path.exists("database/temp/attack_start.txt"):
            attack_start_timestamp = "0"
        else:
            with open("database/temp/attack_start.txt","r") as f:
                attack_start_timestamp = int(f.read().split(".")[0])
            
            min, sec = divmod(time.time() - int(attack_start_timestamp),60)
            attack_start_timestamp = str(int(min)) + "m&nbsp;" + str(int(round(sec,0))) + "s"




        with open("database/logs/blue.json","r") as f:
            blue_logs_list_ori = json.load(f)
        blue_logs_list = []
        for blue_log_now in blue_logs_list_ori:
            min, sec = divmod(time.time() - int(blue_log_now["timestamp"]),60)
            blue_log_now["timestamp"] = str(int(min)) + "m&nbsp;" + str(int(round(sec,0))) + "s"
            blue_log_now["origin"] = "blue"
            blue_log_now["timeline_class"] = "container_time_right"
            blue_log_now["timeline_side"] = "right"
            blue_logs_list.append(blue_log_now)

        with open("database/logs/red.json","r") as f:
            red_logs_list_ori = json.load(f)
        red_logs_list = []
        for red_log_now in red_logs_list_ori:
            min, sec = divmod(time.time() - int(red_log_now["timestamp"]),60)
            red_log_now["timestamp"] = str(int(min)) + "m&nbsp;" + str(int(round(sec,0))) + "s"
            red_log_now["origin"] = "red"
            red_log_now["timeline_class"] = "container_time"
            red_log_now["timeline_side"] = "left"
            red_logs_list.append(red_log_now)

        total_logs_list = []
        total_logs_list.extend(blue_logs_list)
        total_logs_list.extend(red_logs_list)
        total_logs_list.sort(key=extract_time, reverse=True)

        blue_logs_list.reverse()
        red_logs_list.reverse()
        # total_logs_list.reverse()

        return render_template("main/dashboard_main1.html",total_logs_list=total_logs_list,attack_start_timestamp=attack_start_timestamp,blue_logs_list=blue_logs_list,red_logs_list=red_logs_list,sim_running=sim_running,sim_start_timestamp=sim_start_timestamp,sidebar_html_insert=cpdash_get_sidebar().replace("active_state_class1","is-active"), profile_picture=user_data["picture"],profile_username=user_data["username"],profile_userid=user_data["userid"],profile_email=user_data["email"])
    else:
        return redirect('/login')
    

@app.route("/d2", methods=['GET']) #logs
def cpdashy_2_main():
    if current_user.is_authenticated:
        userid = str(current_user.name).replace("user","").replace("User","").replace("USER","")
        with open(f'database/users/{userid}/user.json','r') as f:
            user_data = json.load(f)

        if not os.path.exists("database/temp/sim_running.txt"):
            sim_running = "False"
        else:
            with open("database/temp/sim_running.txt","r") as f:
                sim_running = f.read()

        if not os.path.exists("database/temp/sim_start.txt"):
            sim_start_timestamp = "0"
        else:
            with open("database/temp/sim_start.txt","r") as f:
                sim_start_timestamp_stamp = int(f.read().split(".")[0])
            
            min, sec = divmod(time.time() - int(sim_start_timestamp_stamp),60)
            sim_start_timestamp = str(int(min)) + "m&nbsp;" + str(int(round(sec,0))) + "s"


        if not os.path.exists("database/temp/attack_start.txt"):
            attack_start_timestamp = "0"
        else:
            with open("database/temp/attack_start.txt","r") as f:
                attack_start_timestamp = int(f.read().split(".")[0])
            
            min, sec = divmod(time.time() - int(attack_start_timestamp),60)
            attack_start_timestamp = str(int(min)) + "m&nbsp;" + str(int(round(sec,0))) + "s"




        with open("database/logs/blue.json","r") as f:
            blue_logs_list_ori = json.load(f)
        blue_logs_list = []
        for blue_log_now in blue_logs_list_ori:
            min, sec = divmod(time.time() - int(blue_log_now["timestamp"]),60)
            blue_log_now["timestamp"] = str(int(min)) + "m&nbsp;" + str(int(round(sec,0))) + "s"
            blue_log_now["origin"] = "blue"
            blue_log_now["timeline_class"] = "container_time_right"
            blue_log_now["timeline_side"] = "right"
            blue_logs_list.append(blue_log_now)

        with open("database/logs/red.json","r") as f:
            red_logs_list_ori = json.load(f)
        red_logs_list = []
        for red_log_now in red_logs_list_ori:
            min, sec = divmod(time.time() - int(red_log_now["timestamp"]),60)
            red_log_now["timestamp"] = str(int(min)) + "m&nbsp;" + str(int(round(sec,0))) + "s"
            red_log_now["origin"] = "red"
            red_log_now["timeline_class"] = "container_time"
            red_log_now["timeline_side"] = "left"
            red_logs_list.append(red_log_now)

        total_logs_list = []
        total_logs_list.extend(blue_logs_list)
        total_logs_list.extend(red_logs_list)
        total_logs_list.sort(key=extract_time, reverse=True)

        blue_logs_list.reverse()
        red_logs_list.reverse()
        total_logs_list.reverse()

        return render_template("main/dashboard_main2.html",total_logs_list=total_logs_list,attack_start_timestamp=attack_start_timestamp,blue_logs_list=blue_logs_list,red_logs_list=red_logs_list,sim_running=sim_running,sim_start_timestamp=sim_start_timestamp,sidebar_html_insert=cpdash_get_sidebar().replace("active_state_class2","is-active"), profile_picture=user_data["picture"],profile_username=user_data["username"],profile_userid=user_data["userid"],profile_email=user_data["email"])
    else:
        return redirect('/login')
    
@app.route("/d1/startsim", methods=['GET']) #start and stop the sim
def cpdashy_startsim():
    if current_user.is_authenticated:
        if os.path.exists("database/temp/sim_running.txt"):
            with open("database/temp/sim_running.txt","r") as f:
                current_state = f.read()
            if not current_state == "False":
                with open("database/temp/sim_running.txt","w") as f:
                    f.write("False")
            else:
                clear_session_full()
                with open("database/temp/sim_start.txt","w") as f:
                    f.write(str(time.time()))
                with open("database/temp/sim_running.txt","w") as f:
                    f.write("True")
            
        else:
            clear_session_full()
            with open("database/temp/sim_start.txt","w") as f:
                f.write(str(time.time()))
            with open("database/temp/sim_running.txt","w") as f:
                f.write("True")
        return redirect("/d1")
    else:
        return redirect('/login')
    

# API
def clear_session_full():
    for file_now in ["database/temp/sim_start.txt","database/temp/attack_start.txt","database/temp/sim_running.txt","database/temp/attack_running.txt"]:
        try:
            os.remove(file_now)
        except:
            pass
    with open("database/logs/red.json","w") as f:
        f.write("[]")
    with open("database/logs/blue.json","w") as f:
        f.write("[]")

@app.route("/api/red", methods=['POST'])
def api_red_logs():
    temp_json_n = request.json
    print("red log received")
    print(temp_json_n)

    if temp_json_n["data"].lower() == "start of attack":
        with open("database/temp/attack_start.txt",'w') as f:
            f.write(str(temp_json_n["timestamp"]))

    with open("database/logs/red.json","r") as f:
        logs_list = json.load(f)
    logs_list.append(temp_json_n)
    with open("database/logs/red.json","w") as f:
        json.dump(logs_list,f)

    return("log saved")


@app.route("/api/blue", methods=['POST'])
def api_blue_logs():
    temp_json_n = request.json
    temp_json_n["data"] = b64decode(temp_json_n["data"]).decode("utf-8").replace("\n","<br>")
    print("blue log received")
    print(temp_json_n)


    with open("database/logs/blue.json","r") as f:
        logs_list = json.load(f)
    logs_list.append(temp_json_n)
    with open("database/logs/blue.json","w") as f:
        json.dump(logs_list,f)

    return("log saved")




# Error handling
@app.errorhandler(401)
def custom_401(error):
    return redirect("/")

@app.errorhandler(404)
def custom_404(error):
    return redirect("/")

clear_session_full()

if __name__ == '__main__':
    app.run(host='185.78.255.231', threaded=True,use_reloader=True, port=443, ssl_context=('/etc/letsencrypt/live/network.kyudev.xyz/fullchain.pem', '/etc/letsencrypt/live/network.kyudev.xyz/privkey.pem'))