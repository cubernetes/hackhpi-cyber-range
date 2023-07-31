#!/usr/bin/env python3

import os, datetime, requests, random, json, time, string, re
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, request, render_template, redirect, send_file, url_for, jsonify, session, flash, after_this_request
from flask_login import current_user, login_user, LoginManager, UserMixin, login_required, login_user, logout_user
from flask_mobility import Mobility
from flask_caching import Cache
from flask_ipban import IpBan
from fpdf import FPDF
from device_detector import DeviceDetector
from flask_sslify import SSLify
from requests_oauthlib import OAuth2Session
from shutil import copyfile
from werkzeug.middleware.shared_data import SharedDataMiddleware
from oauthlib.oauth2 import WebApplicationClient
from discord_webhook import DiscordWebhook, DiscordEmbed

STARTED = 0

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
        self.name = 'user' + str(id)
        self.password = self.name + '_secret'

    def __repr__(self):
        return '%d/%s/%s' % (self.id, self.name, self.password)

@login_manager.user_loader
def load_user(userid):
    return User(userid)

def get_username(self):
    return self.username

@app.route('/')
def homepage():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login_general():
    if request.method == 'POST':
        commit_proper = True
        try:
            username = request.form['username']
            password_login = request.form['password_login']
            if username == '' and password_login == '':
                commit_proper = False
        except:
            commit_proper = False

        if commit_proper:
            all_user_files = os.listdir('./database/users')
            matching_user_json = None
            for user_now in all_user_files:
                with open(f'./database/users/{user_now}/user.json') as user_file:
                    user_json = json.load(user_file)
                if user_json['username'] == username or str(user_json['email']).lower() == username.lower():
                    matching_user_json = user_json
            
            if not matching_user_json == None:
                if matching_user_json['password'] == password_login:
                    var_user_to_login = User(matching_user_json['userid'])
                    login_user(var_user_to_login)
                    return redirect('/d1')
                else:
                    return render_template('login/invalid_credentials_noti.html')
            else:
                return render_template('login/invalid_credentials_noti.html')
        else:
            return render_template('login/invalid_credentials_noti.html')
    else:
        return render_template('login/main_login.html')

@app.route('/logout', methods=['GET'])
def cpdashy_logout_main():
    try:
        logout_user()
    except:
        pass #prolly not even logged in
    return redirect('/login')

# Main Dashboard start
def extract_time(json):
    try:
        return json['timestamp']
    except KeyError:
        return 0

def cpdash_get_sidebar():
    with open('templates/sidebar.html') as f:
        sidebar = f.read()
    return sidebar

@app.route('/d1', methods=['GET']) #main manager dash
def cpdashy_1_main():
    global STARTED
    if current_user.is_authenticated:
        userid = str(current_user.name).replace('user', '').replace('User', '').replace('USER', '')
        with open(f'./database/users/{userid}/user.json') as f:
            user_data = json.load(f)

        if not os.path.exists('./database/temp/sim_running.txt'):
            sim_running = 'False'
        else:
            with open('./database/temp/sim_running.txt') as f:
                sim_running = f.read()

        if not os.path.exists('./database/temp/sim_start.txt'):
            sim_start_timestamp = '-1'
            STARTED = False
        else:
            with open('./database/temp/sim_start.txt') as f:
                sim_start_timestamp = f.read()
            STARTED = True

        if not os.path.exists('./database/temp/attack_start.txt'):
            attack_start_timestamp = '-1'
        else:
            with open('./database/temp/attack_start.txt') as f:
                attack_start_timestamp = f.read()

        with open('./database/logs/blue.json') as f:
            blue_logs_list_ori = json.load(f)
        blue_logs_list = []
        for blue_log_now in blue_logs_list_ori:
            blue_log_now['timestamp'] = str(int(time.time()))
            blue_log_now['origin'] = 'blue'
            blue_log_now['timeline_class'] = 'container_time_right'
            blue_log_now['timeline_side'] = 'right'
            blue_logs_list.append(blue_log_now)

        with open('./database/logs/red.json') as f:
            red_logs_list_ori = json.load(f)
        red_logs_list = []
        for red_log_now in red_logs_list_ori:
            red_log_now['timestamp'] = str(int(time.time()))
            red_log_now['origin'] = 'red'
            red_log_now['timeline_class'] = 'container_time'
            red_log_now['timeline_side'] = 'left'
            red_logs_list.append(red_log_now)

        total_logs_list = []
        total_logs_list.extend(blue_logs_list)
        total_logs_list.extend(red_logs_list)
        total_logs_list.sort(key=extract_time, reverse=True)

        blue_logs_list.reverse()
        red_logs_list.reverse()
        # total_logs_list.reverse()

        return render_template('main/dashboard_main1.html', total_logs_list=total_logs_list, attack_start_timestamp=attack_start_timestamp, blue_logs_list=blue_logs_list, red_logs_list=red_logs_list, sim_running=sim_running, sim_start_timestamp=sim_start_timestamp, sidebar_html_insert=cpdash_get_sidebar().replace('active_state_class1', 'is-active'), profile_picture=user_data['picture'], profile_username=user_data['username'], profile_userid=user_data['userid'], profile_email=user_data['email'])
    else:
        return redirect('/login')

@app.route('/d2', methods=['GET']) #logs
def cpdashy_2_main():
    if current_user.is_authenticated:
        userid = str(current_user.name).replace('user', '').replace('User', '').replace('USER', '')
        with open(f'./database/users/{userid}/user.json') as f:
            user_data = json.load(f)

        if not os.path.exists('./database/temp/sim_running.txt'):
            sim_running = 'False'
        else:
            with open('./database/temp/sim_running.txt') as f:
                sim_running = f.read()

        if not os.path.exists('./database/temp/sim_start.txt'):
            sim_start_timestamp = '0'
        else:
            with open('./database/temp/sim_start.txt') as f:
                sim_start_timestamp = int(f.read().split('.')[0])
            
            min, sec = divmod(int(time.time()) - int(sim_start_timestamp), 60)
            sim_start_timestamp = str(int(min)) + 'm&nbsp;' + str(int(round(sec, 0))) + 's'

        if not os.path.exists('./database/temp/attack_start.txt'):
            attack_start_timestamp = '0'
        else:
            with open('./database/temp/attack_start.txt') as f:
                attack_start_timestamp = int(f.read().split('.')[0])
            
            min, sec = divmod(int(time.time()) - int(attack_start_timestamp), 60)
            attack_start_timestamp = str(int(min)) + 'm&nbsp;' + str(int(round(sec, 0))) + 's'

        with open('./database/logs/blue.json') as f:
            blue_logs_list_ori = json.load(f)
        blue_logs_list = []
        for blue_log_now in blue_logs_list_ori:
            min, sec = divmod(int(time.time()) - int(blue_log_now['timestamp']), 60)
            blue_log_now['timestamp'] = str(int(min)) + 'm&nbsp;' + str(int(round(sec, 0))) + 's'
            blue_log_now['origin'] = 'blue'
            blue_log_now['timeline_class'] = 'container_time_right'
            blue_log_now['timeline_side'] = 'right'
            blue_logs_list.append(blue_log_now)

        with open('./database/logs/red.json') as f:
            red_logs_list_ori = json.load(f)
        red_logs_list = []
        for red_log_now in red_logs_list_ori:
            min, sec = divmod(int(time.time()) - int(red_log_now['timestamp']), 60)
            red_log_now['timestamp'] = str(int(min)) + 'm&nbsp;' + str(int(round(sec, 0))) + 's'
            red_log_now['origin'] = 'red'
            red_log_now['timeline_class'] = 'container_time'
            red_log_now['timeline_side'] = 'left'
            red_logs_list.append(red_log_now)

        total_logs_list = []
        total_logs_list.extend(blue_logs_list)
        total_logs_list.extend(red_logs_list)
        total_logs_list.sort(key=extract_time, reverse=True)

        blue_logs_list.reverse()
        red_logs_list.reverse()
        total_logs_list.reverse()

        return render_template('main/dashboard_main2.html', total_logs_list=total_logs_list, attack_start_timestamp=attack_start_timestamp, blue_logs_list=blue_logs_list, red_logs_list=red_logs_list, sim_running=sim_running, sim_start_timestamp=sim_start_timestamp, sidebar_html_insert=cpdash_get_sidebar().replace('active_state_class2', 'is-active'), profile_picture=user_data['picture'], profile_username=user_data['username'], profile_userid=user_data['userid'], profile_email=user_data['email'])
    else:
        return redirect('/login')
    
@app.route('/d1/startsim', methods=['GET']) #start and stop the sim
def cpdashy_startsim():
    if current_user.is_authenticated:
        if os.path.exists('./database/temp/sim_running.txt'):
            with open('./database/temp/sim_running.txt') as f:
                current_state = f.read()
            if not current_state == 'False':
                with open('./database/temp/sim_running.txt', 'w') as f:
                    f.write('False')
            else:
                clear_session_full()
                with open('./database/temp/sim_start.txt', 'w') as f:
                    f.write(str(int(time.time())))
                with open('./database/temp/sim_running.txt', 'w') as f:
                    f.write('True')
        else:
            clear_session_full()
            with open('./database/temp/sim_start.txt', 'w') as f:
                f.write(str(int(time.time())))
            with open('./database/temp/sim_running.txt', 'w') as f:
                f.write('True')
        return redirect('/d1')
    else:
        return redirect('/login')
    

@app.route("/d3", methods=['GET']) #victim specs
def cpdashy_3_main():
    if current_user.is_authenticated:
        userid = str(current_user.name).replace("user","").replace("User","").replace("USER","")
        with open(f'database/users/{userid}/user.json','r') as f:
            user_data = json.load(f)

        if not os.path.exists("database/temp/attack_start.txt"):
            attack_start_timestamp = "0"
        else:
            with open("database/temp/attack_start.txt","r") as f:
                attack_start_timestamp = int(f.read().split(".")[0])
            
            min, sec = divmod(time.time() - int(attack_start_timestamp),60)
            attack_start_timestamp = str(int(min)) + "m&nbsp;" + str(int(round(sec,0))) + "s"

        if attack_start_timestamp == "0":
            reachable = "<b style='color: green'>True</b>"
            cpu_percentage = random.choice(["7%","8%","9%","10%","11%"])
            ram_percentage = random.choice(["7%","8%","9%","10%","11%"])
            ports_open = ["80","443"]
        else:
            reachable = "<b style='color: green'>True</b>"
            cpu_percentage = random.choice(["67%","48%","90%","17%","81%"])
            ram_percentage = random.choice(["19%","8%","9%","10%","11%"])
            ports_open = ["80","443"]



        return render_template("main/dashboard_main3.html",reachable=reachable,cpu_percentage=cpu_percentage,ram_percentage=ram_percentage,ports_open=ports_open,attack_start_timestamp=attack_start_timestamp,sidebar_html_insert=cpdash_get_sidebar().replace("active_state_class3","is-active"), profile_picture=user_data["picture"],profile_username=user_data["username"],profile_userid=user_data["userid"],profile_email=user_data["email"])
    else:
        return redirect('/login')
    

def generate_proof_pdf():
    with open('./database/logs/blue.json') as f:
        blue_logs_list_ori = json.load(f)
    blue_logs_list = []
    for blue_log_now in blue_logs_list_ori:
        blue_log_now['timestamp'] = datetime.datetime.fromtimestamp(int(blue_log_now['timestamp'])).strftime("%H:%M:%S")
        blue_log_now['origin'] = 'blue'
        blue_log_now['timeline_class'] = 'container_time_right'
        blue_log_now['timeline_side'] = 'right'
        blue_logs_list.append(blue_log_now)

    with open('./database/logs/red.json') as f:
        red_logs_list_ori = json.load(f)
    red_logs_list = []
    for red_log_now in red_logs_list_ori:
        red_log_now['timestamp'] = datetime.datetime.fromtimestamp(int(red_log_now['timestamp'])).strftime("%H:%M:%S")
        red_log_now['origin'] = 'red'
        red_log_now['timeline_class'] = 'container_time'
        red_log_now['timeline_side'] = 'left'
        red_logs_list.append(red_log_now)

    total_logs_list = []
    total_logs_list.extend(blue_logs_list)
    total_logs_list.extend(red_logs_list)
    total_logs_list.sort(key=extract_time, reverse=True)

    pdf = FPDF()
    pdf.add_page()

    pdf.image("static/icon/main_free.png", x=175, y=13, w=25, h=25, type='png', link='https://hackhpi.kyudev.xyz')

    pdf.ln(h=8) #br
    pdf.set_font("arial", size=28)
    pdf.cell(0, 10, txt="CyberRange Export",  ln=1, align='L')
    pdf.set_font("arial", size=12)
    pdf.ln() #br
    pdf.cell(0, 10, txt="Log export of ", ln=1, align='L')

    pdf.set_font("arial", size=15, style="b")
    pdf.cell(0, 8, txt=datetime.datetime.now().strftime("%d.%m.%Y, %H:%M:%S"), ln=2, align='L') #name_entered
    pdf.set_font("arial", size=10)
    pdf.cell(0, 0, txt="Employee 2982373", ln=0) #userid

    pdf.ln() #br
    pdf.ln(h=10) #br
    pdf.set_font("arial", size=12)

    for log_now in total_logs_list:
        data = re.sub('(<[a-z].*?>)|(</[a-z].*?>)', '', log_now["data"])
        if log_now["origin"] == "red":
            pdf.cell(0, 12, txt=f'{log_now["timestamp"]} | Attacker: {data}', ln=2, align='L')
        else:
            pdf.cell(0, 12, txt=f'{log_now["timestamp"]} | Defender: {data}', ln=2, align='L')


    pdf.output(f'database/pdfs/export.pdf')

@app.route("/d4", methods=['GET']) #pdf
def cpdashy_4_main():
    if current_user.is_authenticated:
        userid = str(current_user.name).replace("user","").replace("User","").replace("USER","")
        with open(f'database/users/{userid}/user.json','r') as f:
            user_data = json.load(f)

        generate_proof_pdf()
        return send_file(f'database/pdfs/export.pdf',as_attachment=True)
    else:
        return redirect('/login')

# API
def clear_session_full():
    for file_now in ['./database/temp/sim_start.txt', './database/temp/attack_start.txt', './database/temp/sim_running.txt', './database/temp/attack_running.txt']:
        try:
            os.remove(file_now)
        except:
            pass
    with open('./database/logs/red.json', 'w') as f:
        f.write('[]')
    with open('./database/logs/blue.json', 'w') as f:
        f.write('[]')

@app.route('/api/logs', methods=['GET'])
def api_get_logs():
    with open('./database/logs/red.json') as f:
        red_raw = f.read()
    red = json.loads(red_raw)
    with open('./database/logs/blue.json') as f:
        blue_raw = f.read()
    blue = json.loads(blue_raw)

    result = {
        'red': red,
        'blue': blue
    }
    return json.dumps(result, ensure_ascii=False)

def datas(logs):
    for log in logs:
        yield log['data']

@app.route('/api/red', methods=['POST'])
def api_red_logs():
    global STARTED
    temp_json_n = request.json
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        remote_addr = request.environ['REMOTE_ADDR']
    else:
        remote_addr = request.environ['HTTP_X_FORWARDED_FOR']
    temp_json_n['data'] = remote_addr + ': ' + temp_json_n['data']

    if STARTED:
        if 'start of attack' in temp_json_n['data'].lower():
            with open('./database/temp/attack_start.txt', 'w') as f:
                f.write(str(temp_json_n['timestamp']))

        with open('./database/logs/red.json') as f:
            logs_list = json.load(f)
        if temp_json_n['data'] not in datas(logs_list):
            logs_list.append(temp_json_n)
        with open('./database/logs/red.json', 'w') as f:
            json.dump(logs_list, f, ensure_ascii=False)

        return 'log saved\n'
    else:
        return 'simulation not started\n'

@app.route('/api/blue', methods=['POST'])
def api_blue_logs():
    global STARTED
    temp_json_n = request.json

    if STARTED:
        with open('./database/logs/blue.json') as f:
            logs_list = json.load(f)
        logs_list.append(temp_json_n)
        with open('./database/logs/blue.json', 'w') as f:
            json.dump(logs_list, f, ensure_ascii=False)

        return 'log saved\n'
    else:
        return 'simulation not started\n'

# Error handling
@app.errorhandler(401)
def custom_401(error):
    return redirect('/')

@app.errorhandler(404)
def custom_404(error):
    return redirect('/')

clear_session_full()

if __name__ == '__main__':
    app.run(host='0.0.0.0', threaded=True, use_reloader=True, port=8086)
    # app.run(host='185.78.255.231', threaded=True,use_reloader=True, port=443, ssl_context=('/etc/letsencrypt/live/network.kyudev.xyz/fullchain.pem', '/etc/letsencrypt/live/network.kyudev.xyz/privkey.pem'))
