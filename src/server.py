from src import scanner
from src import toolbox
from src import webutils
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
import os
from time import sleep
from datetime import datetime
import threading
import json
import ctypes
import hashlib
from html import escape

app = Flask(__name__)
socketio = SocketIO(app)

OUTPUT_FILE = None
SCANNER_THREAD = None
RUNNING = False
LINES_READ = []
REPORT_PATH = None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/show_report")
def show_report():
    if REPORT_PATH is not None:
        return send_from_directory('../output',REPORT_PATH.replace('output/',''))
    else:
        return render_template("index.html")

@app.route('/launch_scan', methods=['POST'])
def launch_scan():
    
    global SCANNER_THREAD

    data = request.get_json()
    # print(json.dumps(data,indent=1))
    SCANNER_THREAD = threading.Thread(target=prepare_scan, args=(data,))
    RUNNING = True
    SCANNER_THREAD.start()

    return jsonify({
        "status": "success"
    })

@app.route('/stop_scan', methods=['POST'])
def stop_scan():
    
    global SCANNER_THREAD, RUNNING

    if SCANNER_THREAD is not None:
        RUNNING = False
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(SCANNER_THREAD.ident), ctypes.py_object(SystemExit))
        toolbox.warn("Scan terminated")

    return jsonify({
        "status": "success"
    })

def prepare_scan(data:dict):
    
    global OUTPUT_FILE, RUNNING, REPORT_PATH

    ATTACK_MODE = True
    SUBDOMAINS_ENUM = False
    SCOPE = "medium"
    FORCE = False
    FLAGS = 'XLSOBRM'
    SKIP_PARAMINER = False

    if "mode" in data and data["mode"] == "enum":
        ATTACK_MODE = False

    if "scope" in data and (data["scope"] == "strict" or data["scope"] == "full"):
            SCOPE = data["scope"]

    if ("subdomains" in data and data["subdomains"] == "yes") or SCOPE == "full":
        SUBDOMAINS_ENUM = True

    if "force" in data and data["force"] == "yes":
        FORCE = True

    if "attacks" in data and type(data["attacks"]) is list:
        FLAGS = ''
        for flag in data["attacks"]:
            if flag.upper() in 'XLSOBRM':
                FLAGS += flag.upper()

    if "paraminer" in data and data["paraminer"] == "yes":
        SKIP_PARAMINER = True

    if "headers" in data and type(data["headers"]) is list:
        for header in data["headers"]:
            key, value = header["key"], header["value"]
            while value.startswith(' '):
                value = value[1:]
            webutils.HEADERS[name] = value

    csv_dir = ""
    json_dir = ""

    if "output" in data and type(data["output"]) is list:
        for output in data["output"]:
            if output == "csv":
                csv_dir = "output/"
            if output == "json":
                json_dir = "output/"

    if not os.path.exists("output/"):
            os.mkdir("output") 

    if "target" in data and data["target"] != "":
        name = data["target"].replace(':','_').replace('/','')
        datenow = datetime.now().strftime('_%Y-%m-%d_%H_%M')
        OUTPUT_FILE = os.path.join("output/",name+datenow+".lincox")
        toolbox.log_to_dir(filename=OUTPUT_FILE,override=True)
        toolbox.set_debug(True)
        
        target = scanner.Target(data["target"],ATTACK_MODE,FORCE,SCOPE)

        target.initialize()

        if SUBDOMAINS_ENUM:
                target.enumerate_subdomains()
                if not SCOPE == "full":
                    REPORT_PATH = target.create_report(json_dir,csv_dir)
                    return

        target.search_services()

        target.enumerate_web_services()
        
        target.search_parameters(SKIP_PARAMINER)

        if not ATTACK_MODE:
            target.attack_mode = False
            REPORT_PATH = target.create_report(json_dir,csv_dir)
            return

        if 'X' in FLAGS:
            # search for reflected XSS and DOM XSS (in GET params)
            target.search_xss()

        if 'L' in FLAGS:
            # search local file inclusion (TODO: RFI ?)
            target.search_lfi()

        if 'S' in FLAGS:        
            # search SQL injection (integrate SQLmap)
            target.search_sqli()

        if 'O' in FLAGS: 
            # search open redirect (in GET params)
            target.search_open_redirect()
        
        if 'B' in FLAGS:
            # search default creds / small bruteforce if login detected
            target.auth_attack()

        if 'R' in FLAGS:
            # search SSRF (ngrok integration ?)
            target.search_ssrf()

        if 'M' in FLAGS:
            # search misconfigurations : headers, rate limiting, versions... (optional)
            target.search_misconfiguration()

        REPORT_PATH = target.create_report(json_dir,csv_dir)

@socketio.on("connect")
def handle_connect():

    global LINES_READ

    def read_file():
        
        if OUTPUT_FILE and os.path.exists(OUTPUT_FILE):
            with open(OUTPUT_FILE, "r") as f:
                f.seek(0, os.SEEK_SET)
                for line in f:
                    hash_value = hashlib.md5(line.encode()).hexdigest()
                    if hash_value not in LINES_READ:
                        socketio.emit("file_update", {"content": escape(line)})
                        LINES_READ.append(hash_value)

            with open(OUTPUT_FILE, "r") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if line:
                        hash_value = hashlib.md5(line.encode()).hexdigest()
                        if hash_value not in LINES_READ:
                            socketio.emit("file_update", {"content": escape(line)})
                            LINES_READ.append(hash_value)

    thread = threading.Thread(target=read_file)
    thread.daemon = True
    thread.start()

def run(port:int=5000):
    """
    start the web server on given port
    """
    socketio.run(app, port=port, debug=False)
