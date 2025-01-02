import requests
from src.webutils import get_headers, get_page_source
from urllib.parse import quote_plus

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
        page = get_page_source(f"{url}/?{param}={payload}")
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