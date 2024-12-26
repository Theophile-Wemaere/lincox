from termcolor import colored
from datetime import datetime
import lincox as main

DEBUG = False

def set_debug(status):

    global DEBUG
    DEBUG = status
    print(f"DEBUG : {DEBUG}")

def print_banner():
    banner = """
 █████       █████ ██████   █████   █████████     ███████    █████ █████
░░███       ░░███ ░░██████ ░░███   ███░░░░░███  ███░░░░░███ ░░███ ░░███ 
 ░███        ░███  ░███░███ ░███  ███     ░░░  ███     ░░███ ░░███ ███  
 ░███        ░███  ░███░░███░███ ░███         ░███      ░███  ░░█████   
 ░███        ░███  ░███ ░░██████ ░███         ░███      ░███   ███░███  
 ░███      █ ░███  ░███  ░░█████ ░░███     ███░░███     ███   ███ ░░███ 
 ███████████ █████ █████  ░░█████ ░░█████████  ░░░███████░   █████ █████
░░░░░░░░░░░ ░░░░░ ░░░░░    ░░░░░   ░░░░░░░░░     ░░░░░░░    ░░░░░ ░░░░░

By Theophile.W, Quentin.L, Maximilien.L, Maxime.V and Nithyalakshmi.P
        
"""
    print(banner)

def exit_error(msg,code):
    """
    print error message and exit
    """

    print()
    print(get_header("ERROR")+msg)
    exit(code)

def get_header(type:str)->str:
    """
    get timestamp and type header
    """

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    timestamp_header = '[' + colored(timestamp,"blue") + ']'
    if type == "DEBUG":
        return timestamp_header + ' ' + '['+colored("DEBUG",attrs=["bold"])+'] '

    if type == "INFO":
        return timestamp_header + ' ' + '['+colored("INFO","green")+'] '

    if type == "ATTACK":
        return timestamp_header + ' ' + '['+colored("ATTACK","light_red",attrs=["bold"])+'] '

    if type == "WARNING":
        return timestamp_header + ' ' + '['+colored("WARNING","black","on_light_yellow")+'] '

    if type == "ERROR":
        return timestamp_header + ' ' + '['+colored("ERROR","yellow","on_red")+'] '

    if type == "VULN1":
        return timestamp_header + ' ' + '['+colored("LOW","black","on_blue",attrs=["bold"])+'] '
    if type == "VULN2":
        return timestamp_header + ' ' + '['+colored("MEDIUM","black","on_yellow",attrs=["bold"])+'] '
    if type == "VULN3":
        return timestamp_header + ' ' + '['+colored("HIGH","black","on_light_red",attrs=["bold"])+'] '

def debug(msg):
    """
    print debug message
    """

    if not DEBUG:
        return

    print(get_header("DEBUG")+msg)

def tprint(*args,start='',end='\n'):
    """
    toolbox print with timestamp and colors
    """
    print(start,end='')
    print(get_header("INFO")+" ".join(map(str, args)),end='')
    print(end,end='')

def vprint(*args,start='',end='\n',level=1):
    """
    vulnerability print with timestamp and colors
    level 1 : blue
    level 2 : yellow
    level 3 : red 
    """

    print(start,end='')
    print(get_header(f"VULN{level}") + " ".join(map(str, args)), end='')
    print(end,end='')

def warn(*args,start='',end='\n'):
    """
    toolbox print with timestamp and colors
    """
    print(start,end='')
    print(get_header("WARNING")+" ".join(map(str, args)),end='')
    print(end,end='')

def isint(v):
    try:     
        i = int(v)
    except:  
        return False
    return True

def dict_filter_duplicates(dicts:list,filter:str)->list:
    seen_values = set()
    unique_dicts = []
    for d in dicts:
        if d[filter] not in seen_values:
            unique_dicts.append(d)
            seen_values.add(d[filter])
    return unique_dicts