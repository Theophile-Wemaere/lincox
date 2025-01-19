from termcolor import colored
from datetime import datetime
import lincox as main
import os

DEBUG = False
FILENAME = None

def set_debug(status):

    global DEBUG
    DEBUG = status
    print(colored("DEBUG = True","black","on_red",attrs=["bold"]))

def log_to_dir(directory,filename):

    global FILENAME
    timestamp = datetime.now().strftime('_%Y-%m-%d_%H_%M')
    FILENAME = os.path.join(directory,filename+f'{timestamp}.lincox')
    print(colored(f"Logging script output to {FILENAME}","black","on_green",attrs=["bold"]))

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

    if FILENAME:
        with open(FILENAME,"a") as file:
            file.write(get_header("ERROR")+msg+'\n')

    exit(code)

def get_header(header_type:str,show_timestamp=True,uncolored=False)->str:
    """
    get timestamp and type header
    """

    timestamp_header = ''
    header = None
    if show_timestamp:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        timestamp_header = '[' + colored(timestamp,"blue") + '] '
        if uncolored:
            timestamp_header = '[' + timestamp + '] '

    if header_type == "DEBUG":
        header = timestamp_header +  '['+colored("DEBUG",attrs=["bold"])+'] '

    if header_type == "INFO":
        header = timestamp_header + '['+colored("INFO","green")+'] '

    if header_type == "ATTACK":
        header = timestamp_header + '['+colored("ATTACK","light_red",attrs=["bold"])+'] '

    if header_type == "WARNING":
        header = timestamp_header + '['+colored("WARNING","black","on_light_yellow")+'] '

    if header_type == "ERROR":
        header = timestamp_header + '['+colored("ERROR","yellow","on_red")+'] '

    if header_type == "VULN1":
        header = timestamp_header + '['+colored("LOW","black","on_blue",attrs=["bold"])+'] '
    if header_type == "VULN2":
        header = timestamp_header + '['+colored("MEDIUM","black","on_yellow",attrs=["bold"])+'] '
    if header_type == "VULN3":
        header = timestamp_header + '['+colored("HIGH","black","on_light_red",attrs=["bold"])+'] '

    return header

def debug(msg):
    """
    print debug message
    """

    if not DEBUG:
        return

    print(get_header("DEBUG")+msg)
    
    if FILENAME:
        with open(FILENAME,"a") as file:
            file.write(get_header("DEBUG")+msg+'\n')

def tprint(*args,start='',end='\n'):
    """
    toolbox print with timestamp and colors
    """
    print(start,end='')
    print(get_header("INFO")+" ".join(map(str, args)),end='')
    print(end,end='')

    if FILENAME and end != '\r':
        with open(FILENAME,"a") as file:
            file.write(get_header("INFO")+" ".join(map(str, args))+end)

def vprint(*args,start='',end='\n',level=1):
    """
    vulnerability print with timestamp and colors
    level 1 : blue
    level 2 : yellow
    level 3 : red 
    """

    print(start,end='')
    print(get_header(f"ATTACK") + get_header(f"VULN{level}",show_timestamp=False) + " ".join(map(str, args)), end='')
    print(end,end='')

    if FILENAME and end != '\r':
        with open(FILENAME,"a") as file:
            file.write(get_header(f"ATTACK") + get_header(f"VULN{level}",show_timestamp=False) + " ".join(map(str, args)) + end)

def warn(*args,start='',end='\n'):
    """
    toolbox print with timestamp and colors
    """
    print(start,end='')
    print(get_header("WARNING")+" ".join(map(str, args)),end='')
    print(end,end='')

    if FILENAME and end != '\r':
        with open(FILENAME,"a") as file:
            file.write(get_header("WARNING")+" ".join(map(str, args))+end)

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

# for debugging

def log_request(r):
    with open("output.html","w") as file:
        file.write(f"HTTP/2 {r.status_code}\n")
        for entry,value in r.headers.items():
            file.write(f"{entry}: {value}\n")
        file.write(r.text)