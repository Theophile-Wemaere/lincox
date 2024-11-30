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

        By Theophile.W, Quentin.L, Maximilien.L and Maxime.V
        
"""
    print(banner)

def exit_error(msg,code):
    """
    print error message and exit
    """

    print(msg)
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


def debug(msg):
    """
    print debug message
    """

    if not DEBUG:
        return

    print(get_header("DEBUG")+msg)

def tprint(*args,end='\n'):
    """
    toolbox print with timestamp and colors
    """
    print(get_header("INFO")+" ".join(map(str, args)),end='')
    print(end,end='')

def isint(v):
    try:     
        i = int(v)
    except:  
        return False
    return True