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
    if not DEBUG:
        print(banner)

def exit_error(msg,code):
    """
    print error message and exit
    """

    print(msg)
    exit(code)

def debug(msg):
    """
    print debug message
    """

    if DEBUG:
        print("[DEBUG]",msg)