#!/bin/env python3

import argparse
from argparse import RawTextHelpFormatter
from src import toolbox
from src import scanner
import pickle
import os

if not os.path.exists("tools/"):
    os.mkdir("tools")

def main():
    """
    check user parameters
    """

    SHOW_HELP = True

    parser = argparse.ArgumentParser(description='lincox, the python security scanner for web applications (and more)',formatter_class=RawTextHelpFormatter)

    # scanning options
    parser.add_argument("-t","--target", nargs='?', dest="target" ,const='target', help="Target to scan (IP or domain name)")

    parser.add_argument("-m","--mode", nargs='?', dest="mode" , const='mode', help="""Scanner mode : 
enum : only conduct enumeration of services
full : default value, conduct enumeration and attack on target""")

    parser.add_argument("-sc","--scope", nargs='?', dest="scope" ,const='scope', help="""Scope of the scanner : 
strict : only scan the given target, (no ports and subdomains enumeration)
medium : default value, scan target for differents services on most used ports
full : scan for subdomains and others services on found subdomains""")

    parser.add_argument("--attacks", nargs='?', dest="attacks_flag" ,const='XLSOBR', help="""attacks to perform : 
X : XSS
L : LFI
S : SQL injection
O : open-redirect
B : brute-force
R : SSRF
Default to 'XLSOBR' if this parameter is not used""")

    parser.add_argument("-p","--ports", nargs='?', dest="ports" ,const='ports', help="""List of port to scan
Use CSV (80,8080,8443) or range (10-1000)
Default : 80,443,8000,8080,8081,8443\n """)

    parser.add_argument("-f","--force", action="store_true" ,dest="force", help="Force enumeration if target seems down (no pingback)")
    parser.add_argument("-sd","--subdomains", action="store_true" ,dest="subdomains", help="Perform subdomain enumeration")

    # debug options
    parser.add_argument("-d","-v","--verbose","--debug", action="store_true" ,dest="debug", help="Debug/Verbose mode")
    parser.add_argument("-q","--quiet", action="store_true" ,dest="quiet", help="Hide banner")
    parser.add_argument("-l", action="store_true", dest="load" , help="load pickle target")

    args = parser.parse_args()

    ATTACK_MODE = True
    SUBDOMAINS_ENUM = False
    SCOPE = "medium"
    FORCE = False
    FLAGS = 'XLSOBR'

    if args.mode:
        if args.mode.lower() == "enum":
            ATTACK_MODE = False

    if args.scope:
        if args.scope.lower() == "strict" or args.scope.lower() == "full":
            SCOPE = args.scope.lower()

    if args.subdomains or SCOPE == "full":
        SUBDOMAINS_ENUM = True

    if args.force:
            FORCE = True

    if ATTACK_MODE and args.attacks_flag:
        FLAGS = ''
        for c in args.attacks_flag:
            if c.upper() in 'XLSOBR':
                FLAGS += c.upper()

    if args.debug:
        toolbox.set_debug(True)

    if not args.quiet:
        toolbox.print_banner()

    if args.target:
        SHOW_HELP = False

        target = scanner.Target(args.target,ATTACK_MODE,FORCE,SCOPE)

        if args.ports:
            if args.ports != "ports":
                target.set_ports_list(args.ports)
                target.override_port = True

        if not args.load:
            target.initialize()

            if SUBDOMAINS_ENUM:
                target.enumerate_subdomains()
                target.create_report()
                exit(0)

            target.search_services()

            target.enumerate_web_services()

            target.search_parameters()

            with open("target.pkl",'wb') as file:
                pickle.dump(target,file)
        else:
            with open("target.pkl",'rb') as file:
                target = pickle.load(file)

        # TODO : optional add other services enumeration, CPE fetching and CVE fetching with online API
        
        if not ATTACK_MODE:
            target.create_report()
            exit(0)
        
        target.create_report()

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
            # # search default creds / small bruteforce if login detected
            target.auth_attack()

        # # search SSRF (ngrok integration ?)
        # target.search_ssrf()

        # # search misconfigurations : headers, rate limiting, versions... (optional)
        # target.search_misconfiguration()

        # # WPscan integration ?
        # target.wp_scan()

        target.create_report()

        with open("target.pkl",'wb') as file:
            pickle.dump(target,file)
        

    if SHOW_HELP:
        parser.print_help()
        # TODO : custom help menu



if __name__ == "__main__":
    print()
    try:
        main()
    except KeyboardInterrupt:
        toolbox.exit_error("Ctrl+C pressed, exiting...",1)
    finally:
        print()