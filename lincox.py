#!/bin/env python3

import argparse
from argparse import RawTextHelpFormatter
from src import toolbox
from src import scanner
from src import webutils
from src import server
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

    parser.add_argument("--attacks", nargs='?', dest="attacks_flag" ,const='XLSOBRM', help="""attacks to perform : 
X : XSS
L : LFI
S : SQL injection
O : open-redirect
B : brute-force
R : SSRF
M : misconfiguration (CSRF, headers)
Default to 'XLSOBRM' if this parameter is not used""")

    parser.add_argument("-p","--ports", nargs='?', dest="ports" ,const='ports', help="""List of port to scan
Use CSV (80,8080,8443) or range (10-1000)
Default : 80,443,8000,8080,8081,8443\n """)

    parser.add_argument("-f","--force", action="store_true" ,dest="force", help="Force enumeration if target seems down (no pingback)")
    parser.add_argument("-sd","--subdomains", action="store_true" ,dest="subdomains", help="Perform subdomain enumeration")
    parser.add_argument("-H", "--headers", dest="headers", action="append", help="Specify a header to be included. Can be used multiple times.")
    parser.add_argument("--skip-paraminer", action="store_true", dest="skip_paraminer" , help="Skip parameter bruteforcing")

    # GUI options
    parser.add_argument("-g","--gui", nargs='?', dest="use_gui" ,const='5000', help="Can be used alone. Run GUI on given port, default to 5000")

    # output options
    parser.add_argument("-oN", nargs='?', dest="normal_output" ,const='', help="Output script to given directory")
    parser.add_argument("-oC", nargs='?', dest="csv_output" ,const='', help="Output script in CSV (only found URL) to given directory")
    parser.add_argument("-oJ", nargs='?', dest="json_output" ,const='', help="Output script in JSON to given directory")
    parser.add_argument("-oA", nargs='?', dest="all_output" ,const='', help="Output script to normal,CSV and JSON in given directory")

    # debug options
    parser.add_argument("-d","-v","--verbose","--debug", action="store_true" ,dest="debug", help="Debug/Verbose mode")
    parser.add_argument("-q","--quiet", action="store_true" ,dest="quiet", help="Hide banner")
    parser.add_argument("-l", action="store_true", dest="load" , help="load pickle target")

    args = parser.parse_args()

    ATTACK_MODE = True
    SUBDOMAINS_ENUM = False
    SCOPE = "medium"
    FORCE = False
    FLAGS = 'XLSOBRM'

    # select scanning mode
    if args.mode:
        if args.mode.lower() == "enum":
            ATTACK_MODE = False

    # select scope
    if args.scope:
        if args.scope.lower() == "strict" or args.scope.lower() == "full":
            SCOPE = args.scope.lower()

    # select subdomain enumeration
    if args.subdomains or SCOPE == "full":
        SUBDOMAINS_ENUM = True

    # set force scan mode
    if args.force:
            FORCE = True

    # set attacks to perform
    if ATTACK_MODE and args.attacks_flag:
        FLAGS = ''
        for c in args.attacks_flag:
            if c.upper() in 'XLSOBRM':
                FLAGS += c.upper()

    # set custom headers:
    if args.headers:
        for header in args.headers:
            index = header.find(':')
            name,value = header[:index], header[index+1:]
            while value.startswith(' '):
                value = value[1:]
            webutils.HEADERS[name] = value

    # prepare file output
    normal_output = False
    csv_output = False
    json_output = False
    normal_dir = ""
    csv_dir = ""
    json_dir = ""

    if args.normal_output:
        normal_output = True
        normal_dir = args.normal_output
    if args.csv_output:
        csv_output = True
        csv_dir = args.csv_output
    if args.json_output:
        json_output = True
        json_dir = args.json_output

    if args.all_output:
        normal_output = True
        normal_dir = args.all_output
        csv_output = True
        csv_dir = args.all_output
        json_output = True
        json_dir = args.all_output

    if normal_output and (not os.path.exists(normal_dir) or not os.path.isdir(normal_dir)):
        print(f"Error, {normal_dir} doesn't exist or is not a directory")
        exit(1)
    if csv_output and (not os.path.exists(csv_dir) or not os.path.isdir(csv_dir)):
        print(f"Error, {csv_dir} doesn't exist or is not a directory")
        exit(1)
    if json_output and (not os.path.exists(json_dir) or not os.path.isdir(json_dir)):
        print(f"Error, {csv_dir} doesn't exist or is not a directory")
        exit(1)
    
    if args.debug:
        toolbox.set_debug(True)

    if not args.quiet:
        toolbox.print_banner()

    if args.use_gui:
        SHOW_HELP = False
        server.run(args.use_gui)
    
    elif args.target:
        SHOW_HELP = False

        if normal_output:
            toolbox.log_to_dir(normal_dir,args.target.replace(':','_').replace('/',''))


        target = scanner.Target(args.target,ATTACK_MODE,FORCE,SCOPE)

        if args.ports:
            if args.ports != "ports":
                target.set_ports_list(args.ports)
                target.override_port = True

        if not args.load:
            target.initialize()

            if SUBDOMAINS_ENUM:
                target.enumerate_subdomains()
                target.create_report(json_dir,csv_dir)
                if not SCOPE == "full":
                    exit(0)

            target.search_services()

            target.enumerate_web_services()

            skip = False
            if args.skip_paraminer:
                skip = True
            
            target.search_parameters(skip)

            with open("target.pkl",'wb') as file:
                pickle.dump(target,file)
        else:
            with open("target.pkl",'rb') as file:
                target = pickle.load(file)

        # TODO : optional add other services enumeration, CPE fetching and CVE fetching with online API
        
        if not ATTACK_MODE:
            target.attack_mode = False
            target.create_report(json_dir,csv_dir)
            exit(0)

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

        if 'W' in FLAGS:
            # WPscan integration ?
            pass
        # target.wp_scan()

        target.create_report(json_dir,csv_dir)

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