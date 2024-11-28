import argparse
from src import toolbox
from src import scanner
import pickle

def main():
    """
    check user parameters
    """

    SHOW_HELP = True

    parser = argparse.ArgumentParser(description='lincox, the python security scanner for web applications (and more)')

    parser.add_argument("-t","--target", nargs='?', dest="target" ,const='target', help="Target to scan (IP or domain name)")
    parser.add_argument("-f","--force", action="store_true" ,dest="force", help="Force enumeration if target is down")
    parser.add_argument("-sd","--subdomains", action="store_true" ,dest="subdomain", help="Perform subdomain enumeration")

    # debug options
    parser.add_argument("-d", action="store_true" ,dest="debug", help="Debug mode")
    parser.add_argument("-l", action="store_true", dest="load" , help="load pickle target")
    # -f force scan without ping
    # -p coma separated list of ports

    args = parser.parse_args()

    if args.debug:
        toolbox.set_debug(True)

    toolbox.print_banner()

    if args.target:
        SHOW_HELP = False

        force = False
        if args.force:
            force = True

        target = scanner.Target(args.target,force)
        if not args.load:
            target.initialize()
            target.search_services()
            with open("target.pkl",'wb') as file:
                pickle.dump(target,file)
        else:
            with open("target.pkl",'rb') as file:
                target = pickle.load(file)
        # TODO : optional add other services enumeration, CPE fetching and CVE fetching with online API

        if args.subdomain:
            target.enumerate_subdomains()
        target.enumerate_web_services()

    if SHOW_HELP:
        parser.print_help()



if __name__ == "__main__":
    print()
    try:
        main()
    except KeyboardInterrupt:
        print("Ctrl+C pressed, exiting...")
        exit(1)
    finally:
        print()