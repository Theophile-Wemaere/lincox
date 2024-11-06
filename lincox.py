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
    parser.add_argument("-d", action="store_true" ,dest="debug", help="Debug mode")
    parser.add_argument("-t", nargs='?', dest="target" ,const='target', help="Target to scan (IP or domain name)")
    parser.add_argument("-l", action="store_true", dest="load" , help="load pickle target")
    # -f force scan without ping
    # -p coma separated list of ports

    args = parser.parse_args()

    if args.debug:
        toolbox.set_debug(True)

    toolbox.print_banner()

    if args.target:
        SHOW_HELP = False

        target = scanner.Target(args.target)
        if not args.load:
            target.initialize()
            target.search_services()
            with open("target.pkl",'wb') as file:
                pickle.dump(target,file)
        else:
            with open("target.pkl",'rb') as file:
                target = pickle.load(file)
        # TODO : optional add other services enumeration, CPE fetching and CVE fetching with online API
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
        # check if valid ip / domain
    finally:
        print()