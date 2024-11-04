import argparse
from src import toolbox
from src import scanner

def main():
    """
    check user parameters
    """

    SHOW_HELP = True

    parser = argparse.ArgumentParser(description='lincox, the python security scanner for web applications (and more)')
    parser.add_argument("-d", action="store_true" ,dest="debug", help="Debug mode")
    parser.add_argument("-t", nargs='?', dest="target" ,const='target', help="Target to scan (IP or domain name)")

    args = parser.parse_args()

    if args.debug:
        toolbox.set_debug(True)

    toolbox.print_banner()

    if args.target:
        SHOW_HELP = False

        target = scanner.Target(args.target)
        target.initialize()

    if SHOW_HELP:
        parser.print_help()



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Ctrl+C pressed, exiting...")
        exit(1)
        # check if valid ip / domain