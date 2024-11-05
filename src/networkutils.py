from src import toolbox
import socket
import ping3
import threading

def ping_target(address: str)-> bool:
    """
    check if target is alive
    """

    if address == None:
        toolbox.exit_error("Error, trying to ping but no address specified",1)
    
    response = ping3.ping(address)
    if response:
        return True
    return False

def scan_ports(address:str, ports:list)-> list:
    """
    scan for open ports
    ports in an array of int
    return the array of port open
    """

    open_ports = []

    if len(ports) == 0:
        toolbox.debug("Warning, no ports to scan specified")
        return None

    def TCP_connect(ip, port):

        delay = 3 # 3 sec timeout
        TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        TCPsock.settimeout(delay)
        try:
            TCPsock.connect((ip, port))
            toolbox.debug(f"Port {port} open")
            open_ports.append(port)
        except:
            toolbox.debug(f"Port {port} not open")

    threads = []

    for port in ports: 
        t = threading.Thread(target=TCP_connect, args=(address, port))
        threads.append(t)

    # Starting threads
    for i in range(len(ports)):
        threads[i].start()

    # Locking the main thread until all threads complete
    for i in range(len(ports)):
        threads[i].join()

    return open_ports

    