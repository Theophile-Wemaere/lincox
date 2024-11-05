from src import toolbox
from src import webutils
import socket
import threading
import re
import os
import ping3
import shlex

COMMON_PORTS = [80,443,8000,8080,8081,8443]

class Target:

    def __init__(self,target: str):
        self.target = target
        self.ports = []

    def initialize(self):
        """
        setup target for scans
        check target validity
        """
        
        print("Checking target validity...")

        # check if target string is a valid target to scan
        self.__check_target_validity()
        toolbox.debug(f"Type of target : {self.type} -> {self.address}")

        # check if a protocal and/or a port has been specified
        self.__check_target_protocol()
        
        # check if target is alive
        self.__ping_target()

        print(f"Target is valid, launching discovery on {self.address}")

        

    def __check_target_validity(self):
        """
        check if target is a valid IP or domain name
        return -1 if bad target
        return 1 if IP
        return 2 if domain
        """

        ip_regex = r"^(((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4})$"
        domain_regex = r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)"

        # try IPv4 
        if re.match(ip_regex,self.target):
            self.type = "ip"
            self.address = re.match(ip_regex,self.target).group(1)
        # else try domain name
        elif re.match(domain_regex,self.target):
            self.type = "domain"
            self.address = re.match(domain_regex,self.target).group(1) # isdomain
        else: # bad target
            toolbox.exit_error(f"Bad target : {self.target}. Use IP address or http://domain.tld type target",0)

    def __check_target_protocol(self):
        """
        check if target contain protocol
        return protocol and address if found
        else return False
        """

        # possibility of adding ssh://, ftp://, ...
        protocols = [
            "https",
            "http"
        ]

        found = False
        for protocol in protocols:
            if self.target.find(protocol) != -1:
                toolbox.debug(f"Found protocol : {protocol}")
                self.protocol = protocol
                found = True
        
        if not found:
            toolbox.debug(f"No protocol found : {self.target}")

        if self.target.find(f"{self.address}:") != -1:
            rest = self.target[self.target.find(self.protocol)+len(self.protocol)+3:] if hasattr(self,'protocol') else self.target
            port_regex = r":([0-9]{1,4})"
            if re.match(port_regex,rest):
                self.port = re.match(port_regex,self.target).group(1)
                toolbox.debug(f"Found port in target : {self.port}")

    def __ping_target(self):
        """
        check if target is alive
        """

        if self.target == None:
            toolbox.exit_error("Error, trying to ping but no address specified",1)
        
        response = ping3.ping(self.address)
        if response:
            toolbox.debug(f"{self.address} is up!")
        else:
            toolbox.debug(f"{self.address} is down!")
            toolbox.exit_error(f"{self.address} is down, use -f to scan anyway",0)

    def search_services(self):
        """
        search for services on the target
        need to be run after initialize() function
        """

        if hasattr(self,'port'):
            self.ports.append(int(self.port))

        from contextlib import closing

        for port in COMMON_PORTS:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(3)
                if sock.connect_ex((self.address, port)) == 0:
                    print(f"Port {port} is open")
                    self.ports.append(port)
                else:
                    print(f"Port {port} is not open")
            # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # result = sock.connect_ex((self.address,port))
            # if result == 0:
            #     self.ports.append(port)
            #     toolbox.debug(f"Port {port} is open on {self.adress}")
            # sock.close()

        
        if len(self.ports) == 0:
            toolbox.exit_error(f"No open ports found on {address}, use -p to specify port(s) to scan",0)

        toolbox.debug(f"Open ports found on {self.address} : {",".join(self.ports)}")

    def __scan_ports(self,ports:list):
        """
        scan for open ports
        ports in an array of int
        return the array of port open
        """
