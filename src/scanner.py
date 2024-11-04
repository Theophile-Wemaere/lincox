from src import toolbox
from src import webutils
import re
import os
import ping3
import shlex

class Target:

    def __init__(self,target: str):
        self.target = target

    def initialize(self):
        """
        setup target for scans
        check target validity
        """
        
        # check if target string is a valid target to scan
        self.__check_target_validity()
        toolbox.debug(f"Type of target : {self.type} -> {self.address}")

        # check if a protocal and/or a port has been specified
        self.__check_target_protocol()
        
        # check if target is alive
        self.__ping_target()

        

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
            print(rest,re.match(port_regex,rest))
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