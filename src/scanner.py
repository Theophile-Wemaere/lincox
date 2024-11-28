from src import toolbox
from src import webutils as wu
from src import networkutils as nu
import re
import os

COMMON_PORTS = [80,443,8000,8080,8081,8443]

class Target:

    def __init__(self,target: str, force_scan: bool):
        self.target = target
        self.force_scan = force_scan

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
        alive = nu.ping_target(self.address)
        if alive:
            toolbox.debug(f"{self.address} is up!")
        else:
            toolbox.debug(f"{self.address} is down!")
            if self.force_scan:
                print(f"{self.address} is down\nContinuing scan as force flag is set")
            else:
                toolbox.exit_error(f"{self.address} is down, use -f to scan anyway",0)

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

    def search_services(self):
        """
        search for services on the target
        need to be run after initialize() function
        """

        to_scan = COMMON_PORTS

        if hasattr(self,'port'):
            to_scan += int(self.port)

        self.ports = nu.scan_ports(self.address,to_scan)
        
        if len(self.ports) == 0:
            toolbox.exit_error(f"No open ports found on {self.address}, use -p to specify port(s) to scan",0)

        print(f"Open ports found on {self.address} : {",".join([str(port) for port in self.ports])}")
        print("Enumerating services...")
        self.services = nu.nmap_scan(self.address,",".join([str(port) for port in self.ports]))
        f = False
        for service in self.services:
            if self.services[service]["name"] == "http":
                f = True
        if not f:
            toolbox.exit_error(f"No WEB services found on {self.address}, exiting",0)

    def enumerate_web_services(self):
        """
        crawl and fuzz on webservice discovered
        must be run after search_service() function
        """

        visited_urls = []
        fuzzed_urls = []
        wordlist = "data/wordlist.txt"

        print(f"Running Crawler on {self.target}")
        for service in self.services:
            data = self.services[service]
            if data["name"] == "http":
                protocol = "http"
                if hasattr(self,'protocol'):
                    protocol = self.protocol

                url = f"{protocol}://{self.address}:{service}"

                if str(service).find("80") != -1:
                    url = f"http://{self.address}"

                if str(service).find("443") != -1:
                    url = f"https://{self.address}"

                visited_urls += [url]
                visited_urls += wu.Crawler(urls=visited_urls).run()

        print(f"Running Fuzzer on {self.target}")
        for service in self.services:
            data = self.services[service]
            if data["name"] == "http":
                protocol = "http"
                if hasattr(self,'protocol'):
                    protocol = self.protocol

                url = f"{protocol}://{self.address}:{service}"

                if service == 80:
                    url = f"http://{self.address}"
                elif service == 443:
                    url = f"https://{self.address}"

                fuzzed_urls += wu.Fuzzer(url,wordlist).run()

    def enumerate_subdomains(self):
        """
        enumerate subdomains
        for now only use ctr.sh
        """

        if self.type != "domain":
            print(f"Given target {self.address} is not a domain, skipping...")
        else:
            domains = wu.get_crt_domains(self.address)
            if len(domains) == 0:
                print(f"No domains found with crt.sh for {self.address}")
                return
            alives = []
            for domain in domains:
                alive = nu.ping_target(domain)
                if alive:
                    alives.append(domain)

            print(f"Found {len(alives)} domains alive, saving to {self.address}_subdomains.txt")
            with open(f"{self.address}_subdomains.txt","w") as file:
                for domain in alives:
                    file.write(domain+"\n")