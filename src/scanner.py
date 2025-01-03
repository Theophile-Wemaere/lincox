from src import toolbox
from src import webutils as wu
from src import networkutils as nu
from src import vulntest as vt
from src import reporting
import re
import os
import time
from datetime import datetime
from alive_progress import alive_bar
import json

class Target:

    def __init__(self,target: str, attack_mode:bool, force_scan: bool, scope: str):
        self.start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.target = target
        self.attack_mode = attack_mode
        self.force_scan = force_scan
        self.scope = scope
        self.ports_list = [80,443,8000,8080,8081,8443]
        self.ports_args = ",".join(list(map(str,self.ports_list)))
        self.override_port = False
        self.found_data = []
        self.found_headers = []
        self.forms_list = []
        self.url_parameters = []
        self.found_xss = []
        self.found_fi = []
        self.found_sqli = []
        self.found_openredirect = []
        self.found_ssrf = []
        self.found_broken_auth = []
        self.found_misconf = []

    def initialize(self):
        """
        setup target for scans
        check target validity
        """
        
        toolbox.tprint("Checking target validity...")

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
                toolbox.tprint(f"{self.address} seems to be down")
                toolbox.tprint("Continuing scan as force flag is set")
            else:
                toolbox.exit_error(f"{self.address} is down, use -f to scan anyway",0)

        toolbox.tprint(f"Target is valid, launching discovery on {self.address}")

    def set_ports_list(self,ports:str):
        """
        change the list of ports to scan
        Formats accepted :
        - 192
        - start-end
        - 1,2,3,4
        - -/all
        """

        self.ports_args = ports

        ports_list = []
        if ports == '-' or ports == 'all':
            ports_list = [i for i in range(1,65536)]
        
        else:
            for port in ports.split(','):
                if port.find('-') != -1:
                    start,end = port.split('-')
                    if toolbox.isint(start) and toolbox.isint(end):
                        for i in range(int(start),int(end)+1):
                            ports_list.append(i)

                elif toolbox.isint(port):
                    ports_list.append(int(port))

        if len(ports_list) == 0:
            toolbox.debug("No ports specified, keeping default port list")
        else:
            self.ports_list = ports_list
            toolbox.debug(f"Updated list of ports to scans ({len(self.ports_list)} ports)")

        return ports_list

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
            "http",
            "https"
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
            port_regex = r":([0-9]{1,5})"
            match = re.search(port_regex,rest)
            if match:
                self.port = re.search(port_regex,self.target).group(1)
                toolbox.debug(f"Found port in target : {self.port}")

    def search_services(self):
        """
        search for services on the target
        need to be run after initialize() function
        """

        to_scan = self.ports_list

        if hasattr(self,'port'):
            to_scan += [int(self.port)]

        if self.scope == "strict":
            if hasattr(self,'port'):
                to_scan = [self.port]
                self.ports_args = str(self.port)
            elif hasattr(self,'protocol'):
                if self.protocol.find("https") != -1:
                    to_scan = [443]
                    self.ports_args = "443"
                elif self.protocol.find("http") != -1:
                    to_scan = [80]
                    self.ports_args = "80"
            else:
                to_scan = [80,443]
                self.ports_args = "80,443"

        elif self.scope == "full" and not self.override_port:
            to_scan = self.set_ports_list("all")

        self.ports = nu.PortScanner(self.address).run(to_scan)
        
        if len(self.ports) == 0 and not self.force_scan:
            toolbox.exit_error(f"No open ports found on {self.address}, use -p to specify port(s) to scan or -f to force scan",0)
        
        if len(self.ports) > 0:
            toolbox.tprint(f"Open ports found on {self.address} : {",".join([str(port) for port in self.ports])}")
        
        toolbox.tprint("Enumerating services with nmap (can take a few minutes)...")
        
        if len(self.ports) == 0 and self.force_scan:
            self.ports = to_scan

        self.services = nu.nmap_scan(self.address,",".join([str(port) for port in self.ports]))
        f = False
        for service in self.services:
            if self.services[service]["name"].find("http") != -1:
                f = True
        if not f:
            toolbox.exit_error(f"No WEB services found on {self.address}, exiting",0)

    def enumerate_web_services(self):
        """
        crawl and fuzz on webservice discovered
        must be run after search_service() function
        """

        self.crawled_urls = []
        self.fuzzed_urls = []
        visited_urls = []
        wordlist = "data/wordlist.txt"

        toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...")
        time.sleep(5)

        for service in self.services:
            # print("trying",self.services[service])
            data = self.services[service]
            if data["name"].find("http") != -1:
                protocol = "http"
                if hasattr(self,'protocol'):
                    protocol = self.protocol

                url = f"{protocol}://{self.address}:{service}"

                if service == 80:
                    url = f"http://{self.address}"

                if service == 443 or data["name"].find("https") != -1:
                    url = f"https://{self.address}"


                toolbox.tprint(f"Crawling from {url}")
                crawled_urls, found_headers, found_data, forms_list = wu.Crawler(url=[url],visited_urls=visited_urls).run()
                for url,code in crawled_urls:
                    self.crawled_urls.append((url,code))
                    visited_urls.append(url)

                for fh in found_headers:
                    if fh not in self.found_headers:
                        self.found_headers.append(fh)

                for fd in found_data:
                    if fd not in self.found_data:
                        self.found_data.append(fd)

                for fl in forms_list:
                    if fl not in self.forms_list:
                        self.forms_list.append(fl)

        self.crawled_urls = list(set(self.crawled_urls))
        self.found_data = toolbox.dict_filter_duplicates(self.found_data,"line")

        toolbox.tprint(f"Found {len(self.crawled_urls)} URL(s) on {self.target} via crawling")

        to_pop = []
        for i in range(len(self.forms_list)):
            form = self.forms_list[i]
            if len(form['parameters']) == 0:
                toolbox.tprint(f"Trying to get more info on form at {form['url']}, please wait")
                to_pop += [i]
                # try to get more info using selenium (in case form is generated on client side with JS)
                forms = wu.get_form_w_selenium(form['url'])
                for form in forms:
                    if form not in self.forms_list:
                        self.forms_list.append(form)

        shift = 0
        for i in to_pop:
            self.forms_list.pop(i-shift)
            shift += 1

        toolbox.tprint(f"Found {len(self.found_headers)} interesting headers, {len(self.found_data)} interesting data and {len(self.forms_list)} forms")

        toolbox.tprint(f"Running Fuzzer on {self.target}")
        for service in self.services:
            data = self.services[service]
            if data["name"].find("http") != -1:
                protocol = "http"
                if hasattr(self,'protocol'):
                    protocol = self.protocol

                url = f"{protocol}://{self.address}:{service}"

                if service == 80:
                    url = f"http://{self.address}"
                elif service == 443:
                    url = f"https://{self.address}"
                
                self.fuzzed_urls += wu.Fuzzer(url,wordlist).run()

        toolbox.tprint(f"Found {len(self.fuzzed_urls)} URL(s) on {self.target} via fuzzing")
        self.all_urls = []
        for url,code in self.crawled_urls:
            self.all_urls.append((url,code,"Crawler"))
        for url,code in self.fuzzed_urls:
            self.all_urls.append((url,code,"Fuzzer"))

    def enumerate_subdomains(self):
        """
        enumerate subdomains
        for now only use ctr.sh
        """

        if self.type != "domain" or self.address == "localhost":
            toolbox.tprint(f"Given target {self.address} is not a domain, skipping...")
        else:
            domains = wu.get_crt_domains(self.address)
            if len(domains) == 0:
                toolbox.tprint(f"No domains found with crt.sh for {self.address}")
                return
            else:
                toolbox.tprint(f"Found {len(domains)} domains with crt.sh")
            self.domains = []
            alives = 0
            with alive_bar(len(domains),title=toolbox.get_header("INFO")+f"Checking domains status", enrich_print=False) as bar:
                for domain in domains:
                    alive = nu.ping_target(domain)
                    if alive:
                        self.domains.append((domain,"alive"))
                        alives += 1
                    else:
                        self.domains.append((domain,"down"))
                    bar()

            toolbox.tprint(f"Found {len(domains)} domains with {alives} alives, saving to {self.address}_subdomains.txt")
            # with open(f"{self.address}_subdomains.txt","w") as file:
            #     for domain in alives:
            #         file.write(domain+"\n")
       
    def search_parameters(self):
        """
        try to bruteforce for common POST and GET parameters on web root
        """

        toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...")
        time.sleep(5)

        wordlist = "data/burp-parameter-names.txt"
        self.url_parameters = []

        for service in self.services:
            data = self.services[service]
            if data["name"].find("http") != -1:
                protocol = "http"
                if hasattr(self,'protocol'):
                    protocol = self.protocol

                url = f"{protocol}://{self.address}:{service}"

                if service == 80:
                    url = f"http://{self.address}"
                elif service == 443:
                    url = f"https://{self.address}"

                results = wu.ParaMiner(url,wordlist).run()
                for result in results:
                    if result not in self.url_parameters:
                        self.url_parameters.append(result)

        for url in self.all_urls:
            if url[0].find('?') != -1:
                parameters = url[0][url[0].find('?')+1:].split('&')
                for parameter in parameters:
                    parameter = parameter.split('=')[0].split('#')[0] # remove fragment if found
                    data = [url[0].split('?')[0],parameter,'200','0','GET','']
                    if data not in self.url_parameters:
                        self.url_parameters.append(data)

        for form in self.forms_list:
            if form["method"] == "get":
                for param in form["parameters"]:
                    data = [form["url"].split('#')[0].split('?')[0],param["name"],'200','0','GET',param["type"]]
                    if data not in self.url_parameters:
                        self.url_parameters.append(data)

        toolbox.tprint(f"Got {len([x for x in self.url_parameters if x[-1] == "GET"])} get parameter to test")
        toolbox.tprint(f"Got {len([x for x in self.forms_list if x["method"].lower() == "get"])} get forms to test")

    def search_xss(self):
        """
        search for reflected XSS in GET parameters
        """

        if len(self.url_parameters) == 0:
            toolbox.tprint("No GET parameters found on target, skipping RXSS detection")
            return

        toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...")
        time.sleep(5)

        with alive_bar(len(self.url_parameters), title=toolbox.get_header("ATTACK")+f"Testing XSS on {len(self.url_parameters)} parameters", enrich_print=False) as bar:
            for param in self.url_parameters:
                result = vt.test_reflection(param[0],param[1],"GET",param[5])
                if result:
                    # todo : test multiples payload depending on reflection context
                    toolbox.vprint(f"Possible RXSS on {param[0]}/?{param[1]}=here",level=2,end='')
                    self.found_xss.append((param[0],param[1],"GET","reflected XSS"))
                else:
                    result = vt.test_dom_reflection(param[0],param[1],param[5])
                    if result:
                        toolbox.vprint(f"Possible DOM XSS on {param[0]}/?{param[1]}=here",level=2,end='')
                        self.found_xss.append((param[0],param[1],"GET","DOM XSS"))
                bar()

    def search_lfi(self):
        """
        search for LFI and maybe RFI in the futur
        for now, only Linux based system (marker is /etc/passwd)
        """

        if len(self.url_parameters) == 0 and len(self.forms_list) == 0:
            toolbox.tprint("No parameters found on target, skipping LFI/RFI detection")
            return

        # toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...")
        # time.sleep(5)

        to_test = []
        for form in self.forms_list:
            if len(form['parameters']) > 0:
                body = {}
                for param in form['parameters'] :
                    body[param['name']] = param['value']
                to_test.append((form['url'],[entry for entry in body],form['method'].lower()))

        for param in self.url_parameters:
            url, parameter = param[0], param[1]
            data = (url,[parameter],"get")
            if data not in to_test:
                to_test.append(data)

        with alive_bar(len(to_test), title=toolbox.get_header("ATTACK")+f"Testing LFI on found forms and parameters", enrich_print=False) as bar:
            for url,parameters,method in to_test:
                    # toolbox.debug(f"Testing {url} with method {method}")
                    result = vt.test_lfi_linux(url,parameters,method)
                    if result:
                        toolbox.vprint(f"LFI detected on {url}{result}",level=3,end='')
                    # print(json.dumps(body,indent=1))
                    # print(json.dumps(form,indent=1))
                    bar()

    def create_report(self):
        """
        create a report of the scan results
        """

        self.end = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        html = reporting.html_report(self)

        with open("index.html","w") as report:
            report.write(html)