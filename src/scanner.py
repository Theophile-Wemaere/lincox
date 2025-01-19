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
import shutil
import random
from termcolor import colored


class Target:

    def __init__(self, target: str, attack_mode: bool, force_scan: bool, scope: str):
        self.start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.target = target
        self.attack_mode = attack_mode
        self.force_scan = force_scan
        self.scope = scope
        self.ports_list = [80, 443, 8000, 8080, 8081, 8443]
        self.ports_args = ",".join(list(map(str, self.ports_list)))
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
        self.found_credentials = []
        self.found_misconf = []
        self.params_to_test = []
        self.services = []

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
                toolbox.exit_error(
                    f"{self.address} is down, use -f to scan anyway", 0)

        toolbox.tprint(
            f"Target is valid, launching discovery on {self.address}")

    def set_ports_list(self, ports: str):
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
            ports_list = [i for i in range(1, 65536)]

        else:
            for port in ports.split(','):
                if port.find('-') != -1:
                    start, end = port.split('-')
                    if toolbox.isint(start) and toolbox.isint(end):
                        for i in range(int(start), int(end)+1):
                            ports_list.append(i)

                elif toolbox.isint(port):
                    ports_list.append(int(port))

        if len(ports_list) == 0:
            toolbox.debug("No ports specified, keeping default port list")
        else:
            self.ports_list = ports_list
            toolbox.debug(f"Updated list of ports to scans ({
                          len(self.ports_list)} ports)")

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
        if re.match(ip_regex, self.target):
            self.type = "ip"
            self.address = re.match(ip_regex, self.target).group(1)
        # else try domain name
        elif re.match(domain_regex, self.target):
            self.type = "domain"
            self.address = re.match(
                domain_regex, self.target).group(1)  # isdomain
        else:  # bad target
            toolbox.exit_error(f"Bad target : {
                               self.target}. Use IP address or http://domain.tld type target", 0)

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
            rest = self.target[self.target.find(
                self.protocol)+len(self.protocol)+3:] if hasattr(self, 'protocol') else self.target
            port_regex = r":([0-9]{1,5})"
            match = re.search(port_regex, rest)
            if match:
                self.port = re.search(port_regex, self.target).group(1)
                toolbox.debug(f"Found port in target : {self.port}")

    def search_services(self):
        """
        search for services on the target
        need to be run after initialize() function
        """

        to_scan = self.ports_list

        if hasattr(self, 'port'):
            to_scan += [int(self.port)]

        if self.scope == "strict":
            if hasattr(self, 'port'):
                to_scan = [self.port]
                self.ports_args = str(self.port)
            elif hasattr(self, 'protocol'):
                if self.protocol.find("https") != -1:
                    to_scan = [443]
                    self.ports_args = "443"
                elif self.protocol.find("http") != -1:
                    to_scan = [80]
                    self.ports_args = "80"
            else:
                to_scan = [80, 443]
                self.ports_args = "80,443"

        elif self.scope == "full" and not self.override_port:
            to_scan = self.set_ports_list("all")

        self.ports = nu.PortScanner(self.address).run(to_scan)

        if len(self.ports) == 0 and not self.force_scan:
            toolbox.exit_error(f"No open ports found on {
                               self.address}, use -p to specify port(s) to scan or -f to force scan", 0)

        if len(self.ports) > 0:
            toolbox.tprint(f"Open ports found on {self.address} : {
                           ",".join([str(port) for port in self.ports])}")

        toolbox.tprint(
            "Enumerating services with nmap (can take a few minutes)...")

        if len(self.ports) == 0 and self.force_scan:
            self.ports = to_scan

        self.services = nu.nmap_scan(self.address, ",".join(
            [str(port) for port in self.ports]))
        f = False
        for service in self.services:
            if self.services[service]["name"].find("http") != -1:
                f = True
        if not f:
            toolbox.exit_error(f"No WEB services found on {
                               self.address}, exiting", 0)

    def enumerate_web_services(self):
        """
        crawl and fuzz on webservice discovered
        must be run after search_service() function
        """

        self.crawled_urls = []
        self.fuzzed_urls = []
        visited_urls = []
        wordlist = "data/wordlist.txt"

        toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...", end='\r')
        time.sleep(5)
        print(' '*72, end='\r')

        for service in self.services:
            # print("trying",self.services[service])
            data = self.services[service]
            if data["name"].find("http") != -1:
                protocol = "http"
                if hasattr(self, 'protocol'):
                    protocol = self.protocol

                url = f"{protocol}://{self.address}:{service}"

                if service == 80:
                    url = f"http://{self.address}"

                if service == 443 or data["name"].find("https") != -1:
                    url = f"https://{self.address}"

                toolbox.tprint(f"Crawling from {url}")
                crawled_urls, found_headers, found_data, forms_list = wu.Crawler(url=[url], visited_urls=visited_urls).run()
                for url, code in crawled_urls:
                    self.crawled_urls.append((url, code))
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
        self.found_data = toolbox.dict_filter_duplicates(self.found_data, "line")

        toolbox.tprint(f"Found {len(self.crawled_urls)} URL(s) on {self.target} via crawling")

        to_pop = []
        for i in range(len(self.forms_list)):
            form = self.forms_list[i]
            if len(form['parameters']) == 0:
                toolbox.tprint(f"Trying to get more info on form at {
                               form['url']}, please wait")
                to_pop += [i]
                #  try to get more info using selenium (in case form is generated on client side with JS)
                forms = wu.get_form_w_selenium(form['url'])
                for form in forms:
                    if form not in self.forms_list:
                        self.forms_list.append(form)

        #  filter duplicates
        existing_forms = []
        for i in range(len(self.forms_list)):
            form = self.forms_list[i]
            params = []
            for param in form['parameters']:
                params += [param['name']]

            id_form = form['url'].split('?')[0]+form['method']+",".join(params)
            if id_form not in existing_forms:
                existing_forms.append(id_form)
            else:
                to_pop += [i]

        to_pop = list(set(to_pop))

        shift = 0
        for i in to_pop:
            self.forms_list.pop(i-shift)
            shift += 1

        toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...", end='\r')
        time.sleep(5)
        print(' '*72, end='\r')

        toolbox.tprint(f"Running Fuzzer on {self.target}")
        for service in self.services:
            data = self.services[service]
            if data["name"].find("http") != -1:
                protocol = "http"
                if hasattr(self, 'protocol'):
                    protocol = self.protocol

                url = f"{protocol}://{self.address}:{service}"

                if service == 80:
                    url = f"http://{self.address}"
                elif service == 443:
                    url = f"https://{self.address}"

                fuzzed_urls, forms_list = wu.Fuzzer(url, wordlist).run()
                self.fuzzed_urls += fuzzed_urls
                for fl in forms_list:
                    if fl not in self.forms_list:
                        self.forms_list.append(fl)


        toolbox.tprint(f"Found {len(self.fuzzed_urls)} URL(s) on {
                       self.target} via fuzzing")
        self.all_urls = []
        for url, code in self.crawled_urls:
            self.all_urls.append((url, code, "Crawler"))
        for url, code in self.fuzzed_urls:
            self.all_urls.append((url, code, "Fuzzer"))

        toolbox.tprint(f"Found {len(self.found_headers)} interesting headers, {len(self.found_data)} interesting data and {len(self.forms_list)} forms")


    def enumerate_subdomains(self):
        """
        enumerate subdomains
        for now only use ctr.sh
        """

        if self.type != "domain" or self.address == "localhost":
            toolbox.tprint(f"Given target {
                           self.address} is not a domain, skipping...")
        else:
            domains = wu.get_crt_domains(self.address)
            if len(domains) == 0:
                toolbox.tprint(
                    f"No domains found with crt.sh for {self.address}")
                return
            else:
                toolbox.tprint(f"Found {len(domains)} domains with crt.sh")
            self.domains = []
            alives = 0
            with alive_bar(len(domains), title=toolbox.get_header("INFO")+f"Checking domains status", enrich_print=False) as bar:
                for domain in domains:
                    alive = nu.ping_target(domain)
                    if alive:
                        self.domains.append((domain, "alive"))
                        alives += 1
                    else:
                        self.domains.append((domain, "down"))
                    bar()

            toolbox.tprint(f"Found {len(domains)} domains with {
                           alives} alives, saving to {self.address}_subdomains.txt")
            # with open(f"{self.address}_subdomains.txt","w") as file:
            #     for domain in alives:
            #         file.write(domain+"\n")

    def search_parameters(self,skip_paraminer=False):
        """
        try to bruteforce for common POST and GET parameters on web root
        """

        toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...", end='\r')
        time.sleep(5)
        print(' '*72, end='\r')

        wordlist = "data/burp-parameter-names.txt"
        self.url_parameters = []

        if not skip_paraminer:
            for service in self.services:
                data = self.services[service]
                if data["name"].find("http") != -1:
                    protocol = "http"
                    if hasattr(self, 'protocol'):
                        protocol = self.protocol

                    url = f"{protocol}://{self.address}:{service}"

                    if service == 80:
                        url = f"http://{self.address}"
                    elif service == 443:
                        url = f"https://{self.address}"

                    results = wu.ParaMiner(url, wordlist).run()
                    for result in results:
                        if result not in self.url_parameters:
                            self.url_parameters.append(result)

        for url in self.all_urls:
            if url[0].find('?') != -1:
                parameters = url[0][url[0].find('?')+1:].split('&')
                for parameter in parameters:
                    parameter = parameter.split('=')[0].split(
                        '#')[0]  #  remove fragment if found
                    data = [url[0].split('?')[0], parameter,
                            '200', '0', 'GET', '', 'from_url']
                    if data not in self.url_parameters:
                        self.url_parameters.append(data)

        for form in self.forms_list:
            if form["method"] == "get":
                for param in form["parameters"]:
                    data = [form["url"].split('#')[0].split('?')[0], param["name"], '200', '0', 'GET', param["type"], "from_form"]
                    if data not in self.url_parameters:
                        self.url_parameters.append(data)

        # toolbox.tprint(f"Got {len([x for x in self.url_parameters if x[-1] == "GET"])} get parameter to test")
        # toolbox.tprint(f"Got {len([x for x in self.forms_list if x["method"].lower() == "get"])} get forms to test")

        for form in self.forms_list:
            if len(form['parameters']) > 0:
                body = {}
                for param in form['parameters']:
                    body[param['name']] = param['value']
                self.params_to_test.append((form['url'], [entry for entry in body], form['method'].lower()))
        
        for param in self.url_parameters:
            url, parameter, origin = param[0], param[1], param[6]
            data = (url, [parameter], "get")
            if data not in self.params_to_test and origin != "from_form":
                self.params_to_test.append(data)

    def search_xss(self):
        """
        search for reflected XSS in GET parameters
        """

        self.found_xss = []

        if len(self.url_parameters) == 0:
            toolbox.tprint(
                "No GET parameters found on target, skipping XSS detection")
            return

        toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...", end='\r')
        time.sleep(5)
        print(' '*72, end='\r')

        msgs = []
        with alive_bar(len(self.url_parameters), title=toolbox.get_header("ATTACK")+f"Testing XSS on {len(self.url_parameters)} parameters", enrich_print=False) as bar:
            for param in self.url_parameters:
                result = vt.test_reflection(
                    param[0], param[1], "GET", param[5])
                if result:
                    payload, confidence_level = result
                    msgs.append(f"Possible reflected XSS ({confidence_level} confidence) on {param[0]}?{param[1]}={payload}")
                    self.found_xss.append((param[0], param[1], "GET", "reflected XSS", confidence_level,payload))
                else:
                    result = vt.test_dom_reflection(
                        param[0], param[1], param[5])
                    if result:
                        payload, confidence_level = result
                        msgs.append(f"Possible DOM XSS ({confidence_level} confidence) on {param[0]}?{param[1]}={payload}")
                        self.found_xss.append((param[0], param[1], "GET", "DOM XSS", confidence_level,payload))
                bar()

        for msg in msgs:
            toolbox.vprint(msg, level=2)
        if len(msgs) == 0:
            toolbox.tprint("No XSS found")

    def search_lfi(self):
        """
        search for LFI and maybe RFI in the futur
        for now, only Linux based system (marker is /etc/passwd)
        """

        self.found_fi = []

        if len(self.params_to_test) == 0:
            toolbox.tprint(
                "No parameters found on target, skipping LFI detection")
            return

        toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...", end='\r')
        time.sleep(5)
        print(' '*72, end='\r')

        msgs = []
        with alive_bar(len(self.params_to_test), title=toolbox.get_header("ATTACK")+f"Testing LFI on found forms and parameters", enrich_print=False) as bar:
            for url, parameters, method in self.params_to_test:
                result = vt.test_lfi_linux(url, parameters, method)
                if result:
                    msgs.append(f"LFI detected on {method.upper()} {url} with parameter : {result}")
                    self.found_fi.append((url,method,result))
                bar()

        for msg in msgs:
            toolbox.vprint(msg, level=3)
        if len(msgs) == 0:
            toolbox.tprint("No LFI injection found")

    def search_sqli(self):
        """
        search for SQL injection inside found parameters
        use SQLMAP for maximum efficiency
        """

        self.found_sqli = []

        if len(self.params_to_test) == 0:
            toolbox.tprint(
                "No parameters found on target, skipping SQL injection detection")
            return

        toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...", end='\r')
        time.sleep(5)
        print(' '*72, end='\r')

        command = ""

        if shutil.which("sqlmap") is None:
            toolbox.tprint("SQLmap not found in PATH !")
            if not os.path.exists("tools/sqlmap"):
                if shutil.which("git") is not None:
                    toolbox.tprint("Cloning SQLmap repository, please wait")
                    os.system(
                        "git clone https://github.com/sqlmapproject/sqlmap tools/sqlmap")
                    command = ["python3", "tools/sqlmap/sqlmap.py"]
                else:
                    toolbox.warn(
                        "git command not found, cannot clone SQLmap locally")
                    toolbox.warn(
                        "Skipping SQL injections detection, please install git or SQLmap")
            else:
                command = ["python3", "tools/sqlmap/sqlmap.py"]
                toolbox.tprint("Using local tools/sqlmap repo")
        else:
            command = ["sqlmap"]

        msgs = []
        with alive_bar(len(self.params_to_test), title=toolbox.get_header("ATTACK")+f"Testing SQL injections on found forms and parameters", enrich_print=False) as bar:
            for url, parameters, method in self.params_to_test:
                results = vt.test_sqli(command, url, parameters, method)
                if results:
                    for result in results:
                        msgs.append(f"SQL injection detected on {url} with parameter {result[2]} : {result[3]}")
                        self.found_sqli.append((url,result))
                bar()

        for msg in msgs:
            toolbox.vprint(msg, level=3)
        if len(msgs) == 0:
            toolbox.tprint("No SQL injection found")

    def search_open_redirect(self):
        """
        search for open redirection inside GET parameters
        """

        self.found_openredirect = []

        if len(self.url_parameters) == 0:
            toolbox.tprint(
                "No GET parameters found on target, skipping open redirect detection")
            return

        toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...", end='\r')
        time.sleep(5)
        print(' '*72, end='\r')

        msgs = []
        with alive_bar(len(self.url_parameters), title=toolbox.get_header("ATTACK")+f"Searching open redirect in GET parameters", enrich_print=False) as bar:
            for param in self.url_parameters:
                result = vt.test_open_redirect(param[0], param[1])
                if result:
                    if result == "internal":
                        msgs.append(f"Possible internal open redirect on {param[0]}?{param[1]}=here")
                        self.found_openredirect.append((param[0], param[1], "GET", "internal open redirect"))
                    elif result == "external":
                        msgs.append(f"Possible external open redirect on {param[0]}?{param[1]}=here")
                        self.found_openredirect.append((param[0], param[1], "GET", "external open redirect"))
                else:
                    # test with selenium for client side open redirect ?
                    pass
                bar()

        for msg in msgs:
            toolbox.vprint(msg, level=1)
        if len(msgs) == 0:
            toolbox.tprint("No Open Redirect found")

    def auth_attack(self):
        """
        test for default creds/small bruteforce is login detected
        """

        self.found_credentials = []

        forms_to_test = []
        for form in self.forms_list:
            is_login = False
            for param in form['parameters']:
                param = param['name'].lower()
                if param.find('password') != -1 or param.find('user') != -1 or param.find('email') != -1 or param.find('passwd') != -1:
                    is_login = True
            if is_login:
                forms_to_test.append(form)

        if len(forms_to_test) == 0:
            toolbox.tprint(
                "No login forms found on target, skipping authentication attack")

        toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...", end='\r')
        time.sleep(5)
        print(' '*72, end='\r')

        to_skip_url = [
            "register",
            "signup",
            "sign-up",
            "captcha",     # DVWA skipping
            "setup.php",       # DVWA skipping
            "security.php"  # DVWA skipping
        ]

        url_scanned = []

        for form in forms_to_test:
            skip = False
            for entry in to_skip_url:
                if entry in form['url']:
                    skip = True

            if form['url'] in url_scanned:
                skip = True
            else:
                url_scanned.append(form['url'])

            if skip:
                continue

            result = vt.test_default_credentials(form)
            if result:
                for username, password in result:
                    toolbox.vprint(f"Possible valid credential : {colored(username, "green", 
                        attrs=["bold"])} : {colored(password, "green", attrs=["bold"])}", level=3)
                    self.found_credentials.append((form['url'],username,password))
        
        if len(self.found_credentials) == 0:
            toolbox.tprint("No default credentials found")

    def search_ssrf(self):
        """
        search for Server Side Request Forgery
        """

        self.found_ssrf = []

        if len(self.params_to_test) == 0:
            toolbox.tprint(
                "No parameters found on target, skipping SSRF detection")
            return

        toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...", end='\r')
        time.sleep(5)
        print(' '*72, end='\r')

        msgs = []
        with alive_bar(len(self.params_to_test), title=toolbox.get_header("ATTACK")+f"Testing SSRF on found forms and parameters", enrich_print=False) as bar:
            for url, parameters, method in self.params_to_test:
                # random hash for request identification
                req_id = str(random.getrandbits(16))
                result = vt.test_ssrf(url, parameters, method, req_id)
                if result:
                    msgs.append(f"Possible SSRF detected on {method.upper()} {url} with parameter : {result}")
                    self.found_ssrf.append((url,method,parameters))
                bar()

        for msg in msgs:
            toolbox.vprint(msg, level=3)
        if len(msgs) == 0:
            toolbox.tprint("No SSRF found")

    def search_misconfiguration(self):
        """
        search for common misconfiguration / bad practice
        """

        self.found_misconf = []

        toolbox.tprint(f"Sleeping 5 sec to avoid being blocked...", end='\r')
        time.sleep(5)
        print(' '*72, end='\r')

        # test for missing Headers
        url = ""

        useful_headers = {
            'Content-Security-Policy': 'Defines a policy for content loading on the page, helping to prevent cross-site scripting (XSS) and other code injection attacks by specifying which sources of content are trusted.',
            'X-Frame-Options': 'Prevents the page from being embedded in an iframe, which helps mitigate clickjacking attacks by disallowing the page to be displayed in a potentially malicious context.',
            'X-Content-Type-Options': 'Prevents the browser from interpreting files as a different MIME type than what is specified in the "Content-Type" header, helping to mitigate attacks based on MIME-sniffing vulnerabilities.',
            'Referrer-Policy': 'Controls how much information is sent in the "Referer" header when navigating to a different site, reducing privacy risks by limiting exposure of sensitive URL data.',
            'Permissions-Policy': 'Controls which features and APIs (like geolocation, camera, etc.) can be used on a website, helping to reduce the potential attack surface by limiting access to sensitive browser features.',
        }

        for service in self.services:
            data = self.services[service]
            if data["name"].find("http") != -1:
                protocol = "http"
                if hasattr(self, 'protocol'):
                    protocol = self.protocol

                url = f"{protocol}://{self.address}:{service}"

                if service == 80:
                    url = f"http://{self.address}"

                if service == 443 or data["name"].find("https") != -1:
                    url = f"https://{self.address}"

                current_headers = wu.get_server_headers(url)
                for header in useful_headers:
                    if header.lower() not in current_headers:
                        toolbox.vprint(f"Missing header found : {header}",level=1)
                        self.found_misconf.append({
                            "type": "missing_header",
                            "url": url,
                            "name": header,
                            "comments": useful_headers[header]
                        })

                for header in current_headers:
                    if header.lower().find('set-cookie') != -1:
                        cookie_attrs = current_headers[header].lower().split(';')
                        HttpOnly = True
                        Secure = True
                        if not "httponly" in cookie_attrs:
                            HttpOnly = False
                        if not "secure" in cookie_attrs:
                            Secure = False
                        if not HttpOnly or not Secure:
                            toolbox.vprint(f"Missing cookie attribute found, Secure: {Secure} - HttpOnly: {HttpOnly}",level=1)
                            self.found_misconf.append({
                                "type": "bad_cookie",
                                "url": url,
                                "name": None,
                                "comments": {
                                    "HttpOnly": HttpOnly,
                                    "Secure": Secure
                                }
                            })

        if len(self.params_to_test) == 0:
            toolbox.tprint(
                "No parameters found on target, skipping CSRF detection")
            return

        msgs = []
        with alive_bar(len(self.forms_list), title=toolbox.get_header("ATTACK")+f"Testing CSRF on found forms and parameters", enrich_print=False) as bar:
            for form in self.forms_list:
                result = vt.test_csrf(form)
                if result:
                    if result == 1:
                        self.found_misconf.append({
                            "type":"csrf_not_found",
                            "url": form['url'],
                            "name": None,
                            'comments': form['method']
                        })
                        msgs.append(f"CSRF not found for form on {form['method']} {form['url']}")
                    if result == 2:
                        self.found_misconf.append({
                            "type":"csrf_not_used",
                            "url": form['url'],
                            "name": None,
                            'comments': form['method']
                        })
                        msgs.append(f"CSRF found but not used on {form['method']} {form['url']}")
                bar()

        for msg in msgs:
            toolbox.vprint(msg,level=1)
        if len(msgs) == 0:
            toolbox.tprint("No CSRF misconfigurations found")

    def create_report(self,json_dir,csv_dir):
        """
        create a report of the scan results
        """

        self.end = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        html = reporting.html_report(self)

        if not os.path.exists("output/"):
            os.mkdir("output") 

        datenow = datetime.now().strftime('_%Y-%m-%d_%H:%M')
        target_name = self.target.replace(':','_').replace('/','')
        report_name = "output/" + target_name + datenow + '.html'

        with open(report_name, "w") as report:
            report.write(html)

        if json_dir != "":
            json_data = {}
            for entry in dir(self):
                if type(getattr(self,entry)) is dict or type(getattr(self,entry)) is dict:

                    json_data[entry] = getattr(self,entry)
            
            filename = os.path.join(json_dir,target_name+datenow+'.json')
            with open(filename,"w") as file:
                json.dump(json_data,file,indent=1)

        if csv_dir != "":
            columns = ["url","response","source"]
            filename = os.path.join(csv_dir,target_name+datenow+'.csv')
            with open(filename,"w") as file:
                
                file.write(",".join(columns)+'\n')
                
                for url,code in self.crawled_urls:
                    line = [url,str(code),"crawler"]
                    file.write(",".join(line)+'\n')
                
                for url,code in self.fuzzed_urls:
                    line = [url,str(code),"fuzzer"]
                    file.write(",".join(line)+'\n')
                                      
                    
