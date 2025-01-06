from html import escape
from src import toolbox
from src import networkutils as nu
from urllib.parse import urljoin
import requests
import bs4
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from alive_progress import alive_bar
import json
import re
import random
import copy
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import time


import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings('ignore', category=bs4.XMLParsedAsHTMLWarning)
warnings.filterwarnings('ignore', category=bs4.MarkupResemblesLocatorWarning)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

HEADERS = {
    "User-Agent":"lincox 1.0"
}

def get_headers():

    # random user agent for FW bypass (work sometimes)
    headers = copy.deepcopy(HEADERS)
    headers["User-Agent"] += "." + str(random.getrandbits(24))

    return headers

class Crawler:

    def __init__(self, url=[],visited_urls=[]):
        self.visited_urls = visited_urls
        self.urls_to_visit = url
        self.address = url[0]
        self.root_domain = nu.get_domain(url[0])
        self.all_urls = []
        self.STOP = False
        self.headers = []
        self.headers2url = []
        self.found_data = []
        self.found_data_line = []
        self.forms_list = []
        self.previous_size = 0

    def __download_url(self, url):

        # print(f"Trying {url}")

        if self.STOP:
            return

        try:
            r = requests.get(url,allow_redirects=True,headers=get_headers(),verify=False)
            if r.url not in self.all_urls:
                toolbox.debug(f"Found path {r.url}")
                self.all_urls.append((r.url,r.status_code))
                self.visited_urls.append(url)

                # data research
                for header in r.headers:
                    if is_header_interesting(header):
                        data = (header,r.headers[header])
                        if data not in self.headers:
                            self.headers.append((header,r.headers[header]))
                            self.headers2url.append((header,r.headers[header],url))
                            toolbox.debug(f"Found header {header}")
                results = search_page_for_technology(r.text,url)
                if len(results) > 0:
                    for entry in results:
                        entry["url"] = url
                        if entry['line'] not in self.found_data_line:
                            toolbox.debug(f"Found {entry['name']} : {entry['line']}")
                            self.found_data.append(entry)
                            self.found_data_line.append(entry['line'])

                # form research
                self.forms_list += search_page_for_form(r.text,r.url)
            return r.text

        except KeyboardInterrupt:
            toolbox.warn(f"Keyboard interrupt detected, skipping Crawler on {self.address}",start='\n')
            self.STOP = True
        except urllib3.exceptions.ProtocolError:
            print("sleeping")
            time.sleep(5)
            return False
        except requests.exceptions.ConnectionError:
            print("sleeping")
            time.sleep(5)
            return False
        except Exception as e:
            print("Exception :",url,e)
            return False

    def __get_linked_urls(self, url, html):
        tags_with_urls = {
            'a': 'href',
            'link': 'href',
            'script': 'src',
            'img': 'src',
            'iframe': 'src',
            'video': 'src',
            'audio': 'src',
            'source': 'src',
            'form': 'action',
        }
        soup = bs4.BeautifulSoup(html, 'html.parser')
        for tag, attr in tags_with_urls.items():
            elements = soup.find_all(tag)
            for element in elements:
                path = element.get(attr)
                if path:
                    # Resolve relative URLs
                    # if path.startswith('/') or path.startswith('http'):
                    if path.startswith("mailto"):
                        return
                    path = urljoin(url, path)
                    yield path
        
        # TODO : crawl JS file for url with fetch(), href, ...

    def __extract_url(self,url):
        """
        remove comment from url
        """

        if url.find('#') != -1:
            ind = url.find('#')
            url = url [:ind]
            return url + "#LINCOX" # marker for vuln research
        
        return url

    def __add_url_to_visit(self, url):
        if url != None:
            domain = nu.get_domain(url)
            if domain != -1 and not domain.endswith(self.root_domain) and domain != self.root_domain:
                # if a domain is found and it's not the root domain (e.g. external links like youtube, instagram, ...) or a subdomain
                return
            
            url = self.__extract_url(url)

            if url not in self.visited_urls and url not in self.urls_to_visit and not url.startswith('#'):
                # hide media, js and css files
                media = r".*\.(jpg|jpeg|png|gif|mp4|mov|avi|ico|mp3|wav|flac|svg|js|css|pdf|webp).*"
                if not re.match(media, url, re.IGNORECASE):
                    self.urls_to_visit.append(url)

    def __crawl(self, url):
        html= self.__download_url(url)
        if html:
            for url in self.__get_linked_urls(url, html):
                self.__add_url_to_visit(url)

    def run(self):

        while self.urls_to_visit:

            if self.STOP:
                return self.all_urls, self.headers2url, self.found_data, self.forms_list
            
            msg = f"Found {len(self.visited_urls)} urls, got {len(self.urls_to_visit)} to visit"
            if self.previous_size-len(msg) > 0:
                toolbox.tprint(msg+" "*(self.previous_size-len(msg)),end='\r')
            else:
                toolbox.tprint(msg,end='\r')
            
            self.previous_size = len(msg)
            url = self.urls_to_visit.pop(0)
            try:
                self.__crawl(url)
            except:
                pass
            finally:
                self.visited_urls.append(url)
        
        return self.all_urls, self.headers2url, self.found_data, self.forms_list

class Fuzzer:

    def __init__(self,address,wordlist,method='GET',body=None,fuzzed_urls=[]):
        self.address = address
        self.wordlist = wordlist
        self.method = method
        self.fuzzed_urls = fuzzed_urls
        self.headers = None
        self.body = None
        if body is not None:
            self.body = body
        self.STOP = False

    def __get_file_lines(self,file_path:str)->list:

        lines = []
        if not os.path.exists(file_path):
            toolbox.exit_error(f"Error, {file_path} doesn't exists",1)
        
        with open(file_path,"r") as file:
            for line in file:
                lines.append(line.replace('\n',''))
            
        return lines

    def __fetch_url(self,line:str)->str:

        if self.STOP:
            return

        r = None
        if self.method == "GET":
            r = requests.get(f"{self.address}/{line}",headers=get_headers(),verify=False)
        elif self.method == "POST":
            r = requests.post(f"{self.address}/{line}",data=self.body,headers=get_headers(),verify=False)
        return r.url,r.status_code,len(r.text)

    def run(self):

        lines = self.__get_file_lines(self.wordlist)
        num_concurrent = 80
        
        if len(lines) == 0:
            toolbox.exit_error(f"Error, {file_path} seems to be empty",1)

        results = []
        previous_size = 0

        try:
            with alive_bar(len(lines), title=toolbox.get_header("INFO")+f"Fuzzing {self.address}", enrich_print=False) as bar:
                with ThreadPoolExecutor(max_workers=num_concurrent) as executor:
                    
                    future_to_line = {executor.submit(self.__fetch_url, line): line for line in lines}

                    for future in as_completed(future_to_line):
                        line = future_to_line[future]
                        result = future.result()
                        if result:
                            url,code,size = result
                            if code not in [403,404] and size != previous_size:
                                previous_size = size
                                toolbox.debug(f"Found path {url}")
                                results.append((url,code))
                        bar()
        except KeyboardInterrupt:
            toolbox.warn(f"Keyboard interrupt detected, skipping Fuzzer on {self.address}",start='\n')
            self.STOP = True
            return []
        except Exception as e:
            print(e)
            return []

        for url in results:
            if url not in self.fuzzed_urls:
                self.fuzzed_urls.append(url)

        return self.fuzzed_urls

class ParaMiner:

    def __init__(self,url,wordlist):
        self.url = url
        self.wordlist = wordlist
        self.STOP = False

    def __get_file_lines(self,file_path:str)->list:

        lines = []
        if not os.path.exists(file_path):
            toolbox.exit_error(f"Error, {file_path} doesn't exists",1)
        
        with open(file_path,"r") as file:
            for line in file:
                lines.append(line.replace('\n',''))
            
        return lines

    def __fetch_url(self,line:str)->str:

        if self.STOP:
            return

        value = "/etc/passwd"

        try:
            r = requests.get(f"{self.url}?{line}={value}",headers=get_headers(),verify=False)
            if len(r.text) != self.default_size:
                return r.url,line,r.status_code,len(r.text),"GET",''
            
            # else try POST request
            body = {
                f"{line}":f"{value}"
            }
            r = requests.post(f"{self.url}",data=body,headers=get_headers(),verify=False)
            if len(r.text) != self.default_size:
                return self.url,line,r.status_code,len(r.text),"POST",'','from_paraminer'
            return False
        except ConnectionResetError:
            time.sleep(5)
            return False


    def run(self):

        lines = self.__get_file_lines(self.wordlist)
        num_concurrent = 80
        
        if len(lines) == 0:
            toolbox.exit_error(f"Error, {file_path} seems to be empty",1)

        ready = False
        while not ready:
            try:

                results = []
                self.default_size = len(requests.get(f"{self.url}",headers=get_headers(),verify=False).text)

                # get default code for unknown parameter
                self.default_code_get = requests.get(f"{self.url}/?LINCOX=lugi",headers=get_headers(),verify=False).status_code
                self.default_code_post = requests.post(f"{self.url}",data={"LINCOX":"albert-fish"},headers=get_headers(),verify=False).status_code

                self.bad_codes = [403,404,405]
                if self.default_code_get != 200:
                    self.bad_codes.append(self.default_code_get)
                if self.default_code_post != 200:
                    self.bad_codes.append(self.default_code_post)

                ready = True

            except ConnectionResetError:
                time.sleep(5)
                return False
            except requests.exceptions.ConnectionError:
                time.sleep(5)
                return False

        try:
            with alive_bar(len(lines), title=toolbox.get_header("INFO")+f"Searching parameter in {self.url}", enrich_print=False) as bar:
                with ThreadPoolExecutor(max_workers=num_concurrent) as executor:
                    
                    future_to_line = {executor.submit(self.__fetch_url, line): line for line in lines}

                    for future in as_completed(future_to_line):
                        line = future_to_line[future]
                        result = future.result()
                        if result:
                            url,parameter,code,size,method, type = result
                            if code not in self.bad_codes and size != self.default_size:
                                toolbox.debug(f"Found parameter {parameter} with {method} request")
                                results.append(result)

                        if self.STOP:
                            break
                        bar()
        except KeyboardInterrupt:
            toolbox.warn(f"Keyboard interrupt detected, skipping ParaMiner on {self.url}",start='\n')
            self.STOP = True
            return []
        except Exception as e:
            print(e)
            return []

        return results

def get_crt_domains(address: str)-> list:
    """
    use the API of crt.sh to find domains names using SSL certificates
    """

    r = requests.get(f"https://crt.sh/?q={address}&output=json")
    json_data = json.loads(r.text)
    # print(json.dumps(json_data,indent=1))
    domains = []
    for entry in json_data:
        domains.append(entry["common_name"])
        if entry["name_value"].find('\n') != -1:
            domains += entry["name_value"].split('\n')
        else:
            domains.append(entry["name_value"])
    domains = list(set(domains))
    for domain in domains:
        toolbox.debug("Found domain " + domain)
    return domains

def is_header_interesting(header:str)->bool:
    """
    check if a header is interesting
    """

    header = header.lower()
    if header == "server":
        return True
    elif header == "x-powered-by":
        return True
    elif header.startswith("x-"):
        return True
    else:
        return False

def search_page_for_technology(page:str,url:str)->list:
    """
    search a webpage for well known technology markers
    """

    def search_wordpress(line):
        markers = [
            "WordPress",
            "/wp-content",
            "wp-includes",
            "/wp-admin",
            "/wp-"
        ]

        for marker in markers:
            if line.lower().find(marker.lower()) != -1:
                return True
        return False
    
    def search_drupal(line):
        markers = [
            "Drupal"
        ]

        for marker in markers:
            if line.lower().find(marker.lower()) != -1:
                return True
        return False

    def search_joomla(line):
        markers = [
            "Joomla"
        ]

        for marker in markers:
            if line.lower().find(marker.lower()) != -1:
                return True
        return False
    
    def search_password(line):

        line = line.lower().strip()

        if re.search(r'<\s*input[^>]*type\s*=\s*["\']password["\']', line, re.IGNORECASE):
            return False
        if re.search(r'<.*?>', line):
            return False

        if re.search(r'(Enter\s+(password|pass)|Your\s+(password|pass))', line, re.IGNORECASE):
            return False

        if re.search(r'(password|pass)\s*=\s*["\'].*["\']', line, re.IGNORECASE):
            return True
            
        if re.search(r'set(P|p)ass(word)?\s*\(', line):
            return True

        if re.search(r'["\'](password|pass)["\']\s*:\s*["\'].*["\']', line, re.IGNORECASE):
            return True

        if re.search(r'(password|pass)\s*=\s*os\.environ\.get', line, re.IGNORECASE):
            return False

        if line.find("passwd") != -1 or line.find("passphrase") != -1 or line.find("password") != -1:
            return True

        return False

    def search_username(line):

        line = line.lower().strip()

        if re.search(r'<.*?>', line):
            return False

        if re.search(r'(Enter\s+(username|user|email|credential)|Your\s+(username|user|email|credential))', line, re.IGNORECASE):
            return False

        if re.search(r'(username|user|email|credential)\s*=\s*["\'].*["\']', line, re.IGNORECASE):
            return True
        if re.search(r'set(User(name)?|Email|Credential)\s*\(', line, re.IGNORECASE):
            return True

        if re.search(r'["\'](username|user|email|credential)["\']\s*:\s*["\'].*["\']', line, re.IGNORECASE):
            return True

        if re.search(r'(username|user|email|credential)\s*=\s*os\.environ\.get', line, re.IGNORECASE):
            return False

        return False

    def search_comment(line):

        if line.startswith("//") or line.startswith("<!-") or line.startswith("/*") or line.startswith("#"):
            return True
        if line.find(" //") != -1 or line.find("\t//") != -1 or line.find("<!-") != -1 or line.find("/*") != -1:
            return True

        return False
    
    line = ""
    results = []
    for s in page:
        if s != '\n':
            line += s
        else:
            # analyse line for markers
            if search_wordpress(line):
                results.append({
                    "name":"Wordpress",
                    "type":"CMS",
                    "line":escape(line)
                })
            if search_drupal(line):
                results.append({
                    "name":"Drupal",
                    "type":"CMS",
                    "line":escape(line)
                })
            if search_joomla(line):
                results.append({
                    "name":"Joomla",
                    "type":"CMS",
                    "line":escape(line)
                })
            if search_password(line):
                results.append({
                    "name":"Password",
                    "type":"credential",
                    "line":escape(line)
                })
            if search_username(line):
                results.append({
                    "name":"Username",
                    "type":"credential",
                    "line":escape(line)
                })
            if search_comment(line):
                results.append({
                    "name":"Comment",
                    "type":"other",
                    "line":escape(line)
                })
            line = ""
    
    # for result in results:
    #     toolbox.debug(f"Found {result['name']} : {result['line']}")

    return results

def is_url_data_blacklisted(url:str)->bool:
    """
    check if a url is blacklisted to avoid trash in data research results
    """

    blacklist = [
        "git/index"
    ]

    for entry in blacklist:
        if url.find(entry) != -1:
            return True

    return False

def search_page_for_form(page:str,url:str)-> list:
    """
    search a webpage for form to test
    """

    soup = bs4.BeautifulSoup(page, 'html.parser')
    forms = soup.find_all('form')
    form_data_list = []

    for form in forms:
        form_info = {
            "method": form.get('method', 'get').lower(),
            "action": form.get('action'),
            "url": url,
            "parameters": []
        }

        for input_tag in form.find_all('input'):
            param = {
                "name": input_tag.get('name'),
                "type": input_tag.get('type', 'text').lower(),
                "value": input_tag.get('value')
            }
            if param["name"]:
                form_info["parameters"].append(param)
        for textarea_tag in form.find_all('textarea'):
            param = {
                "name": textarea_tag.get('name'),
                "type": "textarea",
                "value": textarea_tag.text
            }
            if param["name"]:
                form_info["parameters"].append(param)
        for select_tag in form.find_all('select'):
            for option_tag in select_tag.find_all('option'):
                param = {
                    "name": select_tag.get('name'),
                    "type": "select",
                    "value": option_tag.get('value')
                }
                if param["name"]:
                    form_info["parameters"].append(param)
                    break

        form_data_list.append(form_info)

    return form_data_list

def get_page_source(url):
    """
    Opens a URL in a Selenium WebDriver, waits for the page to load,
    and returns the page source.
    """
    options = webdriver.ChromeOptions()
    options.add_argument('--headless=new')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')

    try:
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        time.sleep(3)
        page_source = driver.page_source
        return page_source
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    finally:
        if 'driver' in locals():
            driver.quit()

def get_form_w_selenium(url:str)->dict:
    """
    load a page with selenium to get form info
    in case it is generated client side
    """

    page = get_page_source(url)
    forms = search_page_for_form(page,url)
    return forms

# def search_technology(urls:list):
#     """
#     enumerate given urls to search for special headers or technology info
#     """

#     headers = []
#     headers2url = []
#     found_data = []

#     with alive_bar(len(urls), title=toolbox.get_header("INFO")+f"Searching in found URLs...", enrich_print=False) as bar:
#         for url,source,source in urls:
#             if is_url_data_blacklisted(url):
#                 bar()
#                 continue
#             try:
#                 r = requests.get(url,headers=get_headers(),verify=False)
#                 bar()
#             except KeyboardInterrupt:
#                 toolbox.warn("Keyboard interrupt detected, skipping search",start='\n')
#             except Exception as e:
#                 bar()
#                 print(e)
#                 continue
#             r_headers = dict(r.headers)
#             for header in r.headers:
#                 if is_header_interesting(header):
#                     data = (header,r.headers[header])
#                     if data not in headers:
#                         headers.append((header,r.headers[header]))
#                         headers2url.append((header,r.headers[header],url))
#                         toolbox.debug(f"Found header {header}")
#             results = search_page_for_technology(r.text,url)
#             if len(results) > 0:
#                 for entry in results:
#                     entry["url"] = url
#                     found_data.append(entry)

#     # print(json.dumps(headers,indent=1))
#     # print(json.dumps(found_data,indent=1))
#     return headers2url,found_data
