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

import warnings
warnings.filterwarnings('ignore', category=bs4.XMLParsedAsHTMLWarning)

class Crawler:

    def __init__(self, url=[],visited_urls=[]):
        self.visited_urls = visited_urls
        self.urls_to_visit = url
        self.root_domain = nu.get_domain(url[0])
        self.all_urls = []
        self.STOP = False

    def __download_url(self, url):
        try:
            r = requests.get(url,allow_redirects=True)
            if r.url not in self.all_urls:
                toolbox.debug(f"Found path {r.url}")
                self.all_urls.append((r.url,r.status_code))
                self.visited_urls.append(url)
            return r.text
        except KeyboardInterrupt:
            toolbox.warn("Keyboard interrupt detected, skipping Crawler",start='\n')
            self.STOP = True
        except Exception as e:
            print(url)
            print(e)
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
                media = r".*\.(jpg|jpeg|png|gif|mp4|mov|avi|mp3|wav|flac|svg|js|css).*"
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
                return self.all_urls

            toolbox.tprint(f"Found {len(self.visited_urls)} urls, got {len(self.urls_to_visit)} to visit",end='\r')
            url = self.urls_to_visit.pop(0)
            try:
                self.__crawl(url)
            except:
                pass
            finally:
                self.visited_urls.append(url)
        
        return self.all_urls

class Fuzzer:

    def __init__(self,address,wordlist,headers=None,method='GET',body=None,fuzzed_urls=[]):
        self.address = address
        self.wordlist = wordlist
        self.method = method
        self.fuzzed_urls = fuzzed_urls
        self.headers = None
        self.body = None
        if headers is not None:
            self.headers = headers
        if body is not None:
            self.body = body

    def __get_file_lines(self,file_path:str)->list:

        lines = []
        if not os.path.exists(file_path):
            toolbox.exit_error(f"Error, {file_path} doesn't exists",1)
        
        with open(file_path,"r") as file:
            for line in file:
                lines.append(line.replace('\n',''))
            
        return lines

    def __fetch_url(self,line:str)->str:

        r = None
        try:
            if self.method == "GET":
                r = requests.get(f"{self.address}/{line}",headers=self.headers)
            elif self.method == "POST":
                r = requests.post(f"{self.address}/{line}",body=self.body,headers=self.address)
        except:
            return False
        return r.url,r.status_code

    def run(self):

        lines = self.__get_file_lines(self.wordlist)
        num_concurrent = 80
        
        if len(lines) == 0:
            toolbox.exit_error(f"Error, {file_path} seems to be empty",1)

        results = []

        with alive_bar(len(lines), title=toolbox.get_header("INFO")+f"Fuzzing {self.address}", enrich_print=False) as bar:
            with ThreadPoolExecutor(max_workers=num_concurrent) as executor:
                
                future_to_line = {executor.submit(self.__fetch_url, line): line for line in lines}

                for future in as_completed(future_to_line):
                    line = future_to_line[future]
                    result = future.result()
                    if result:
                        url,code = result
                        if code not in [403,404]:
                            url,code = result
                            toolbox.debug(f"Found path {url}")
                            # results.append((line, url, result))
                            results.append((url,code))
                    bar()

        for url in results:
            if url not in self.fuzzed_urls:
                self.fuzzed_urls.append(url)

        return self.fuzzed_urls

def get_crt_domains(address: str)-> list:
    """
    use the API of ctr.sh to find domains names using SSL certificates
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

def search_page_for_technology(page:str)->dict:
    """
    search a webpage for well known technology markers
    """
    
    for s in page:
        if s == '\n':
            line += s

def search_technology(urls:list):
    """
    enumerate given urls to search for special headers or technology info
    """

    headers = []
    headers2url = {}

    for url,source,source in urls:
        r = requests.get(url)
        r_headers = dict(r.headers)
        for header in r.headers:
            if is_header_interesting(header):
                data = (header,r.headers[header])
                if data not in headers:
                    headers.append((header,r.headers[header]))
                    headers2url[header] = url
                    toolbox.debug(f"Found header {header}")
        search_page_for_technology(r.text)
    # print(json.dumps(headers,indent=1))