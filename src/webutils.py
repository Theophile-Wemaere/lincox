from src import toolbox
from src import networkutils as nu
from urllib.parse import urljoin
import requests
import bs4

class Crawler:

    def __init__(self, urls=[]):
        self.visited_urls = []
        self.urls_to_visit = urls
        self.root_domain = nu.get_domain(urls[0])

    def download_url(self, url):
        return requests.get(url,allow_redirects=True).text

    def get_linked_urls(self, url, html):
        soup = bs4.BeautifulSoup(html, 'html.parser')
        links = soup.find_all('a')
        for link in links:
            path = link.get('href')
            if path and path.startswith('/'):
                path = urljoin(url, path)
            yield path

    def add_url_to_visit(self, url):
        if url != None:
            domain = nu.get_domain(url)
            if domain != -1 and not domain.endswith(self.root_domain) and domain != self.root_domain:
                # if a domain is found and it's not the root domain (e.g. external links like youtube, instagram, ...) or a subdomain
                return
            if url not in self.visited_urls and url not in self.urls_to_visit and not url.startswith('#'):
                toolbox.debug(f"Found path {url}")
                self.urls_to_visit.append(url)

    def crawl(self, url):
        html = self.download_url(url)
        for url in self.get_linked_urls(url, html):
            self.add_url_to_visit(url)

    def run(self):
        while self.urls_to_visit:
            url = self.urls_to_visit.pop(0)
            self.crawl(url)
            self.visited_urls.append(url)
            try:
                self.crawl(url)
            except:
                pass
            finally:
                self.visited_urls.append(url)
        
        return self.visited_urls