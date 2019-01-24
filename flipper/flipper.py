import requests
import re
import os
import argparse
from bs4 import BeautifulSoup as BS

def cli():
    parser = argparse.ArgumentParser(description='A web scraping tool to help pentesters crawl websites for vulnerable personal info')
    parser.add_argument('url', metavar='N', type=str, nargs='+',
                        help='url(s) to crawl for vulnerabilities')
    parser.add_argument('-r', dest='recursive', default=False, action="store_true", 
                        help='recursively crawl all top level URLs found on the requested site')
    args = parser.parse_args()

    vulns = {}
    cleaned_urls = add_protocols(args.url)
    for url in cleaned_urls:
        scraper = get_scraper(url)
        found_strings, found_urls = format_site(scraper)
        vuln_items = crawl_emails(found_strings + found_urls)
        for s in vuln_items:
            if s not in vulns:
                vulns[s] = {'located_on': []}
            vulns[s]['located_on'] += url
        if args.recursive:
            cleaned_found_urls = add_protocols(found_urls)
            for found_url in cleaned_found_urls:
                if found_url not in cleaned_urls:
                    cleaned_urls += found_url
            print(cleaned_found_urls)
    print(vulns)

def print_title(title):
    rows, columns = os.popen('stty size', 'r').read().split()
    columns = int(cols) - len(title)
    print('-' * round(columns/2) + title + '-' * round(columns/2))

def add_protocols(urls):
    r = re.compile('^(http|https):\/\/')
    for i, url in enumerate(urls):
        if not r.match(url):
            urls[i] = 'http://' + url
    return urls

def get_scraper(url):
    r = requests.get(url)
    bs = BS(r.text, 'html.parser')
    return bs

def format_site(bs):
    urls = [x.get('href') for x in bs.find_all('a')]
    strings = re.sub('\n', ' ', bs.get_text()).split()
    
    return strings, urls

def crawl_emails(strings):
    r = re.compile('([a-zA-Z0-9])+@([a-zA-Z0-9])+\.(com|org|net|edu)')
    emails = filter(r.search, strings)
    return emails

if __name__ == '__main__':
    cli()
