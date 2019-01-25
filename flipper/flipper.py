import requests
import re
import os
import argparse
import spacy
from bs4 import BeautifulSoup as BS
from halo import Halo
from spacy.tokens import Doc

def cli():
    parser = argparse.ArgumentParser(description='A web scraping tool to help pentesters crawl websites for vulnerable personal info')
    parser.add_argument('url', metavar='N', type=str, nargs='+',
                        help='url(s) to crawl for vulnerabilities')
    parser.add_argument('-r', dest='recursive', default=False, action="store_true", 
                        help='recursively crawl all top level URLs found on the requested site')
    parser.add_argument('--debug', dest='debug', default=False, action="store_true", 
                    help='Debugging is actually all about finding the bug. About understanding why the bug was there to begin with. About knowing that it’s existence was no accident.')
    args = parser.parse_args()

    emails = ()
    phones = ()
    ents = ()

    spinner = Halo(text='GET HYPED', spinner='dots')
    spinner.start()
    for base_url in args.url:
        cleaned_urls = [base_url]
        for url in cleaned_urls:
            
            spinner.text = 'Scraping {}'.format(url)
            # build a beautiful soup web scraper
            scraper = get_scraper(url)
            # pull strings, urls, and body text from the current url
            found_strings, found_urls, text = format_site(scraper)
            # run website page through nlp, build and return "entities" of people / orgs
            ents = set(find_ents(scraper)).union(ents)
            # build entity class in vuln dict if entity not already present

            emails = set(crawl_emails(text.split() + found_urls)).union(emails)
            phones = set(crawl_phones(text.split() + found_urls)).union(phones)

            if args.recursive == True:
                cleaned_found_urls = add_protocols(base_url, found_urls)
                for found_url in cleaned_found_urls:
                    if found_url not in cleaned_urls and base_url in found_url:
                        cleaned_urls.append(found_url)

    vectored_emails = []
    for email in emails:
        spinner.text = 'Vectoring {}'.format(email)
        vector_entities(email, ents)

    print(emails)
    print(phones)
    print(ents)

def print_title(title):
    rows, columns = os.popen('stty size', 'r').read().split()
    columns = int(cols) - len(title)
    print('-' * round(columns/2) + title + '-' * round(columns/2))

def add_protocols(base, urls):
    r = re.compile('^\/([a-zA-Z0-9])+')
    for i, url in enumerate(urls):
        if r.match(url):
            urls[i] = base + url[1:]
    return urls

def vector_entities(data, ents):
    wordlist = [data] + [x.text for x in ents]
    nlp = spacy.load('en_core_web_md')  # make sure to use larger model!
    tokens = Doc(nlp, wordlist)
    for token in tokens[1:]:
        print(tokens[0].text, token.text, tokens[0].similarity(token))


def get_scraper(url):
    r = requests.get(url)
    bs = BS(r.text, 'html.parser')
    return bs

def format_site(bs):
    text = bs.get_text()
    strings = bs.find_all('a')
    urls = [x.get('href') for x in bs.find_all('a')]

    return strings, urls, text

def find_ents(bs):
    body_text = ' '.join(
        [re.sub(r'(\n|[ ]{2,})', ' ', x.get_text()) for x in bs.find_all('body')])
    nlp = spacy.load('en_core_web_md')
    doc = nlp(body_text)
    ents = [x for x in doc.ents if x.label_ == 'PERSON' or x.label_ == 'ORG']

    return ents

def crawl_emails(strings):
    remail = re.compile('([a-zA-Z0-9])+@([a-zA-Z0-9])+\.(com|org|net|edu)')
    vulns = list(filter(remail.search, strings))
    return vulns

def crawl_phones(strings):
    rphone = re.compile(
            '^([0-9](-))?(\(?[0-9]{3}\)?|[0-9]{3})(-)([0-9]{3}(-)[0-9]{4}|[a-zA-Z0-9]{7})$')
    vulns = list(filter(rphone.search, strings))
    return vulns

if __name__ == '__main__':
    cli()
