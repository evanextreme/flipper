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
    parser.add_argument('-x', dest='spider', default=True, action="store_false", 
                        help='Only crawl URLs provided. Do not spider using found URLs.')
    parser.add_argument('--debug', dest='debug', default=False, action="store_true", 
                    help='Debugging is actually all about finding the bug. About understanding why the bug was there to begin with. About knowing that it’s existence was no accident.')
    args = parser.parse_args()

    emails = ()
    phones = ()
    ents = ()

    spinner = Halo(text='GET HYPED', spinner='dots')
    spinner.start()
    all_text = []
    for base_url in args.url:
        cleaned_urls = [base_url]
        for url in cleaned_urls:
            if base_url in url:
                spinner.text = 'Scraping {}'.format(url)
                # build a beautiful soup web scraper
                scraper = get_scraper(url)
                if scraper:
                    # pull strings, urls, and body text from the current url
                    found_text, found_urls = format_site(scraper)
                    # run website page through nlp, build and return "entities" of people / orgs
                    # build entity class in vuln dict if entity not already present

                    new_emails, new_urls, new_phones, new_ips = crawl_strings(found_urls + found_text)
                    emails = new_emails.union(emails)
                    phones = new_phones.union(phones)

                    all_text.append('\n'.join(found_text + list(new_emails)))


                    if args.spider:
                        cleaned_found_urls = add_protocols(base_url, found_urls)
                        for found_url in cleaned_found_urls:
                            if found_url not in cleaned_urls and base_url in found_url:
                                cleaned_urls.append(found_url)

    spinner.text = 'Finding entities...'
    ents = set(find_ents(all_text))
    vectored_emails = []
    for email in emails:
        spinner.text = 'Vectoring {}'.format(email)
        vector_entities(email, ents)
    spinner.stop()
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


def find_ents(all_strings):
    nlp = spacy.load('en_core_web_md')
    for string in all_strings:
        tokens = nlp(string)
        for token in tokens:
            print(token)
        for e in [x for x in tokens if x.ent_type_ == 'PERSON' or x.ent_type_ == 'ORG']:
            for t in [x for x in tokens if x.ent_type_ == 'PERSON' or x.ent_type_ == 'ORG']:
                print(e.text, t.text, e.similarity(t))
    return all_ents


def vector_entities(data, ents):
    wordlist = [data] + [x.text for x in ents]
    nlp = spacy.load('en_core_web_md')  # make sure to use larger model!
    tokens = nlp(wordlist)
    for token in tokens[1:]:
        print(tokens[0].text, token.text, tokens[0].similarity(token))


def get_scraper(url):
    try:
        r = requests.get(url)
        bs = BS(r.text, 'html.parser')
        return bs
    except requests.exceptions.ConnectionError as err:
        return None

def format_site(bs):
    tags = bs.find_all()
    text = []
    hrefs = []
    for tag in tags:
        if hasattr(tag, 'text') and len(tag.text) > 0:
            text.append(tag.text.replace('\n', ' '))
        if 'href' in tag.attrs:
            hrefs.append(tag.attrs['href'])

    return text, hrefs

def get_text(tag):
    print('tag')


def crawl_strings(strings):
    remail = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
    rurl = re.compile(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
    rphone = re.compile(
        r"(?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?([2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?([0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(\d+))?")
    rip = re.compile(
        r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])")
    emails, urls, phones, ips = set(), set(), set(), set()
    
    for x in strings:
        s = str(x)
        email = remail.search(s)
        url = rurl.match(s)
        phone = rphone.match(s)
        ip = rip.match(s)
        if email:
            emails.add(s[email.span()[0]:email.span()[1]])
            strings.append(s[email.span()[1]:])
        elif url:
            urls.add(s[url.span()[0]:url.span()[1]])
            strings.append(s[url.span()[1]:])
        elif phone:
            phones.add(s[phone.span()[0]:phone.span()[1]])
            strings.append(s[phone.span()[1]:])
        elif ip:
            ips.add(s[ip.span()[0]:ip.span()[1]])
            strings.append(s[ip.span()[1]:])
    
    return emails, urls, phones, ips

if __name__ == '__main__':
    cli()
