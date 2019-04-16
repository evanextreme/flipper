import requests
import re
import os
import argparse
import spacy
from bs4 import BeautifulSoup as BS
from halo import Halo
from spacy.tokens import Doc
from tqdm import tqdm

MAX_ENTS = 3
FILE_TYPES = ['PNG', 'JPG', 'PDF']

EMAIL_RE = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
URL_RE = re.compile(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
PHONE_RE = re.compile(
        r"(?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?([2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?([0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(\d+))?")
IP_RE = re.compile(
        r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])")


class Relative:
    def __init__(self, text, confidence):
        self.name = text.strip()
        self.confidence = confidence

    def __eq__(self, value):
        return self.name == value.name

    def __str__(self):
        return self.name

class Vulnerability:
    def __init__(self, ent):
        self.name = ent.text.strip()
        self.kind = None
        if ent.like_email:
            self.kind = 'Email'
        elif ent.like_num and PHONE_RE.matches(ent.text):
            self.kind = 'Phone'
        self.relatives = []

    def __eq__(self, value):
        if type(value) == str:
            return self.name == value
        return self.name == value.name
    def __str__(self):
        return self.name

    def add_relative(self, name, confidence):
        new_rel = Relative(name, confidence)
        new_rel.entity = self
        if new_rel in self.relatives:
            if self.relatives[self.relatives.index(new_rel)].confidence < new_rel.confidence:
                self.relatives.remove(new_rel)
            else:
                return
        
        for i, vuln in enumerate(self.relatives):
            if new_rel.confidence > vuln.confidence:
                self.relatives.insert(i, new_rel)
                return
        self.relatives.append(new_rel)

def cli():
    parser = argparse.ArgumentParser(description='A web scraping tool to help pentesters crawl websites for vulnerable personal info')
    parser.add_argument('url', metavar='N', type=str, nargs='+',
                        help='url(s) to crawl for vulnerabilities')
    parser.add_argument('-f', '--files', default=False, action="store_true",
                            help='Download / crawl compatible file types.')
    parser.add_argument('-l', dest='limit', type=int, nargs='?',
                        help='Limits the amount of URLs to spider/crawl for each site')
    parser.add_argument('-o', dest='output', type=str, nargs='?', help='Writes output to file path specified.')
    parser.add_argument('-x', dest='spider', default=True, action="store_false",
                        help='Only crawl URLs provided. Do not spider using found URLs.')
    parser.add_argument('--no-relatives', dest='relatives', default=True, action="store_false",
                        help='Disables confidence / entity processing.')

    parser.add_argument('--debug', dest='debug', default=False, action="store_true", 
                    help='Debugging is actually all about finding the bug. About understanding why the bug was there to begin with. About knowing that it’s existence was no accident.')
    args = parser.parse_args()

    emails = {}
    phones = {}

    spinner = Halo(text='Get hyped.', spinner='dots')
    spinner.start()
    i = 1
    
    nlp = None
    if args.relatives:
        spinner.text += ' Loading NLP library. '
        nlp = spacy.load('en_core_web_md')

    for base_url in args.url:
        cleaned_urls = [base_url]
        pbar = tqdm(cleaned_urls, position=1)
        for url in pbar:
            if base_url in url and file_type(url) != None:
                n = len(cleaned_urls)
                pbar.total = n
                if args.limit:
                    n = args.limit
                
                spinner.text = '{}/{} {:15} {}'.format(
                    i, n, 'Scraping...', url)
                spinner.spinner = 'simpleDotsScrolling'
                # build a beautiful soup web scraper
                scraper = get_scraper(url)
                if scraper:
                    # pull strings, urls, and body text from the current url
                    found_strings, found_urls = format_site(scraper)
                    # run website page through nlp, build and return "entities" of people / orgs
                    # build entity class in vuln dict if entity not already present

                    new_emails, new_urls, new_phones, new_ips = crawl_strings(
                        found_urls + found_strings)
                    add_pages(new_emails, url, all_vulns)
                    add_pages(new_phones, url, all_vulns)

                    if args.relatives and len(new_emails) + len(new_phones) > 1:
                        spinner.text = '{}/{} {:15} {}'.format(
                            i, n, 'Tokenizing...', url)
                        spinner.spinner = 'simpleDotsScrolling'

                        tokens = nlp(' '.join(found_strings))

                        spinner.text = '{}/{} {:15} {}'.format(
                            i, n, 'Comparing...', url)
                        spinner.spinner = 'squish'
                        vulns = find_ents(tokens)
                        for vuln in vulns:
                            if vuln.kind == 'email':
                                emails[vuln.name]['relatives'] = emails[vuln.name]['relatives'].union(vuln.relatives)


                    if args.spider:
                        cleaned_found_urls = add_protocols(base_url, found_urls)
                        for found_url in cleaned_found_urls:
                            if found_url not in cleaned_urls and base_url in found_url:
                                cleaned_urls.append(found_url)
                i += 1
                if args.limit and i > args.limit:
                    break    
    
    output = print_title('Emails') + print_dict(emails)
    
    if args.output:
        f = open(args.output, 'w')
        f.write(output)
        spinner.succeed('All done! Output written to {}'.format(args.filepath))
    else:
        spinner.succeed('All done! Here you go <3')
        print(output)

def print_title(title):
    rows, columns = os.popen('stty size', 'r').read().split()
    columns = int(columns) - len(title)
    return str('-' * round(columns/2) + title + '-' * round(columns/2))

def print_dict(dic):
    output = ''
    for name, objects in dic.items():
        output += '\n{}\n\tPages Found: '.format(name)
        for page in objects['pages']:
            output += '\n\t{}'.format(page)
        output += '\n\tPossible Relatives: '
        for relative in objects['relatives']:
            output += '\n\t{} - {}'.format(relative.name, relative.confidence)
        
    return output + '\n'

def add_pages(data, page, dic):
    for x in data:
        if x in dic:
            dic[x]['pages'].add(page)
        else:
            dic[x]={'pages': set([page]), 'relatives': set()}

def add_protocols(base, urls):
    r = re.compile('^\/([a-zA-Z0-9])+')
    for i, url in enumerate(urls):
        if r.match(url):
            urls[i] = base + url[1:]
    return urls


def find_ents(tokens):
    vulns = []
    for ent in tokens:
        if ent.text.strip() not in vulns and (ent.like_email or (ent.like_num and PHONE_RE.match(ent.text))):
            vuln = Vulnerability(ent)
            if vuln in vulns:
                i = vulns.index(vuln)
                vuln = vulns.pop(i)
            
            for t in tokens:
                vuln.add_relative(t.text, ent.similarity(t))
            vulns.append(vuln)
    return vulns

def vector_entities(data, ents):
    wordlist = [data] + [x.text for x in ents]
    nlp = spacy.load('en_core_web_md')  # make sure to use larger model!
    tokens = nlp(wordlist)
    for token in tokens[1:]:
        print(tokens[0].text, token.text, tokens[0].similarity(token))

def file_type(url):
    s = url.split('.')
    if s[len(s)-1] == s[2]:
        return 'HTML'
    else:
        ext = s[len(s)-1].split('?')[0]
        if ext.upper() in FILE_TYPES:
            ext.upper()
    
        

def get_scraper(url):
    try:
        r = requests.get(url, stream=True)
        length = int(r.headers.get('Content-Length', 0))
        if length < 1048576:
            return BS(r.text, 'html.parser')
        return None
    except Exception as e:
    # except requests.exceptions.ConnectionError as err:
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

    emails, urls, phones, ips = set(), set(), set(), set()
    
    for x in strings:
        s = str(x)
        email = EMAIL_RE.search(s)
        url = URL_RE.search(s)
        phone = PHONE_RE.search(s)
        ip = IP_RE.search(s)
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
