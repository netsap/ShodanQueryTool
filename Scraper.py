from bs4 import BeautifulSoup
from urllib.request import urlopen
import re


def page_scraper():
    #Needs to grab end page number to work out how many pages to scrape then add loop to grab all links
    #remove duplicated links
    #Needs to grab all links on pages it's scraping
    count = 0
    unformatted_urls = []

    while count < 20:
        pageURL = 'https://www.yelp.co.uk/search?find_desc=&find_loc=Leeds%2C%20West%20Yorkshire&start='+ str(count)
        
        page = urlopen(pageURL)
        soup = BeautifulSoup(page, features="html.parser")

        #next decide whether to use a dict with the shop name and url or a list with the unformatted_urls
        test2 = soup.find_all('a', {'href': re.compile(r'(\/biz\/)(.{1,})(-leeds)(-*\d*\d*\d*)(\?*)')})
        for item in test2:
            if '?' in item.attrs['href']:
                continue
            else:
                #print (item.attrs['href'])
                unformatted_urls.append(item.attrs['href'])
                #print (unformatted_urls)
        
        count += 10
    else:
        format_unformatted_urls(unformatted_urls)
        print ('exiting...')


def format_unformatted_urls(unformatted_urls):
    urls = []
    unformatted_urls = list (dict.fromkeys(unformatted_urls))
    for url in unformatted_urls:
        url = 'https://yelp.co.uk'.join(url)
        print (url)
        #urls.append(url)
    print (urls)
    print ('length' + len(urls))


    print ('Length' + len(unformatted_urls))


def site_scraper(url):
    page = urlopen(url)
    soup = BeautifulSoup(page, features="html.parser")

    test3 = soup.select('a[href*=biz_redir]')
    for item in test3:
        print(item.get_text())


page_scraper()