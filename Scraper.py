from bs4 import BeautifulSoup
from urllib.request import urlopen
from time import sleep
import re


def page_scraper():
    #Needs to grab end page number to work out how many pages to scrape then add loop to grab all links DONE (990 MAX)
    #remove duplicated links DONE
    #Needs to grab all links on pages it's scraping DONE
    count = 0
    unformatted_urls = []

    while count < 10: #Update to 990 once stable
        pageURL = 'https://www.yelp.co.uk/search?find_desc=&find_loc=Leeds%2C%20West%20Yorkshire&start='+ str(count)
        
        page = urlopen(pageURL)
        soup = BeautifulSoup(page, features="html.parser")

        #next decide whether to use a dict with the shop name and url or a list with the unformatted_urls
        test2 = soup.find_all('a', {'href': re.compile(r'(\/biz\/)(.{1,})(-leeds)(-*\d*\d*\d*)(\?*)')})
        for item in test2:
            if '?' in item.attrs['href']:
                continue
            else:
                unformatted_urls.append(item.attrs['href'])
        
        count += 10
        sleep(5)
    else:
        format_unformatted_urls(unformatted_urls)
        print ('exiting...')


def format_unformatted_urls(unformatted_urls):
    urls = []
    unformatted_urls = list (dict.fromkeys(unformatted_urls))
    for url in unformatted_urls:
        url = 'https://yelp.com%s'%url
        urls.append(url)

    print (urls)


def site_scraper(url):
    page = urlopen(url)
    soup = BeautifulSoup(page, features="html.parser")

    test3 = soup.select('a[href*=biz_redir]')
    for item in test3:
        print(item.get_text())

page_scraper()