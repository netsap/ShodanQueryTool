from bs4 import BeautifulSoup
from urllib.request import urlopen
import re

#url = 'https://www.yelp.co.uk/biz/north-bar-leeds'
count = 0

def pageScraper():
    #Needs to grab end page number to work out how many pages to scrape then add loop to grab all links
    #remove duplicated links
    #Needs to grab all links on pages it's scraping
    
    pageURL = 'https://www.yelp.co.uk/search?find_desc=&find_loc=Leeds%2C%20West%20Yorkshire&start='+ str(count)

    page = urlopen(pageURL)
    soup = BeautifulSoup(page, features="html.parser")

    test2 = soup.find_all('a', {'href': re.compile(r'\/biz\/.{1,}?-leeds-*\d*\d*')})
    
    for item in test2:
        print (item.attrs['href'])

    count + 10

    #issue : doesn't pick up -leeds-2 links 
    #test1 = soup.select('a[href$="-leeds"]')

    #test2 = soup.findAll(re.compile(r'\/biz\/.{1,}?-leeds'))

    #testsubject = re.compile(r'\/biz\/.{1,}?-leeds')

    #mo = testsubject.search(test1)


    #\/biz\/.{1,}?-leeds

    #for item in test1:
    #    print (item)

    

def scraper(url):
    page = urlopen(url)
    soup = BeautifulSoup(page, features="html.parser")

    test3 = soup.select('a[href*=biz_redir]') #WORKS!!!!!!!!!
    for item in test3:
        print(item.get_text())

pageScraper()