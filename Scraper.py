from bs4 import BeautifulSoup
from urllib.request import urlopen
from time import sleep
import re
import socket
from ShodanQueryTool import yelp_data

def page_scraper():
    #Needs to grab end page number to work out how many pages to scrape then add loop to grab all links DONE (990 MAX)
    #remove duplicated links DONE
    #Needs to grab all links on pages it's scraping DONE
    count = 0
    

    while count < 20: #Update to 990 once stable
        unformatted_urls = []
        pageURL = 'https://www.yelp.co.uk/search?find_desc=&find_loc=Leeds%2C%20West%20Yorkshire&start='+ str(count)
        
        page = urlopen(pageURL)
        soup = BeautifulSoup(page, features="html.parser")

        #next decide whether to use a dict with the shop site_name and url or a list with the unformatted_urls
        test2 = soup.find_all('a', {'href': re.compile(r'(\/biz\/)(.{1,})(-leeds)(-*\d*\d*\d*)(\?*)')})
        for item in test2:
            if '?' in item.attrs['href']:
                continue
            else:
                unformatted_urls.append(item.attrs['href'])
        
        count += 10
        page_number = int(count/10)
        print ('Page number: ' + str(page_number) + '/99')
        format_unformatted_urls(unformatted_urls)
    else:
        
        print ('exiting...')

def format_unformatted_urls(unformatted_urls):
    urls = []
    unformatted_urls = list (dict.fromkeys(unformatted_urls))
    for url in unformatted_urls:
        url = 'https://yelp.com%s'%url
        urls.append(url)
        site_scraper(url)

def site_scraper(url):
    page = urlopen(url)
    sleep(5)
    soup = BeautifulSoup(page, features="html.parser")

    url_selector = soup.select('a[href*=biz_redir]')
    for url in url_selector:
        if 'Full menu' in url:
            break
        else:
            url = url.get_text()
            #https://www.regextester.com/105075
            reg_url = re.search(r'^(http:\/\/|https:\/\/)?([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+', url)
            site_url = reg_url.group()
            print (site_url)
            site_ip = socket.gethostbyname(site_url)
            print (site_ip)
        site_title = soup.find('h1')
        site_name = site_title.next
        print (site_name)
        
        yelp_data(site_name, site_ip, site_url)
                
page_scraper()