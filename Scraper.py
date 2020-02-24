from bs4 import BeautifulSoup
from urllib.request import urlopen, HTTPError
from time import sleep
import re
import socket
from ShodanQueryTool import yelp_organisation_data, yelp_host_data
from pydig import query as dns_query

def page_scraper():
    #Needs to grab end page number to work out how many pages to scrape then add loop to grab all links DONE (990 MAX)
    #remove duplicated links DONE
    #Needs to grab all links on pages it's scraping DONE
    count = 0
    
    while count < 20: #Update to 990 once stable
        unformatted_urls = []
        pageURL = 'https://www.yelp.co.uk/search?find_desc=&find_loc=Leeds%2C%20West%20Yorkshire&start='+ str(count)
        
        try:
            sleep(3)
            page = urlopen(pageURL)
        except HTTPError:
            print ('Yelp timed out, have you been banned?')
        
        soup = BeautifulSoup(page, features="html.parser")


        #next decide whether to use a dict with the shop site_name and yelp_url or a list with the unformatted_urls
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
    for yelp_url in unformatted_urls:
        yelp_url = 'https://yelp.com%s'%yelp_url
        urls.append(yelp_url)
        site_scraper(yelp_url)

#write function to check if yelp yelp_url is already in DB and if it is skip over to stop making so many requests?
#Issue with this is that the same site can have multiple hosts, maybe dig the domain to get all the IPs

#write function that searches shodan with the IPs, link the entries back to the yelp table ID with ORM
def site_scraper(yelp_url):
    page = urlopen(yelp_url)
    sleep(6)
    soup = BeautifulSoup(page, features="html.parser")

    url_selector = soup.select('a[href*=biz_redir]')
    for yelp_url in url_selector:
        if 'Full menu' in yelp_url:
            break
        else:
            yelp_url = yelp_url.get_text()
            #https://www.regextester.com/105075
            reg_url = re.search(r'^(http:\/\/|https:\/\/)?([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+', yelp_url)
            site_url = reg_url.group()
            print (site_url)
            ip_str = dns_query(site_url, 'A')
            print (ip_str)
        site_title = soup.find('h1')
        site_name = site_title.next
        print (site_name)
        
        yelp_organisation_id = yelp_organisation_data(site_name, site_url)
        for ip in ip_str:
            yelp_host_data(ip, yelp_organisation_id)
                
page_scraper()