from bs4 import BeautifulSoup
from urllib.request import urlopen, HTTPError
from time import sleep
from re import compile, search
from database import yelp_organisation_data, yelp_host_data, check_yelp_url
from socket import getaddrinfo as dns_query
from socket import gaierror

def page_scraper(): 
    #Needs to grab end page number to work out how many pages to scrape then add loop to grab all links DONE (990 MAX)
    #remove duplicated links DONE
    #Needs to grab all links on pages it's scraping DONE
    count = 0

    while count < 990: #Update to 990 once stable
        unformatted_urls = []
        pageURL = 'https://www.yelp.co.uk/search?find_desc=&find_loc=Leeds%2C%20West%20Yorkshire&start='+ str(count)
        
        try:
            sleep(3)
            page = urlopen(pageURL)
            soup = BeautifulSoup(page, features="html.parser")
            anchor_tags = soup.find_all('a', {'href': compile(r'(\/biz\/)(.{1,})(-leeds)(-*\d*\d*\d*)(\?*)')})
            for tag in anchor_tags:
                if '?' in tag.attrs['href']:
                    continue
                else:
                    unformatted_urls.append(tag.attrs['href'])
            
            count += 10
            page_number = int(count/10)
            print ('Page number: ' + str(page_number) + '/99')
            format_unformatted_urls(unformatted_urls)
        except HTTPError:
            print ('Yelp timed out, have you been banned?')
    else:
        print ('Completed yelp scrape, exiting...')

def format_unformatted_urls(unformatted_urls):
    unformatted_urls = list (dict.fromkeys(unformatted_urls))
    for yelp_url in unformatted_urls:
        yelp_url = 'https://yelp.com%s'%yelp_url
        yelp_organisation_id = check_yelp_url(yelp_url)
        if yelp_organisation_id is None:
            site_scraper(yelp_url)

#dig the domain to get all the IPs
#write function that searches shodan with the IPs, link the entries back to the yelp table ID with ORM

def site_scraper(yelp_url):
    page = urlopen(yelp_url)
    sleep(6)
    soup = BeautifulSoup(page, features="html.parser")

    yelp_url_bak = yelp_url

    url_selector = soup.select('a[href*=biz_redir]')
    for yelp_url in url_selector:
        if 'Full menu' in yelp_url:
            break
        else:
            converted_yelp_url = yelp_url.get_text()
            site_title = soup.find('h1')
            site_name = site_title.next
            print (site_name)
            #https://www.regextester.com/105075
            reg_url = search(r'^(http:\/\/|https:\/\/)?([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+', converted_yelp_url)
            site_url = reg_url.group()
            print (site_url)
            try:
                ip_str = dns_query(site_url, 80)
                ip_list = []
                for ip in ip_str:
                    ip_list.append(ip[4][0])
                    print (ip[4][0])
            except gaierror:
                continue
        yelp_organisation_id = yelp_organisation_data(site_name, site_url, yelp_url_bak)
        for ip in ip_list:
            yelp_host_data(ip, yelp_organisation_id)
                
if __name__ == '__main__':
    page_scraper()