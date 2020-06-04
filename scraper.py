from bs4 import BeautifulSoup
from urllib.request import urlopen, HTTPError
from time import sleep
from re import compile, search
from database import yelp_check_org, yelp_check_url, yelp_check_host
from socket import getaddrinfo as dns_query
from socket import gaierror


# Makes request to Yelp, creates soup, passes soup to next function
def yelp_result_scraper():
    count = 0
    while count < 990:  # 990 is the last page
        unformatted_urls = []
        pageURL = 'https://www.yelp.co.uk/search?find_desc=&find_loc='\
            'Leeds%2C%20West%20Yorkshire&start=' + str(count)
        sleep(3)
        try:
            page = urlopen(pageURL)
            soup = BeautifulSoup(page, features="html.parser")
            count += 10
            page_number = int(count/10)
            find_internal_yelp_links(soup, page_number, unformatted_urls)
        except HTTPError:
            print('Yelp timed out, have you been banned?')
            sleep(5)
    else:
        print('Completed yelp scrape, exiting...')


# Finds links to individual yelp listings
def find_internal_yelp_links(soup, page_number, unformatted_urls):
    anchor_tags = soup.find_all('a', {'href': compile(
        r'(\/biz\/)(.{1,})(-leeds)(-*\d*\d*\d*)(\?*)')})
    for tag in anchor_tags:
        if '?' in tag.attrs['href']:
            continue
        else:
            unformatted_urls.append(tag.attrs['href'])
    print(f'Page number: {page_number}/99')
    format_unformatted_urls(unformatted_urls)


# Removes duplicate URLS and forms yelp links to indivudual listings
def format_unformatted_urls(unformatted_urls):
    unformatted_urls = list(dict.fromkeys(unformatted_urls))
    for yelp_url in unformatted_urls:
        yelp_url = 'https://yelp.com%s' % yelp_url
        yelp_organisation_id = yelp_check_url(yelp_url)
        if yelp_organisation_id is None:
            yelp_individual_listing_scraper(yelp_url)


# Makes requests to individual business listings gathered
def yelp_individual_listing_scraper(yelp_url):
    sleep(5)
    try:
        page = urlopen(yelp_url)
        soup = BeautifulSoup(page, features="html.parser")
        yelp_url_bak = yelp_url
        url_selector = soup.select('a[href*=biz_redir]')
        find_external_links(soup, yelp_url_bak, url_selector, yelp_url)
    except HTTPError:
        print('Yelp timed out, have you been banned?')
        pass


# Finds links to external business websites
def find_external_links(soup, yelp_url_bak, url_selector, yelp_url):
    for yelp_url in url_selector:
        if 'Full menu' in yelp_url:
            break
        else:
            converted_yelp_url = yelp_url.get_text()
            site_title = soup.find('h1')
            site_name = site_title.next
            print(site_name)
            # https://www.regextester.com/105075
            reg_url = search(
                r'^(http:\/\/|https:\/\/)?([a-zA-Z0-9-_]+\.)'
                r'*[a-zA-Z0-9][a-zA-Z0-9-_]+', converted_yelp_url)
            site_url = reg_url.group()
            print(site_url)
            ip_list = reverse_dns_query(site_url)
            if ip_list is None:
                continue
            else:
                load_data(site_name, site_url, yelp_url_bak, ip_list)


# Performs a reverse DNS query on the URL to gather IP address(es)
def reverse_dns_query(site_url):
    try:
        ip_str = dns_query(site_url, 80)
        ip_list = []
        for ip in ip_str:
            ip_list.append(ip[4][0])
            print(ip[4][0])
        return ip_list
    except gaierror:
        pass


# Passes all data to database.py functions which load the data into the DB
def load_data(site_name, site_url, yelp_url_bak, ip_list):
    yelp_organisation_id = yelp_check_org(
        site_name, site_url, yelp_url_bak)
    for ip in ip_list:
        yelp_check_host(ip, yelp_organisation_id)


if __name__ == '__main__':
    yelp_result_scraper()
