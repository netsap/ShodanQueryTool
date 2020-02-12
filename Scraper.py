from bs4 import BeautifulSoup
from urllib.request import urlopen

url = 'https://www.yelp.co.uk/biz/laynes-espresso-leeds'

def scraper(url):
    page = urlopen(url)
    soup = BeautifulSoup(page, features="html.parser")

    test3 = soup.select('a[href*=biz_redir]') #WORKS!!!!!!!!!
    for item in test3:
        print(item.get_text())

    #urltest = soup.findAll('biz_redir')
    #atest = soup.a
    #print (urltest)
    #print (atest)
    #test1 = soup.find('a', href='/biz_redir')

    #for link in soup.findAll('a'):
    #    print (link.string)

    
    #for link in soup.findAll('a',class_='lemon--a__373c0__IEZFH link__373c0__29943 link-color--blue-dark__373c0__1mhJo link-size--default__373c0__1skgq'):
    #    print (link.string)

    #for link in soup.findAll('a[href*=biz_redir]'):
        print (link.string)



    #print (test3.string)

     #for link in soup.findAll('a'):
    #    print (link.string)
scraper(url)
