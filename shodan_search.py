from database import check_org, check_host, check_service, query_input
import shodan
from time import time, sleep
from datetime import datetime
from os import path

api = shodan.Shodan("95vvRQj3igAqbCNSpdHMjHC6MlvB1hJD")


def file_parser(file_path):
    file = open(file_path, 'r')
    if path.getsize(file_path) == 0:
        print('No queries found in ' + file_path)
        exit()
    for query in file:
        search(query)


def search(query):
    total_pages = 2
    page_number = 1
    first_run = True

    print(f'Searching Shodan for {query}')

    while page_number < total_pages:
        try:
            # CHANGE PAGE NUM
            results = api.search(query, page=page_number, limit=None)
            sleep(2)
            if first_run is True:
                total_results = results['total']
                total_pages = int(total_results / 100 + 1)
                first_run = False
            if page_number > 1:
                print(f'Searching Page: {page_number}/{total_page}')
            page_number += 1
            for result in results['matches']:
                org = result.get("org", "n/a")
                org_id = check_org(org)
                ip_str = result["ip_str"]
                host_id = check_host(ip_str, result, org, org_id)
                check_service(result, org_id, host_id, org)

        except shodan.exception.APIError as e:
            print(f'{e}, Slowing down request rate')
            sleep(2)


if __name__ == '__main__':
    query_input()
