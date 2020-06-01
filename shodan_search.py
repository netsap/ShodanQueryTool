from database import check_org, check_host, check_service,\
     query_input, log_no_vulns, insert_new_vulns, write_log_file
import shodan
from time import time, sleep
from datetime import datetime
from os import path

api = shodan.Shodan("95vvRQj3igAqbCNSpdHMjHC6MlvB1hJD")


def file_parser(file_path='ShodanQueries'):
    with open(file_path, 'r') as file:
        if path.getsize(file_path) == 0:
            print('No queries found in ' + file_path)
            exit()
        for query in file:
            search(query)


def search(query):
    page_number = 1
    total_pages = 2
    first_run = True
    print(f'Searching Shodan for {query}')
    while page_number < total_pages:
        try:
            results = api.search(query, page=page_number, limit=None)
            sleep(2)
            if first_run is True:
                total_results = results['total']
                total_pages = int(total_results / 100 + 1)
                first_run = False
            if page_number > 1:
                print(f'Searching Page: {page_number}/{total_pages}')
            page_number += 1
            for result in results['matches']:
                parse_results(result)
        except shodan.exception.APIError as e:
            print(f'Timeout, Slowing down request rate')
            sleep(2)
        except KeyError as e:
            print(f'No response, Slowing down request rate')
            sleep(2)
    if write_log_file.called is True:
        print('Entries added to log.txt')


def parse_results(result):
    org = result.get("org", "n/a")
    org_id = check_org(org)
    ip_str = result["ip_str"]
    asn = result.get("asn", "n/a")
    resultLocation = result['location']
    city = resultLocation.get("city", "n/a")
    country_code = resultLocation.get("country_code", "n/a")
    timestamp = result["timestamp"]
    port = result.get("port", 0)
    transport = result.get("transport", "n/a")
    product = result.get("product", "n/a")
    vendor_id = result.get("vendor_id", "n/a")
    data = result.get("data", "")
    shodan_meta = result.get("_shodan")
    shodan_module = shodan_meta.get("module", "n/a")
    shodan_id = shodan_meta.get("id")
    vulns = result.get("vulns", None)
    try:
        domains = result["domains"]
        domain = domains[0]
    except IndexError:
        domain = ""
    hostname_res = result.get("hostnames", "n/a")
    if len(hostname_res) > 0:
        hostname = hostname_res[0]
    else:
        hostname = "n/a"
    if hostname is None or hostname == "":
        hostname = "n/a"
    # https://github.com/cudeso/tools/blob/master/shodan-asset-monitor/shodan-asset-monitor.py
    # Clean up unwanted strings from product and vendor
    product = product.strip("/\n,/\r").replace("&nbsp;", " ").strip()
    vendor_id = vendor_id.strip("/\n,/\r").replace("&nbsp;", " ").strip()

    host_id = check_host(ip_str, asn, city, country_code, org_id)
    if shodan_id is None:
        service_id = log_no_shodan_id(
          port, transport, product, org, org_id, host_id,
          vendor_id, shodan_module, vulns)
    else:
        service_id = check_service(
          port, transport, product, shodan_module, hostname, domain, data,
          timestamp, shodan_id, vendor_id,   org_id, host_id, org)
    if vulns:
        cve, cvss, summary, reference, verified = parse_results(vulns)
        insert_new_vulns(cve, cvss, summary, reference, verified)
    else:
        log_no_vulns(service_id)


def parse_vulns(vulns):
    for cve, v in vulns.items():
        cvss = v.get('cvss')
        summary = v.get('summary')
        reference = v.get('references')
        reference = ','.join(map(str, reference))
        veri = v.get('verified')
        if veri is False:
            verified = 0
        elif veri is True:
            verified = 1
    return cve, cvss, summary, reference, verified


if __name__ == '__main__':
    file_parser()
