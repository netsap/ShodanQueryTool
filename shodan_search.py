from database import check_org, check_host, check_service,\
    query_input, check_vulns, write_log_file,\
    log_no_shodan_id, host_search_query
import shodan
from time import time, sleep
from datetime import datetime
from os import path

# Initialises Shodan with API key
api = shodan.Shodan("95vvRQj3igAqbCNSpdHMjHC6MlvB1hJD")


# Opens file path passed via qtool or uses "ShodanQueries" as default
# Checks if file has entries, if not prints an error
# Passes each query to the next function
def file_parser(file_path='ShodanQueries'):
    with open(file_path, 'r') as file:
        if path.getsize(file_path) == 0:
            print('No queries found in ' + file_path)
            exit()
        for query in file:
            search(query)


# Searches Shodan API for given query,
# increments page_number to gather all results,
# if first run, gathers total number of pages,
# handles timeout and no response errors,
# prints if log file is written to,
# passes each result of the query to sort_results
def search(query):
    first_run = True
    page_number = 1040
    total_pages = 1042
    print(f'Searching Shodan for {query}')
    while page_number <= total_pages:
        try:
            results = api.search(
                query, page=page_number, limit=None, minify=False)
            sleep(1)
            if first_run is True:
                total_results = results['total']
                total_pages = int(total_results / 100 + 1)
                first_run = False
            if page_number > 1:
                print(f'Searching Page: {page_number}/{total_pages}')
            page_number += 1
            for result in results['matches']:
                sort_results(result)
        except shodan.exception.APIError as e:
            print(f'Timeout, pausing requests for 1 second')
            sleep(1)
        except KeyError as e:
            print(f'No response, pausing requests for 1 second')
            sleep(1)
    try:
        if write_log_file.called is True:
            print('Entries added to log.txt')
    except AttributeError:
        pass


# Uses api.host to search for indivdual IPs listed in hosts table,
# assigns variables to each row in hosts table,
# handles timeout errors,
# passes results to next function
def search_hosts():
    hosts = host_search_query()
    for row in hosts:
        ip_str = row.ip_str
        org_id = row.organisation_id
        host_id = row.id
        try:
            host_search_result = api.host(ip_str, minify=False)
            sort_results(host_search_result, host_search=True)
        except shodan.exception.APIError:
            sleep(1)
            print("Timeout")


# gathers organisation, checks to see if it exists in the organisation table,
# passes results to next function based on if api.host or api.search is called
def sort_results(result, host_search=False):
    org = result.get("org", "n/a")
    org_id = check_org(org)
    ip_str = result["ip_str"]
    asn = result.get("asn", "n/a")
    if not host_search:
        parse_search_results(result, org, org_id, ip_str, asn)
    else:
        parse_host_results(result, org, org_id, ip_str, asn)


# Gathers further information from api.search result,
# checks host_id, if exists returns id, otherwise new entry is added
# and ID is returned.
# Passes variables to data_extraction function which returns additional data
# after additional variables are returned, passes variables to
# pass_data_to_database.
def parse_search_results(result, org, org_id, ip_str, asn):
    resultLocation = result['location']
    city = resultLocation.get("city", "n/a")
    country_code = resultLocation.get("country_code", "n/a")
    timestamp = result["timestamp"]
    host_id = check_host(ip_str, asn, city, country_code, org_id)
    shodan_module, port, transport, product, vendor_id, data,\
        shodan_id, vulns, domain, hostname = data_extraction(result)
    pass_data_to_database(
        shodan_module, port, transport, product, hostname, domain,
        data, timestamp, shodan_id, vulns, vendor_id, org, org_id, host_id)


# Gathers further information from api.host result,
# checks host_id, if exists returns id, otherwise new entry is added
# and ID is returned.
# Passes variables to data_extraction function which returns additional data
# after additional variables are returned, passes variables to
# pass_data_to_database.
def parse_host_results(result, org, org_id, ip_str, asn):
    city = result['city']
    country_code = result['country_code']
    timestamp = result['last_update']
    host_id = check_host(ip_str, asn, city, country_code, org_id)
    for row in result['data']:
        shodan_module, port, transport, product, vendor_id, data,\
            shodan_id, vulns, domain, hostname = data_extraction(row)
        pass_data_to_database(
            shodan_module, port, transport, product, hostname, domain,
            data, timestamp, shodan_id, vulns, vendor_id, org, org_id, host_id)


# returns additonal data from result, strips "product" and "vendor_id" of
# potentially unwanted strings.
def data_extraction(result):
    shodan_meta = result.get("_shodan")
    shodan_module = shodan_meta.get("module", "n/a")
    port = result.get("port", 0)
    transport = result.get("transport", "n/a")
    product = result.get("product", "n/a")
    vendor_id = result.get("vendor_id", "n/a")
    data = result.get("data", "")
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
    product = product.strip(
        "/\n,/\r").replace("&nbsp;", " ").strip()
    vendor_id = vendor_id.strip(
        "/\n,/\r").replace("&nbsp;", " ").strip()
    return shodan_module, port, transport, product, vendor_id, data,\
        shodan_id, vulns, domain, hostname


# If shodan_id is none, log the service and continue,
# else check_service to see if exists, if not it will be inserted.
# checks if "vulns" dict exists in results, if so passes to next function.
# If vuln variables are returned, they are passed to check_vulns,
# which checks if the vuln already exists for the service_id,
# if not it is inserted.
def pass_data_to_database(
        shodan_module, port, transport, product, hostname, domain,
        data, timestamp, shodan_id, vulns, vendor_id, org, org_id, host_id):
    if shodan_id is None:
        log_no_shodan_id(
            port, transport, product, org, org_id, host_id,
            vendor_id, shodan_module, vulns)
        pass
    else:
        service_id = check_service(
            shodan_module, port, transport, product, hostname,
            domain, data, timestamp, shodan_id, vendor_id,
            org, org_id, host_id)
        if vulns:
            for vuln in vulns:
                cve, cvss, summary, reference, verified = parse_vulns(vulns)
                check_vulns(
                    cve, cvss, summary, reference, verified,
                    org_id, host_id, service_id)


# Assigns and returns variables from "vulns" dict
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


# If this file is called individually, run this function
if __name__ == '__main__':
    file_parser()
