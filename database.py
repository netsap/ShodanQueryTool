from sqlalchemy import create_engine, Table, Column, Integer, String,\
     ForeignKey, MetaData, select, exc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm.exc import MultipleResultsFound
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import pandas as pd

engine = create_engine('sqlite:///QueryTool.db')
meta = MetaData()
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()


# Notify if any results have been logged
def write_log_file(log_string):
    write_log_file.called = True
    with open('log.txt', 'a') as logFile:
        logFile.write(log_string)


# Creates the Organisation class
class Organisation(Base):
    __tablename__ = 'organisation'

    id = Column(Integer, primary_key=True)
    name = Column(String)

    hosts = relationship('Hosts', cascade='all, delete, delete-orphan')
    services = relationship('Services', cascade='all, delete, delete-orphan')
    vulns = relationship('Vulns', cascade='all, delete, delete-orphan')


# Creates the Hosts class
class Hosts(Base):
    __tablename__ = 'hosts'

    id = Column(Integer, primary_key=True)
    ip_str = Column(String, nullable=False)
    asn = Column(String)
    country_code = Column(String)
    city = Column(String)
    organisation_id = Column(Integer, ForeignKey(
        "organisation.id"), nullable=False)


# Creates the Services class
class Services(Base):
    __tablename__ = 'services'

    id = Column(Integer, primary_key=True)
    port = Column(String, nullable=False)
    transport = Column(String)
    product = Column(String)
    shodan_module = Column(String)
    hostname = Column(String)
    domain = Column(String)
    data = Column(String)
    created = Column(String)
    modified = Column(String)
    shodan_id = Column(String, nullable=False)
    vendor_id = Column(String)
    organisation_id = Column(Integer, ForeignKey(
        "organisation.id"), nullable=False)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)


# Creates the Vulns class
class Vulns(Base):
    __tablename__ = 'vulns'

    id = Column(Integer, primary_key=True)
    cve = Column(String)
    cvss = Column(Integer)
    summary = Column(String)
    reference = Column(String)
    verified = Column(Integer)
    organisation_id = Column(Integer, ForeignKey(
        "organisation.id"), nullable=False)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False)


# Creates the Yelp_organisation class
class YelpOrganisation(Base):
    __tablename__ = 'yelp_organisation'

    id = Column(Integer, primary_key=True)
    site_name = Column(String, nullable=False)
    site_url = Column(String, nullable=False)
    yelp_url = Column(String, nullable=False)
    organisation_id = Column(Integer, ForeignKey(
        "organisation.id"), nullable=True)


# Creates the Yelp_hosts class
class YelpHosts(Base):
    __tablename__ = 'yelp_hosts'

    id = Column(Integer, primary_key=True)
    ip_str = Column(String, nullable=False)
    yelp_organisation_id = Column(Integer, ForeignKey(
        "yelp_organisation.id"), nullable=False)
    organisation_id = Column(Integer, ForeignKey(
        "organisation.id"), nullable=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)


# Creates tables from classes
Base.metadata.create_all(engine)

# Blacklisted words for the 'query' function
input_blacklist = ['UPDATE', 'DELETE', 'INSERT', 'CREATE DATABASE',
                   'CREATE TABLE', 'ALTER DATABASE', 'DROP TABLE',
                   'ALTER TABLE', 'CREATE INDEX', 'DROP INDEX']


# Recives query input, and runs code as required
def query_input():
    con = engine.connect()
    while True:
        query = input(
            '\nType your Query Below to exit type \'exit\' \n').upper()
        if query in input_blacklist:
            print('You may only write select statements')
        elif query == 'EXIT':
            exit()
        else:
            output_data(engine, query)


# Outputs SQL queries from query_input to a .csv file, handles invalid queries
def output_data(engine, query):
    try:
        out = pd.read_sql(query, con=engine)
        file_name = f"queries/{datetime.now().strftime('%d-%m_%H-%M-%S--%f')}\
            .csv".replace(" ", "")
        csv_out = out.to_csv(file_name, index=False)
        print(f'Output saved to: {file_name}')
    except exc.OperationalError:
        print('\nInvalid Query')


# Checks if specified Yelp Organisation exists in yelp_organisation table
def yelp_check_org(site_name, site_url, yelp_url):
    check_site_name = session.query(YelpOrganisation).filter(
        YelpOrganisation.site_name == site_name).one_or_none()
    if check_site_name is None:
        yelp_organisation_id = yelp_insert_new_org(
            site_name, site_url, yelp_url)
    else:
        yelp_organisation_id = check_site_name.id
    return yelp_organisation_id


# Inserts new Yelp Organisation into database, returns organisation ID if so
def yelp_insert_new_org(site_name, site_url, yelp_url):
    insert_yelp_organisation = YelpOrganisation(
        site_name=site_name, site_url=site_url, yelp_url=yelp_url)
    session.add(insert_yelp_organisation)
    session.commit()
    yelp_organisation_id = insert_yelp_organisation.id
    return yelp_organisation_id


# Checks if the Yelp Listing URL already exists in database,
# returns ID of entry if so
def yelp_check_url(yelp_url):
    check_url = session.query(YelpOrganisation).filter(
        YelpOrganisation.yelp_url == yelp_url).one_or_none()
    if check_url is None:
        return None
    else:
        yelp_organisation_id = check_url.id
        return yelp_organisation_id


# Returns ID of yelp host if IP already exists in database,
# otherwise passes variables to insert new host
def yelp_check_host(ip_str, yelp_organisation_id):
    check_ip_str = session.query(YelpHosts).filter(
        YelpHosts.ip_str == ip_str).one_or_none()
    if check_ip_str is None:
        yelp_host_id = yelp_insert_new_host(ip_str, yelp_organisation_id)
    else:
        yelp_host_id = check_ip_str.id
    return yelp_host_id


# Inserts new Yelp Host into the yelp_hosts table, returns ID
def yelp_insert_new_host(ip_str, yelp_organisation_id):
    insert_yelp_hosts = YelpHosts(
        ip_str=ip_str, yelp_organisation_id=yelp_organisation_id)
    session.add(insert_yelp_hosts)
    session.commit()
    yelp_host_id = insert_yelp_hosts.id
    return yelp_host_id


# First step in searching shodan for yelp hosts,
# assignes ip_str, org_id and id of each entry to variables,
# passes variables to function below
def yelp_to_shodan():
    from shodan_search import search
    yelp_gather = session.query(YelpHosts)
    for row in yelp_gather:
        ip_str = row.ip_str
        yelp_organisation_id = row.yelp_organisation_id
        yelp_host_id = row.id
        search(ip_str)
        link_yelp_ids(ip_str, yelp_organisation_id, yelp_host_id)


# Queries hosts table for ip_str which matches any yelp host ip_str
# If a match is found, org_id and host_id are assigned in the yelp_hosts table
def link_yelp_ids(ip_str, yelp_organisation_id, yelp_host_id):
    find_matching_host = session.query(Hosts).filter(
        Hosts.ip_str == ip_str).one_or_none()
    if find_matching_host:
        host_id = find_matching_host.id
        org_id = find_matching_host.organisation_id
        session.query(YelpOrganisation).filter(
            YelpOrganisation.id == yelp_organisation_id).update(
                {'organisation_id': org_id})
        session.query(YelpHosts).filter(YelpHosts.id == yelp_host_id).update(
            {'organisation_id': org_id, 'host_id': host_id})
        session.commit()


# Checks if organisation name already exists in organisation table
def check_org(org):
    search_org = session.query(Organisation).filter(
        Organisation.name == org).one_or_none()
    if search_org is None:
        org_id = insert_new_org(org)
    else:
        org_id = search_org.id
    return org_id


# Inserts new organisation into organisation table
def insert_new_org(org):
    insOrg = Organisation(name=org)
    session.add(insOrg)
    session.commit()
    org_id = insOrg.id
    return org_id


# Checks if ip_str already exists in hosts table,
# if so returns ID, otherwise returns None
def check_host(ip_str):
    hostIDResult = session.query(Hosts).filter(
        Hosts.ip_str == ip_str).one_or_none()
    if hostIDResult is None:
        return None
    else:
        host_id = hostIDResult.id
        return host_id


# Inserts new hosts into hosts table, returns ID
def insert_new_host(ip_str, asn, country_code, city, org_id):
    insHosts = Hosts(
        ip_str=ip_str, asn=asn, country_code=country_code,
        city=city, organisation_id=org_id)
    session.add(insHosts)
    session.commit()
    host_id = insHosts.id
    return host_id


# If the service doesn't exist, None is returned.
# Else, the service_id is returned.
def check_service(shodan_id):
    shodanIDCheck = session.query(Services).filter(
        Services.shodan_id == shodan_id).one_or_none()
    if shodanIDCheck is None:
        return None  # , None?
    else:
        service_id = shodanIDCheck.id
    return service_id


# Checks if service already exists by matching shodan_id,
# If so, a timestamp from the original entry is compared to the current service
# If the timestamp is more recent, the function returns updated
def check_service_timestamp(timestamp, service_id):
    timestamp_check = session.query(Services).filter(
        Services.service_id == service_id).one_or_none()
    if timestamp > timestamp_check.created:
        updated = True
        return updated


# Inserts new service into database and returns service_id
def insert_new_service(
        port, transport, product, shodan_module, hostname, domain, data,
        timestamp, shodan_id, vendor_id, org_id, host_id, org):
    modified = ("n/a")
    insService = Services(
        port=port, transport=transport, product=product,
        shodan_module=shodan_module, hostname=hostname,
        domain=domain, data=data, created=timestamp,
        modified=modified, shodan_id=shodan_id, vendor_id=vendor_id,
        host_id=host_id, organisation_id=org_id)
    session.add(insService)
    session.commit()
    service_id = insService.id
    return service_id


# Updates existing service entry with new information, adds modified timestamp
# and logs update in logfile.
def update_existing_service(
        port, transport, product, shodan_module, hostname, domain,
        data, timestamp, shodan_id, vendor_id, service_id):
    session.query(Services).filter(
        Services.id == service_id).update(
        {'port': port, 'transport': transport, 'product': product,
            'shodan_module': shodan_module, 'hostname': hostname,
            'domain': domain, 'data': data, 'modified': timestamp,
            'shodan_id': shodan_id, 'vendor_id': vendor_id})
    log_string = (f'''
    Service ID: {service_id} has been updated'
    Timestamp: {datetime.now()}''')
    write_log_file(log_string)
    return service_id


# Checks if vuln already exists in database by attempting to match current cve
# and service_id to entries in vulns table.
# If none, variables are passed to next function.
def check_vulns(cve, service_id):
    try:
        vuln_check = session.query(Vulns).filter(Vulns.cve == cve).filter(
            Vulns.service_id == service_id).one_or_none()
        if vuln_check is None:
            return None
    except MultipleResultsFound:
        return 1


# Inserts new vulns into database
def insert_new_vulns(
    cve, cvss, summary, reference, verified,
        org_id, host_id, service_id):
    insVuls = Vulns(
      cve=cve, cvss=cvss, summary=summary, reference=reference,
      verified=verified, organisation_id=org_id, host_id=host_id,
      service_id=service_id)
    session.add(insVuls)
    session.commit()


# Logs entries without a shodan_id to logfile, notifying that they won't
def log_no_shodan_id(
  port, transport, product, org, org_id, host_id,
  vendor_id, shodan_module, vulns):
    global logged
    logged = True
    log_string = (f'''

    Shodan.ID Field is empty, the following data will not be inserted:
    Timestamp:{datetime.now()}
    Port: {port}
    Transport: {transport}
    Product: {product}
    Organisation:{org}
    Org_ID: {org_id}
    Host_ID: {host_id}
    Vendor ID: {vendor_id}
    Shodan Module: {shodan_module}
    Vulns: {vulns}

    ''')
    write_log_file(log_string)
    service_id = None


def import_yelp_data():
    # search the yelp_hosts table ip_str to see if it's in the hosts table.
    # if it's not, do a shodan search on it with the search() function
    hosts = session.query(YelpHosts).all()
    for row in hosts:
        ip_check = session.query(Hosts).filter(
            Hosts.ip_str == row.ip_str).one_or_none()
        if ip_check is None:
            # use search function, grab new host ID & org ID, pass it back
            # into the yelp_host and yelp_org table
            print(row.ip_str)
        else:
            print('else')


# Queries all ip_str's in hosts table, returns results
def host_search_query():
    shodan_hosts = session.query(Hosts).all()
    return shodan_hosts
