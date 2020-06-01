from sqlalchemy import create_engine, Table, Column, Integer, String,\
     ForeignKey, MetaData, select, exc
from sqlalchemy.ext.declarative import declarative_base
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


class Organisation(Base):
    __tablename__ = 'organisation'

    id = Column(Integer, primary_key=True)
    name = Column(String)

    hosts = relationship('Hosts', cascade='all, delete, delete-orphan')
    services = relationship('Services', cascade='all, delete, delete-orphan')
    vulns = relationship('Vulns', cascade='all, delete, delete-orphan')


class Hosts(Base):
    __tablename__ = 'hosts'

    id = Column(Integer, primary_key=True)
    ip_str = Column(String, nullable=False)
    asn = Column(String)
    country_code = Column(String)
    city = Column(String)
    organisation_id = Column(Integer, ForeignKey(
        "organisation.id"), nullable=False)


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


class YelpOrganisation(Base):
    __tablename__ = 'yelp_organisation'

    id = Column(Integer, primary_key=True)
    site_name = Column(String, nullable=False)
    site_url = Column(String, nullable=False)
    yelp_url = Column(String, nullable=False)
    organisation_id = Column(Integer, ForeignKey(
        "organisation.id"), nullable=True)


class YelpHosts(Base):
    __tablename__ = 'yelp_hosts'

    id = Column(Integer, primary_key=True)
    ip_str = Column(String, nullable=False)
    yelp_organisation_id = Column(Integer, ForeignKey(
        "yelp_organisation.id"), nullable=False)
    organisation_id = Column(Integer, ForeignKey(
        "organisation.id"), nullable=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)


Base.metadata.create_all(engine)
input_blacklist = ['UPDATE', 'DELETE', 'INSERT', 'CREATE DATABASE',
                   'CREATE TABLE', 'ALTER DATABASE', 'DROP TABLE',
                   'ALTER TABLE', 'CREATE INDEX', 'DROP INDEX']


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


def output_data(engine, query):
    try:
        out = pd.read_sql(query, con=engine)
        file_name = f"queries/{datetime.now().strftime('%d-%m_%H-%M-%S--%f')}\
            .csv".replace(" ", "")
        csv_out = out.to_csv(file_name, index=False)
        print(f'Output saved to: {file_name}')
    except exc.OperationalError:
        print('\nInvalid Query')


def yelp_check_org(site_name, site_url, yelp_url):
    check_site_name = session.query(YelpOrganisation).filter(
        YelpOrganisation.site_name == site_name).one_or_none()
    if check_site_name is None:
        yelp_insert_new_org(site_name, site_url, yelp_url)
    else:
        yelp_organisation_id = check_site_name.id
    return yelp_organisation_id


def yelp_insert_new_org(site_name, site_url, yelp_url):
    insert_yelp_organisation = YelpOrganisation(
        site_name=site_name, site_url=site_url, yelp_url=yelp_url)
    session.add(insert_yelp_organisation)
    session.commit()
    yelp_organisation_id = insert_yelp_organisation.id
    return yelp_organisation_id


def yelp_check_url(yelp_url):
    check_url = session.query(YelpOrganisation).filter(
        YelpOrganisation.yelp_url == yelp_url).one_or_none()
    if check_url is None:
        return None
    else:
        yelp_organisation_id = check_url.id
        return yelp_organisation_id


def yelp_check_host(ip_str, yelp_organisation_id):
    check_ip_str = session.query(YelpHosts).filter(
        YelpHosts.ip_str == ip_str).one_or_none()
    if check_ip_str is None:
        yelp_insert_new_host(ip_str, yelp_organisation_id)
    else:
        yelp_host_id = check_ip_str.id
    return yelp_host_id


def yelp_insert_new_host():
    insert_yelp_hosts = YelpHosts(
        ip_str=ip_str, yelp_organisation_id=yelp_organisation_id)
    session.add(insert_yelp_hosts)
    session.commit()
    yelp_host_id = insert_yelp_hosts.id
    return yelp_host_id


def yelp_to_shodan():
    from shodan_search import search
    yelp_gather = session.query(YelpHosts)
    for row in yelp_gather:
        ip_str = row.ip_str
        yelp_organisation_id = row.yelp_organisation_id
        yelp_host_id = row.id
        search(ip_str)
        link_yelp_ids(ip_str, yelp_organisation_id, yelp_host_id)


def link_yelp_ids():
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


def check_org(org):
    search_org = session.query(Organisation).filter(
        Organisation.name == org).one_or_none()
    if search_org is None:
        org_id = insert_new_org(org)
    else:
        org_id = search_org.id
    return org_id


def insert_new_org(org):
    insOrg = Organisation(name=org)
    session.add(insOrg)
    session.commit()
    org_id = insOrg.id
    return org_id


def check_host(ip_str, asn, city, country_code, org_id):
    hostIDResult = session.query(Hosts).filter(
        Hosts.ip_str == ip_str).one_or_none()
    if hostIDResult is None:
        host_id = insert_new_host(ip_str, asn, country_code, city, org_id)
    else:
        host_id = hostIDResult.id
    return host_id


def insert_new_host(ip_str, asn, country_code, city, org_id):
    insHosts = Hosts(
        ip_str=ip_str, asn=asn, country_code=country_code,
        city=city, organisation_id=org_id)
    session.add(insHosts)
    session.commit()
    host_id = insHosts.id
    return host_id


def check_service(
  port, transport, product, shodan_module, hostname, domain, data,
  timestamp, shodan_id, vendor_id, org_id, host_id, org):
    shodanIDCheck = session.query(Services).filter(
        Services.shodan_id == shodan_id).one_or_none()
    if shodanIDCheck is None:
        service_id = insert_new_service(
            port, transport, product, shodan_module, hostname, domain, data,
            timestamp, shodan_id, vendor_id, org_id, host_id, org)
    elif timestamp > shodanIDCheck.created:
        service_id = update_existing_service(
            port, transport, product, shodan_module, hostname, domain, data,
            timestamp, shodan_id, vendor_id)
    else:
        service_id = shodanIDCheck.id
    return service_id


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


def update_existing_service(
        port, transport, product, shodan_module, hostname, domain,
        data, timestamp, shodan_id, vendor_id):
    updService = Services(
            port=port, transport=transport, product=product,
            shodan_module=shodan_module, hostname=hostname, domain=domain,
            data=data, modified=timestamp, shodan_id=shodan_id,
            vendor_id=vendor_id)
    session.query(Services).update(updService)
    service_id = updService.id

    log_string = (f'''
    Service ID: {service_id} has been updated'
    Timestamp: {datetime.now()}''')
    write_log_file(log_string)
    return service_id


def insert_new_vulns(cve, cvss, summary, reference, verified):
    insVuls = Vulns(
      cve=cve, cvss=cvss, summary=summary, reference=reference,
      verified=verified, organisation_id=org_id, host_id=host_id,
      service_id=service_id)
    session.add(insVuls)
    session.commit()


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
    Vulns: {vulns}''')
    write_log_file(log_string)
    service_id = None
    return service_id


def log_no_vulns(service_id):
    log_string = (
        f'''
        No Vulns for for Service ID:{service_id}
        Timestamp: {datetime.now()}
        ''')
    write_log_file(log_string)


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


import_yelp_data()
