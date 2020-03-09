from sqlalchemy import create_engine, Table, Column, Integer, String, ForeignKey, MetaData, select, exc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime

engine = create_engine('sqlite:///QueryTool.db')
meta = MetaData()
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

logFile = open('log.txt', 'a')
logged = False


def log_check():
    if logged == True:
        print('Entries have been added to log.txt')


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


def query_input():
    con = engine.connect()

    while True:
        query = input(
            '\nType your Query Below to exit type \'exit\' \n').upper()

        if 'UPDATE' in query or 'DELETE' in query or 'INSERT' in query or 'CREATE DATABASE' in query \
            or 'CREATE TABLE' in query or 'ALTER DATABASE' in query or 'DROP TABLE' in query  \
                or 'ALTER TABLE' in query or 'CREATE INDEX' in query or 'DROP INDEX' in query:
            print('You may only write select statements')

        elif query == 'EXIT':
            exit()

        else:
            try:
                rs = con.execute(query)
                for row in rs:
                    print(row)
            except exc.OperationalError:
                print('\nInvalid Query')


def yelp_organisation_data(site_name, site_url, yelp_url):
    check_site_name = session.query(YelpOrganisation).filter(
        YelpOrganisation.site_name == site_name).one_or_none()

    if check_site_name is None:
        insert_yelp_organisation = YelpOrganisation(
            site_name=site_name, site_url=site_url, yelp_url=yelp_url)
        session.add(insert_yelp_organisation)
        session.commit()

        yelp_organisation_id = insert_yelp_organisation.id
        return yelp_organisation_id
    else:
        yelp_organisation_id = check_site_name.id
        return yelp_organisation_id


def check_yelp_url(yelp_url):
    check_url = session.query(YelpOrganisation).filter(
        YelpOrganisation.yelp_url == yelp_url).one_or_none()

    if check_url is None:
        return None
    else:
        yelp_organisation_id = check_url.id
        return yelp_organisation_id


def yelp_host_data(ip_str, yelp_organisation_id):
    check_ip_str = session.query(YelpHosts).filter(
        YelpHosts.ip_str == ip_str).one_or_none()

    if check_ip_str is None:
        insert_yelp_hosts = YelpHosts(
            ip_str=ip_str, yelp_organisation_id=yelp_organisation_id)
        session.add(insert_yelp_hosts)
        session.commit()

        yelp_host_id = insert_yelp_hosts.id
    else:
        yelp_host_id = check_ip_str.id
        return yelp_host_id


def yelp_to_shodan():
    from shodan_search import search

    yelp_gather = session.query(YelpHosts)
    
    for row in yelp_gather:
        ip_str = row.ip_str
        yelp_organisation_id = row.yelp_organisation_id
        yelp_host_id = row.id
        
        search(ip_str)
    
        match_yelp_data = session.query(Hosts).filter(
            Hosts.ip_str == ip_str).one_or_none()

        if match_yelp_data:
            host_id = match_yelp_data.id
            org_id = match_yelp_data.organisation_id

            session.query(YelpOrganisation).filter(
                YelpOrganisation.id == yelp_organisation_id).update({'organisation_id': org_id})

            session.query(YelpHosts).filter(YelpHosts.id == yelp_host_id).update(
                {'organisation_id': org_id, 'host_id': host_id})
            session.commit()
        else:
            pass


def check_org(org):
    orgIDResult = session.query(Organisation).filter(
        Organisation.name == org).one_or_none()

    if orgIDResult is None:
        insOrg = Organisation(name=org)

        session.add(insOrg)
        session.commit()

        org_id = insOrg.id

        return org_id
    else:
        org_id = orgIDResult.id
        return org_id


def check_host(ip_str, result, org, org_id):
    hostIDResult = session.query(Hosts).filter(
        Hosts.ip_str == ip_str).one_or_none()

    # if the ip exists in the hosts table, grab the ID, if not then enter data as usual
    if hostIDResult is None:
        asn = result.get("asn", "n/a")
        resultLocation = result['location']
        city = resultLocation.get("city", "n/a")
        country_code = resultLocation.get("country_code", "n/a")

        insHosts = Hosts(ip_str=ip_str, asn=asn,
                         country_code=country_code, city=city, organisation_id=org_id)
        session.add(insHosts)
        session.commit()

        host_id = insHosts.id
        return host_id
    else:
        host_id = hostIDResult.id
        return host_id


def check_service(result, org_id, host_id, org):
    global logged
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
    except:
        domain = ""

    hostname_res = result.get("hostnames", "n/a")
    if len(hostname_res) > 0:
        hostname = hostname_res[0]
    else:
        hostname = "n/a"
    if hostname is None or hostname == "":
        hostname = "n/a"

    # Clean up unwanted strings from product and vendor
    product = product.strip("/\n,/\r").replace("&nbsp;", " ").strip()
    vendor_id = vendor_id.strip("/\n,/\r").replace("&nbsp;", " ").strip()

    if shodan_id == None:
        logged = True
        logFile.write(f'\nShodan.ID Field is empty, the following data will not be inserted \nTimestamp: \
            {datetime.now()}\nPort: {port} \nTransport: {transport} \nProduct: {product} \nOrganisation:\
                 {org} \nOrg_ID: {org_id} \nHost_ID: {host_id} \nVendor ID: {vendor_id} \nShodan Module: \
                     {shodan_module} \nVulns: {vulns} \n')
        service_id = None
        return service_id

    shodanIDCheck = session.query(Services).filter(
        Services.shodan_id == shodan_id).one_or_none()

    if shodanIDCheck == None:
        modified = ("n/a")

        insService = Services(port=port, transport=transport, product=product,
                              shodan_module=shodan_module, hostname=hostname, domain=domain, data=data,
                              created=timestamp, modified=modified, shodan_id=shodan_id, vendor_id=vendor_id,
                              host_id=host_id, organisation_id=org_id)

        session.add(insService)
        session.commit()

        service_id = insService.id

        if vulns:
            for cve, v in vulns.items():
                cvss = v.get('cvss')
                summary = v.get('summary')

                reference = v.get('references')
                reference = ','.join(map(str, reference))

                veri = v.get('verified')
                if veri == False:
                    verified = 0
                elif veri == True:
                    verified = 1

                insVuls = Vulns(cve=cve, cvss=cvss, summary=summary, reference=reference,
                                verified=verified, organisation_id=org_id, host_id=host_id,
                                service_id=service_id)
                session.add(insVuls)
                session.commit()
        else:
            logFile.write('\nNo Vulns for for Service ID: ' +
                          str(service_id) + '\nTimestamp: ' + str(datetime.now()) + '\n')
            logged = True

    elif timestamp > shodanIDCheck.created:
        updService = Services(port=port, transport=transport, product=product,
                              shodan_module=shodan_module, hostname=hostname, domain=domain, data=data,
                              modified=timestamp, shodan_id=shodan_id, vendor_id=vendor_id)

        session.query(Services).update(updService)
        session.commit()
        service_id = updService.id

        logFile.write('Service ID: ' + str(service_id) +
                      ' has been updated' + '\nTimestamp: ' + str(datetime.now()))
        logged = True

    else:
        service_id = shodanIDCheck.id

    return service_id


def import_yelp_data():
    # search the yelp_hosts table ip_str to see if it's in the hosts table.
    # if it's not, do a shodan search on it with the search() function
    hosts = session.query(YelpHosts).all()
    for row in hosts:
        ip_check = session.query(Hosts).filter(
            Hosts.ip_str == row.ip_str).one_or_none()
        if ip_check is None:
            # use search function, grab new host ID & org ID, pass it back into the yelp_host and yelp_org table
            print('none')
        else:
            print('else')

#queryTest = session.query(Organisation).get(1)

# Test to delete an Organisation along with all its entries
# session.delete(queryTest)
# session.commit()

# Accessing row data via the ORM
# for row in queryTest.hosts:
#    print (row.id)
# for row in queryTest.services:
#    print (row.__dict__)
# for row in queryTest.vulns:
#    print (row.__dict__)