from sqlalchemy import create_engine, Table, Column, Integer, String, ForeignKey, MetaData, select
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import shodan
from time import sleep
from datetime import datetime
import uuid

engine = create_engine('sqlite:///test2.db')
meta = MetaData()
Base = declarative_base()
Session = sessionmaker(bind = engine)
session = Session()

api = shodan.Shodan("95vvRQj3igAqbCNSpdHMjHC6MlvB1hJD")

ipFile = open('ipFile', 'r')

class Organisation(Base):
    __tablename__ = 'organisation'

    id = Column(Integer, primary_key=True)
    name = Column(String)

class Hosts(Base):
    __tablename__ = 'hosts'

    id = Column(Integer, primary_key=True)
    ip_str = Column(String)
    asn = Column(String)
    org = Column(String)
    country_code = Column(String)
    city = Column(String)
    organisation_id = Column(Integer, ForeignKey("organisation.id"), nullable=False)

class Services(Base):
    __tablename__ = 'services'

    id = Column(Integer, primary_key=True)
    port = Column(String)
    transport = Column(String)
    product = Column(String)
    device_type = Column(String)
    shodan_module = Column(String)
    hostname = Column(String)
    domain = Column(String)
    data = Column(String)
    created = Column(String)
    modified = Column(String)
    #needs indexing
    shodan_id = Column(String)
    vendor_id = Column(String)
    organisation_id = Column(Integer, ForeignKey("organisation.id"), nullable=False)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)

class Vulns(Base):
    __tablename__ = 'vulns'

    id = Column(Integer, primary_key=True)
    cve = Column(String)
    cvss = Column(Integer)
    summary = Column(String)
    reference = Column(String)
    verified = Column(Integer)
    organisation_id = Column(Integer, ForeignKey("organisation.id"), nullable=False)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False)
    
Base.metadata.create_all(engine)

def checkOrg(org):
    orgIDResult = session.query(Organisation).filter(Organisation.name == org).one_or_none()
    
    if orgIDResult is None:
        insOrg = Organisation(name = org)

        session.add(insOrg)
        session.commit()

        org_id = insOrg.id
        return org_id
    else:
        org_id = orgIDResult.id
        return org_id

def checkHost(ip_str, result, org, org_id):
    hostIDResult = session.query(Hosts).filter(Hosts.ip_str == ip_str).one_or_none()
        
    #if the ip exists in the hosts table, grab the ID, if not then enter data as usual
    if hostIDResult is None:
        asn = result.get("asn", "n/a")
        city = result.get("city", "n/a")
        country_code = result.get("country_code", "n/a")

        insHosts = Hosts(ip_str = ip_str, asn = asn, org = org_id, country_code = country_code, city = city, organisation_id = org_id)
        session.add(insHosts)
        session.commit()
        
        host_id = insHosts.id
        return host_id
    else:
        host_id = hostIDResult.id
        return host_id

def checkService(item, org_id, host_id):
    timestamp = item["timestamp"]
    port = item.get("port", 0)
    transport = item.get("transport", "n/a")
    product = item.get("product", "n/a")
    device_type = item.get("device_type", "n/a")
    vendor_id = item.get("vendor_id", "n/a")
    data = item.get("data", "")
    shodan_meta = item.get("_shodan")
    shodan_module = shodan_meta.get("module", "n/a")
    shodan_id = shodan_meta.get("id")
    vulns = item.get("vulns", None)
    
    try:
        domains = item["domains"]
        domain = domains[0]
    except:
        domain = ""

    hostname_res = item.get("hostnames", "n/a")
    if len(hostname_res) > 0:
        hostname = hostname_res[0]
    else:
        hostname = "n/a"
    if hostname is None or hostname == "":
        hostname = "n/a"

    # Clean up unwanted strings from product, vendor and device_type
    product = product.strip("/\n,/\r").replace("&nbsp;", " ").strip()
    vendor_id = vendor_id.strip("/\n,/\r").replace("&nbsp;", " ").strip()
    device_type = device_type.strip("/\n,/\r").replace("&nbsp;", " ").strip()
    
    if shodan_id == None:
        print (f'Shodan.ID Field is empty, the following data will not be inserted \n \
        Port: {port} \n Transport: {transport} \n Product: {product} \n Device Type: {device_type} \n \
        Vendor ID: {vendor_id} \n Shodan Module: {shodan_module} \n Vulns: {vulns} \n')
        service_id = None
        return service_id
    
    shodanIDCheck = session.query(Services).filter(Services.shodan_id == shodan_id).one_or_none()

    if shodanIDCheck == None:
        modified = ("n/a")

        insService = Services(port = port, transport = transport, product = product,\
            device_type = device_type, shodan_module = shodan_module, hostname = hostname,\
                domain = domain, data = data, created = timestamp, modified = modified, \
                    shodan_id = shodan_id,vendor_id = vendor_id, host_id = host_id, organisation_id = org_id)
        
        session.add(insService)
        session.commit()
        
        service_id = insService.id

        if vulns:
            for cve,v in vulns.items():
                cvss = v.get('cvss')
                summary = v.get('summary')

                reference = v.get('references')
                reference = ','.join(map(str, reference)) 
                
                veri = v.get('verified')
                if veri == False:
                    verified = 0
                elif veri == True:
                    verified = 1

                insVuls = Vulns(cve = cve, cvss = cvss, summary = summary, reference = reference,\
                    verified = verified, organisation_id = org_id, host_id = host_id, \
                        service_id = service_id)
                session.add(insVuls)
                session.commit()
    

        else:
            print ('No Vulns for for Service ID: ' + str(service_id))

    elif timestamp > shodanIDCheck.created:

        updService = Services(port = port, transport = transport, product = product,\
        device_type = device_type, shodan_module = shodan_module, hostname = hostname,\
            domain = domain, data = data,  modified = timestamp, \
                shodan_id = shodan_id, vendor_id = vendor_id)
        
        session.query(Services).update(updService)
        session.commit()
        service_id = updService.id

    else:
        service_id = shodanIDCheck.id

    return service_id

def search(ipFile):
    for line in ipFile:
        if 'city:' in line:
            result = api.search(line)
        else:
            result = api.host(line)
        
        org = result.get("org", "n/a")
        org_id = checkOrg(org)

        ip_str = result["ip_str"]
        host_id = checkHost(ip_str, result, org, org_id)

        for item in result["data"]:
            service_id = checkService(item, org_id, host_id)


search(ipFile)