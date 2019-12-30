from sqlalchemy import create_engine, Table, Column, Integer, String, ForeignKey, MetaData, select
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import shodan
from time import sleep



engine = create_engine('sqlite:///test2.db')
meta = MetaData()
Base = declarative_base()
Session = sessionmaker(bind = engine)
session = Session()

api = shodan.Shodan("95vvRQj3igAqbCNSpdHMjHC6MlvB1hJD")

ipFile = open('ipFile', 'r')

#check for org helper method
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
    vendor_id = Column(String)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    organisation_id = Column(Integer, ForeignKey("organisation.id"), nullable=False)

class Vulns(Base):
    __tablename__ = 'vulns'

    id = Column(Integer, primary_key=True)
    cve = Column(String)
    description = Column(String)
    reference = Column(String)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False)
    organisation_id = Column(Integer, ForeignKey("organisation.id"), nullable=False)

Base.metadata.create_all(engine)

exclude_http_title = ["Document Moved", "Bad Request", "Home Loading Page", "webserver",
                      "400 Bad Request !!!", "400 Bad Request", "400 The plain HTTP request was sent to HTTPS port",
                      "401 Unauthorized", "Error 401 - Unauthorized", "401 Authorization Required",
                      "403 - Forbidden: Access is denied.", "403 Interdit", "403 Verboden", "403 Forbidden", "Document Error: Page not found",
                       "404 Not found", "404 Not Found", "404 - Not Found",
                       "500 Internal Server Error",
                       "302 Found", "301 Moved Permanently", "307 Temporary Redirect",
                       "Protected Object", "Object moved", "Not Found", "Web managerment Home",
                       "The page is not found", "Unauthorized", "Index", "Object Not Found",
                       "Document Error: Unauthorized", "Service Unavailable", "Invalid Request",
                       "You are not authorized to view this page", "Not Found", "Index of .", "Index page",
                       "ERROR: The requested URL could not be retrieved", "Moved", "Nothing to see here!",
                       "Site under construction", "Untitled Document", "User access verification."
                      "Error response", "Home Loading Page", "Inloggen", "Login", "index", "Web Client"]

# Convert Shodan returned record to a cleaned construct
def convert_shodan_record(item):
    timestamp = item["timestamp"]
    port = item.get("port", 0)
    transport = item.get("transport", "n/a")
    product = item.get("product", "n/a")
    devicetype = item.get("device_type", "n/a")
    vendorid = item.get("vendor_id", "n/a")
    data = item.get("data", "")
    shodan_meta = item.get("_shodan")
    shodanmodule = shodan_meta.get("module", "n/a")

    # Can we extract info based on the module used by Shodan?
    if shodanmodule and data:
        if shodanmodule == "bacnet":
            data_s = data.split("\n")
            for el in data_s:
                if "Vendor Name" in el:
                    if vendorid == "n/a":
                        vendorid = el[len("Vendor Name") + 2:]
                elif "Model Name" in el:
                    if product == "n/a":
                        product = el[len("Model Name") + 2:]

        elif (shodanmodule == "http-simple-new" or shodanmodule == "http"
              or shodanmodule == "http-simple" or shodanmodule == "http-check"):
            product = "http"
            title = item.get("title", "n/a")
            if title != "n/a" and title not in exclude_http_title:
                product = title

        elif shodanmodule == "telnet":
            data_s = data.split("\n")
            if product == "n/a":
                try:
                    product = data_s[2]
                except:
                    pass

        elif shodanmodule == "rtsp-tcp":
            data_s = data.split("\n")
            for el in data_s:
                if "Server: " in el:
                    if product == "n/a":
                        product = el[len("Server") + 2:]

        elif shodanmodule == "s7":
            data_s = data.split("\n")
            for el in data_s:
                if "Copyright" in el:
                    if vendorid == "n/a":
                        vendorid = el[len("Copyright") + 2:]
                elif "Module type" in el:
                    if product == "n/a":
                        product = el[len("Module type") + 2:]

    # Clean up unwanted strings from product, vendor and devicetype
    product = product.strip("/\n,/\r").replace("&nbsp;", " ").strip()
    vendorid = vendorid.strip("/\n,/\r").replace("&nbsp;", " ").strip()
    devicetype = devicetype.strip("/\n,/\r").replace("&nbsp;", " ").strip()

    return {"timestamp": timestamp,
            "port": port,
            "transport": transport,
            "product": product,
            "devicetype": devicetype,
            "vendorid": vendorid,
            "shodanmodule": shodanmodule,
                "data": data
            }

def checkOrgID(org):
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

def checkHostID(ip_str, result, org, org_id):
    
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

def search(ipFile):

    for line in ipFile:

        result = api.host(line)
        
        org = result.get("org", "n/a")
        org_id = checkOrgID(org)

        ip_str = result["ip_str"]
        host_id = checkHostID(ip_str, result, org, org_id)

        hostname_res = result.get("hostnames", "n/a")
        try:
            domains = result["domains"]
            domain = domains[0]
        except:
            domain = ""
        if len(hostname_res) > 0:
            hostname = hostname_res[0]
        else:
            hostname = "n/a"
        if hostname is None or hostname == "":
            hostname = "n/a"

        for item in result["data"]:
            shodan_data = convert_shodan_record(item)


        vulns = result.get("vulns", "n/a")




search(ipFile)