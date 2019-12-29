from sqlalchemy import create_engine, Table, Column, Integer, String, ForeignKey, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

engine = create_engine('sqlite:///test2.db', echo=True)
meta = MetaData()
Base = declarative_base()
Session = sessionmaker(bind = engine)
session = Session()


class Organisation(Base):
    __tablename__ = 'organisation'

    id = Column(Integer, primary_key=True)
    name = Column(String)

class Hosts(Base):
    __tablename__ = 'hosts'

    id = Column(Integer, primary_key=True)
    ip_str = Column(String)
    hostname = Column(String)
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
    domain = Column(String)
    data = Column(String)
    created = Column(String)
    modified = Column(String)
    vendor_id = Column(String)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)

class Vulns(Base):
    __tablename__ = 'vulns'

    id = Column(Integer, primary_key=True)
    cve = Column(String)
    description = Column(String)
    reference = Column(String)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False)

Base.metadata.create_all(engine)