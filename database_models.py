import os
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime

# Create database connection
DATABASE_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_URL)
Base = declarative_base()
Session = sessionmaker(bind=engine)

# Association table for many-to-many relationships
threat_actor_attribution = Table(
    'threat_actor_attribution',
    Base.metadata,
    Column('threat_actor_id', Integer, ForeignKey('threat_actors.id')),
    Column('attribution_source_id', Integer, ForeignKey('attribution_sources.id'))
)

threat_actor_techniques = Table(
    'threat_actor_techniques',
    Base.metadata,
    Column('threat_actor_id', Integer, ForeignKey('threat_actors.id')),
    Column('technique_id', Integer, ForeignKey('techniques.id'))
)

threat_actor_tools = Table(
    'threat_actor_tools',
    Base.metadata,
    Column('threat_actor_id', Integer, ForeignKey('threat_actors.id')),
    Column('tool_id', Integer, ForeignKey('tools.id'))
)

class ThreatActor(Base):
    """Threat actor model representing APT groups and other malicious actors"""
    __tablename__ = 'threat_actors'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    also_known_as = Column(Text)
    region = Column(String(100))
    active_since = Column(String(50))
    target_sectors = Column(Text)
    notable_attacks = Column(Text)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Relationships
    attributions = relationship("AttributionSource", secondary=threat_actor_attribution, back_populates="threat_actors")
    techniques = relationship("Technique", secondary=threat_actor_techniques, back_populates="threat_actors")
    tools = relationship("Tool", secondary=threat_actor_tools, back_populates="threat_actors")

class AttributionSource(Base):
    """Attribution sources model representing organizations tracking threat actors"""
    __tablename__ = 'attribution_sources'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    url = Column(String(255))
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Relationships
    threat_actors = relationship("ThreatActor", secondary=threat_actor_attribution, back_populates="attributions")

class Technique(Base):
    """Techniques used by threat actors, aligned with MITRE ATT&CK framework"""
    __tablename__ = 'techniques'
    
    id = Column(Integer, primary_key=True)
    technique_id = Column(String(20))  # MITRE ID (e.g., T1566)
    name = Column(String(255), nullable=False)
    tactic = Column(String(100))
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Relationships
    threat_actors = relationship("ThreatActor", secondary=threat_actor_techniques, back_populates="techniques")

class Tool(Base):
    """Tools and malware used by threat actors"""
    __tablename__ = 'tools'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    type = Column(String(100))  # Malware, RAT, Framework, etc.
    description = Column(Text)
    first_observed = Column(String(50))
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Relationships
    threat_actors = relationship("ThreatActor", secondary=threat_actor_tools, back_populates="tools")

class Attack(Base):
    """Cyber attack incidents"""
    __tablename__ = 'attacks'
    
    id = Column(Integer, primary_key=True)
    attack_type = Column(String(100))
    source_country = Column(String(100))
    target_country = Column(String(100))
    source_latitude = Column(Float, nullable=True)
    source_longitude = Column(Float, nullable=True)
    target_latitude = Column(Float, nullable=True)
    target_longitude = Column(Float, nullable=True)
    timestamp = Column(DateTime)
    severity = Column(String(50))
    data_source = Column(String(100))  # e.g., Kaspersky, Radware
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

# Create all tables in the database
def init_db():
    Base.metadata.create_all(engine)

if __name__ == "__main__":
    init_db()