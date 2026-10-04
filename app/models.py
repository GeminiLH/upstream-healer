"""
SQLAlchemy models for database tables.
These models are used by Alembic for schema migrations.
"""

from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Host(Base):
    __tablename__ = 'hosts'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    mac_address = Column(String, nullable=False)

class Subnet(Base):
    __tablename__ = 'subnets'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)