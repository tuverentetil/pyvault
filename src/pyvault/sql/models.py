from sqlalchemy import Boolean, Column,Integer, String, DateTime
# from sqlalchemy.orm import relationship
from pyvault.sql.database import Base

class User(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True, unique=True, index=True)
    email = Column(String)
    full_name = Column(String)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    scopes = Column(String, default="login")
    last_login = Column(DateTime, default=None)

class Identity(Base):
    __tablename__ = 'identities'
    id = Column(Integer, index=True, primary_key=True)
    name = Column(String, index=True)
    password = Column(String)
    last_updated = Column(DateTime)
    version = Column(Integer)
    updated_by = Column(String)
