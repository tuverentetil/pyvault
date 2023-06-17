from typing import Union, List
from datetime import datetime
from pydantic import BaseModel

class IdentityBase(BaseModel):
    name: str  

class IdentityCreate(IdentityBase):
    password: str

class Identity(IdentityCreate):
    last_updated: datetime
    version: int
    updated_by: str
    class Config:
        orm_mode = True

class UserBase(BaseModel):
    username: str
    email: Union[str,None]
    full_name: str
    scopes: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    last_login : Union[datetime, None]
    is_active: bool = True
    class Config:
        orm_mode = True

class UserUpdate(BaseModel):
    email: Union[str,None] = None
    full_name: Union[str,None] = None
    scopes: Union[str,None] = None
    password: Union[str,None] = None
    
