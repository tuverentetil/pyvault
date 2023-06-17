from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List
from datetime import datetime
from passlib.context import CryptContext
from pyvault.sql import models, schemas

def hash_pwd(password: str) -> str:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context.hash(password)

def get_user(db: Session, user_name: str) -> schemas.User:
    user = db.query(models.User).filter(models.User.username == user_name).first()
    user.last_login = datetime.now()
    db.commit()
    db.refresh(user)
    return user

def get_users(db: Session, limit: int = 100) -> List[schemas.User]:
    return db.query(models.User).limit(limit).all()

def create_user(db: Session, user: schemas.UserCreate):
    db_user = models.User(username=user.username, full_name=user.full_name, hashed_password=hash_pwd(user.password), email=user.email, scopes=user.scopes)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return schemas.User(**db_user.__dict__)

def update_user(db: Session, user: str, body: schemas.UserUpdate):
    db_user = db.query(models.User).filter(models.User.username == user).first()
    db_user.hashed_password = hash_pwd(body.password) if body.password is not None else user.hashed_password
    db_user.email = body.email if body.email is not None else db_user.email
    db_user.full_name = body.full_name if body.full_name is not None else db_user.full_name
    db_user.scopes = body.scopes if body.scopes is not None else db_user.scopes
    db.commit()
    db.refresh(db_user)
    return schemas.User(**db_user.__dict__)

def remove_user(db: Session, user_name: str):
    user = db.query(models.User).filter(models.User.username == user_name).first()
    db.delete(user)
    db.commit()
    return True

def reset_user_password(db: Session, username: str, password: str):
    user = db.query(models.User).filter(models.User.username == username).one()
    user.hashed_password = hash_pwd(password)
    db.commit()
    return True

def list_identities(db: Session, limit: int = 100):
    return [ schemas.IdentityBase(**i.__dict__) for i in db.query(models.Identity).limit(limit).distinct()]

# def update_user(db: Session, user: schemas.UserCreate):
def create_identity(db: Session, identity: schemas.IdentityCreate, username: str):
    latest = db.query(models.Identity).filter(models.Identity.name == identity.name).order_by(desc(models.Identity.version)).first()
    ver = latest.version + 1 if latest else 0
    # identity.password = chacha(key=chacha_key, nounce=chacha_server,identity)
    db_identity = models.Identity(**identity.dict(), updated_by=username, last_updated=datetime.now(), version=ver)
    db.add(db_identity)
    db.commit()
    db.refresh(db_identity)
    return schemas.IdentityBase(**db_identity.__dict__)

def remove_identity(db: Session, name: str):
    scrape = db.query(models.Identity).filter(models.Identity.name == name).all()
    for identity in scrape:
        db.delete(identity)
    db.commit()

def get_identity(db: Session, name: str):
    #order by desc by version so we get latest identity
    identity = db.query(models.Identity).filter(models.Identity.name == name).order_by(desc(models.Identity.version)).first()
    return identity

def get_identity_by_version(db: Session, name: str, version: int):
    identity = db.query(models.Identity).filter(models.Identity.name == name).filter(models.Identity.version == version).first()
    return identity

def unlock_user(db: Session, user_name: str) -> None:
    user = db.query(models.User).filter(models.User.username == user_name).one()
    user.is_active = True
    db.commit()

def lock_user(db: Session, user_name: str) -> None:
    user = db.query(models.User).filter(models.User.username == user_name).one()
    user.is_active = False
    db.commit()