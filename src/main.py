from datetime import datetime, timedelta
from pyvault.lib.token import TokenData, Token, TokenDecoded
# from pyvault.lib.identity import IdentitiesList, Identity
from typing import Union, List
from pydantic import ValidationError

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing_extensions import Annotated
from sqlalchemy.orm import Session
from pyvault.sql import crud, models, schemas
from pyvault.sql.database import SessionLocal, engine
# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "288dcb38d72350f476470dc895fdb5b14b1b4bf08c8e53400ab82717ae0d6440"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={"write": "Add/Modify identity", "read": "Read identity.", "admin": "Manage users", "login": "Ability to log in"},
)

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str)-> schemas.User:
    db_user = crud.get_user(db, user_name=username)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db)
):
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=username)
    except (JWTError, ValidationError):
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user


async def get_current_active_user(
    current_user: Annotated[schemas.User, Security(get_current_user, scopes=["login"])]
):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# @app.post("/token", response_model=Token)
@app.post("/token", response_model=TokenDecoded, tags=["login"])
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    if user.scopes is None:
        raise HTTPException(status_code=401, detail="User is not in any scope")
    user.scopes = user.scopes.split()
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    #intersection will only allow comonalities to what user is allowed in DB and what he wanted in form
    #which means he can only limit the scopes from waht he has but not add additional ones
    scope = user.scopes
    if form_data.scopes:
        scope = list(set(user.scopes).intersection(form_data.scopes))
    access_token = create_access_token(
        data={"sub": user.username, "scopes": scope},
        expires_delta=access_token_expires,
    )
    # return {"access_token": access_token, "token_type": "bearer"}
    return {"access_token": access_token, "token_type": "bearer", "username": user.username, "scopes": scope}

@app.post("/identity/list", response_model=List[schemas.IdentityBase], tags=["identity"])
async def get_stored_identities(
    current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["read"])],
    db: Session = Depends(get_db)):
    #here add query the DB to get identeties
    return crud.list_identities(db)

@app.post("/identity/add", response_model=schemas.IdentityBase,tags=["identity"])
async def add_new_identity(
    identity: schemas.IdentityCreate, 
    current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["write"])],
    db: Session = Depends(get_db)):
    #encrypt password before storing to DB (possibly in pydantic model ?)
    identity = crud.create_identity(db, identity, current_user.username)
    return identity

@app.get("/identity/get/{identity}", response_model=Union[schemas.Identity,None], tags=["identity"])
async def get_identity(
    identity: str,
    current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["read"])],
    db: Session = Depends(get_db)):
    return crud.get_identity(db, identity)

@app.get("/identity/get/{identity}/{version}", response_model=Union[schemas.Identity,None], tags=["identity"])
async def get_identity_by_version(
    identity: str,
    version: int,
    current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["read"])],
    db: Session = Depends(get_db)):
    return crud.get_identity_by_version(db, name=identity, version=version)

@app.post("/identity/remove/{identity}", tags=["identity"])
async def update_identity(
    identity: str,
    current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["write","admin"])],
    db: Session = Depends(get_db)):
    identity = crud.remove_identity(db, identity)
    return identity

@app.post("/user/list", response_model=List[schemas.User], tags=["user"])
async def list_users(
    current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["admin"])],
    db: Session = Depends(get_db)):
    return crud.get_users(db)

@app.post("/user/add", response_model=schemas.User, tags=["user"])
async def add_new_user(
    user: schemas.UserCreate, 
    current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["admin"])],
    db: Session = Depends(get_db)):
    crud.create_user(db, user)
    return user

@app.get("/user/get/{user}", response_model=schemas.User, tags=["user"])
async def get_user_details(
    user: str, 
    current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["admin"])],
    db: Session = Depends(get_db)):
    user = get_user(db,user)
    return user

@app.post("/user/update/{user}", response_model=schemas.User, tags=["user"])
async def update_user_details(
    user: str,
    body: schemas.UserUpdate, 
    current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["admin"])],
    db: Session = Depends(get_db)):
    return crud.update_user(db, user, body)


@app.post("/user/reset_password", tags=["user"])
async def reset_user_password(
    current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["login"])],
    password: str,
    db: Session = Depends(get_db)):
    crud.reset_user_password(db, username=current_user.username, password=password)

@app.post("/user/unlock/{user}", tags=["user"])
async def unlock_user(
    user: str, 
    current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["admin"])],
    db: Session = Depends(get_db)):
    crud.unlock_user(db, user)

@app.post("/user/lock/{user}", tags=["user"])
async def lock_user(
    user: str, 
    current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["admin"])],
    db: Session = Depends(get_db)):
    crud.lock_user(db, user)

@app.post("/user/remove/{user}", tags=["user"])
async def lock_user(
    user: str, 
    current_user: Annotated[schemas.User, Security(get_current_active_user, scopes=["admin"])],
    db: Session = Depends(get_db)):
    return crud.remove_user(db, user)