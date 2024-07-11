from passlib.context import CryptContext
from typing import Annotated
from fastapi import Depends, status
from sqlmodel import Session, select
from fastapi_todoapp1.db import get_Session
from fastapi_todoapp1.models import TokenData, User,TokenRefresh
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException

SECRET_KEY = '535bb90d2f79d48718dce4c8e2db61968326a33eb7d2a3547bdee477f87a06b0'
ALGORITHYM = "HS256"
EXPIRY_TIME = 30


oauth_scheme = OAuth2PasswordBearer(tokenUrl="/token")
pwd_context = CryptContext(schemes="bcrypt")


def hash_password(password):
    return pwd_context.hash(password)


def verify_password(password, hash_password):
    return pwd_context.verify(password, hash_password)


def get_user_from_db(session: Annotated[Session, Depends(get_Session)], username: str | None = None,  email: str | None = None):
    statment = select(User).where(
        (User.username == username) | (User.email == email))
    user = session.exec(statment).first()
    print(user)
    if not user:
        statement = select(User).where(User.email == email)
        user = session.exec(statement).first()
        if user:
            return user

    return user


def authenticate_user(session: Annotated[Session, Depends(get_Session)], username: str, password: str):
    db_user = get_user_from_db(session=session, username=username)
    if not db_user:
        return False
    if not verify_password(password=password, hash_password=db_user.password):
        return False

    return db_user


def create_access_token(data: dict, expiry_time: timedelta | None,):
    data_to_encode = data.copy()
    if expiry_time:
        expire = datetime.now(timezone.utc) + expiry_time
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    data_to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(data_to_encode, SECRET_KEY, algorithm=ALGORITHYM)

    return encoded_jwt


def current_user(token: Annotated[str, Depends(oauth_scheme)], session: Annotated[Session, Depends(get_Session)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token, please log in.",
        headers={"www-Authenticate": "Bearer"}
    ) 
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHYM])
        username: str| None = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user_from_db(session,username= token_data.username)
    if not user:
        raise credentials_exception
    return user









def create_refresh_token(data: dict, expiry_time: timedelta | None,):
    data_to_encode = data.copy()
    if expiry_time:
        expire = datetime.now(timezone.utc) + expiry_time
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    data_to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(data_to_encode, SECRET_KEY, algorithm=ALGORITHYM)

    return encoded_jwt

def validate_refresh_token(token:str,session:Annotated[Session,Depends(get_Session)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token, please log in.",
        headers={"www-Authenticate": "Bearer"}
    ) 
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHYM])
        email: str| None = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenRefresh(email=email)
    except:
        raise JWTError
    user = get_user_from_db(session,email = token_data.email)
    if not user:
        raise credentials_exception
    return user
