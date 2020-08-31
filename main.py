from datetime import date, datetime, timedelta
import datetime
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

import json
import pyodbc
from sqlalchemy import create_engine
import urllib
import os


def myconverter(o):
    if isinstance(o, datetime.datetime):
        return o.isoformat()
    if isinstance(o, date):
        return o.isoformat()


def callProcedure(procname, data):
    dir = '%s/secret.json' % (os.path.dirname(__file__))
    with open(dir) as json_file:
        secret = json.load(json_file)

    # on windows os use below connection string
    # params = urllib.parse.quote_plus(
    #     'DRIVER={SQL Server Native Client 11.0};SERVER=%s;DATABASE=%s;UID=%s;PWD=%s' % (secret['server'], secret['db'], secret['username'], secret['password']))
    # db = create_engine("mssql+pyodbc:///?odbc_connect=%s" % params)

    # on Linux os use below connection string
    db = create_engine("mssql+pyodbc://%s:%s@%s/%s?driver=ODBC+Driver+17+for+SQL+Server" %
                       (secret['username'], secret['password'], secret['server'], secret['db']))

    connection = db.raw_connection()

    try:
        print("start calling " + procname)
        cursor = connection.cursor()
        sql = """{ CALL [dbo].[ProcEngine] (@proc=?,@data=?) }"""
        params = (procname, data)

        cursor = cursor.execute(sql, params)
        dt = cursor.fetchall()
        # print(dt)
        columns = [column[0] for column in cursor.description]
        # print(columns)
        results = []
        for row in dt:
            results.append(dict(zip(columns, row)))
        cursor.close()
        connection.commit()
        # print(results)
        jret = json.dumps(results, default=myconverter,
                          ensure_ascii=False).encode('utf8')
        # print(jret)
        return jret
    except Exception as e:
        errstr = "DB Call Proc Error!", e, "occurred."
        print(errstr)
        return None
    finally:
        connection.close()


class Token(BaseModel):
    access_token: str
    token_type: str
    UserID: int
    UserName: str
    IsActive: bool
    FirstName: str
    LastName: str
    MemberID: int


class BackendEntity(BaseModel):
    procname: str
    params: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str
    id: int
    result: str
    isactive: bool
    isdeleted: bool
    createdate: str
    updatedate: str


class TokenEntity(BaseModel):
    username: str
    password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(docs_url=None)

origins = [
    "http://localhost:5800",
    "http://app.hoo.club:5800",
    "https://app.hoo.club:5800",
    "http://app.hoo.club",
    "https://app.hoo.club",
    "http://marshalbackend.com",
    "https://marshalbackend.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],  # origins
    allow_credentials=True,  # True
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# testpw = pwd_context.encrypt(password) will be used for create a new user
def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    result = callProcedure('UserGet', '{"username":"%s"}' % username)
    return json.loads(result)[0]


def authenticate_user(username: str, password: str):
    user = get_user(username)
    user_password = user.get("Password", None)
    if not verify_password(password, user_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    dir = '%s/secret.json' % (os.path.dirname(__file__))
    with open(dir) as json_file:
        secret = json.load(json_file)

    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})

    # print(to_encode)

    # use openssl rand -hex32 to generate a 32 character token for urself and put it in secret json file to use it here
    encoded_jwt = jwt.encode(
        to_encode, secret['secretkey'], algorithm=secret['ALGORITHM'])
    # print('original jwt :' + encoded_jwt)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    dir = '%s/secret.json' % (os.path.dirname(__file__))
    with open(dir) as json_file:
        secret = json.load(json_file)

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        jwt_options = {
            'verify_signature': False,
            'verify_exp': True,
            'verify_nbf': False,
            'verify_iat': True,
            'verify_aud': False
        }
        payload = jwt.decode(token, secret["secretkey"], algorithms=[
                             secret['ALGORITHM']],
                             options=jwt_options)

        username: str = payload.get("sub")

        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError as e:
        print('jwt decode error:' + str(e))
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    # user_id = current_user.get("ID", None)
    if not current_user:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.get("/")
async def get():
    return ('Marshal Backend Server: Hoo')

# @app.get("/favicon.ico")
# async def geticon():
#     dir = '%s/favicon.ico' % (os.path.dirname(__file__))
#     return (open(dir,"wb") )


@app.post("/token", response_model=Token)
async def login_for_access_token(tokenEntity: TokenEntity):
    dir = '%s/secret.json' % (os.path.dirname(__file__))
    with open(dir) as json_file:
        secret = json.load(json_file)

    user = authenticate_user(tokenEntity.username, tokenEntity.password)
    # user_id = user.get("ID", None)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # print(user)
    access_token_expires = timedelta(
        minutes=int(secret['ACCESS_TOKEN_EXPIRE_MINUTES']))
    access_token = create_access_token(
        data={"sub": user.get("UserName", None)}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "UserID": user.get("UserID", None),
            "UserName": user.get("UserName", ""), "IsActive": user.get("IsActive", None),
            "FirstName": user.get("FirstName", ""), "LastName": user.get("LastName", ""),
            "MemberID": user.get("MemberID", None)}


# parameters in the header
@app.post("/BackendEngine/")
async def read_own_test(procname: str, params: str, current_user: User = Depends(get_current_active_user)):
    return callProcedure(procname, params)

# parameters in the body
# @app.post("/BackendEngine/")
# async def read_own_test(backendEntity: BackendEntity, current_user: User = Depends(get_current_active_user)):
#     return callProcedure(backendEntity.procname, backendEntity.params)


# development mode
# @app.post("/BackendEngine1/")
# async def read_own_test1(procname: str, params: str):
#     return callProcedure(procname, params)
