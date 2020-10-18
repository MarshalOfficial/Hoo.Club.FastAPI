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


def callProcedure(procname, data, dbname):
    dir = '%s/secret.json' % (os.path.dirname(__file__))
    with open(dir) as json_file:
        secret = json.load(json_file)

    finaleSrv = ''
    finaleDB = ''
    finaleUsr = ''
    finalPass = ''

    if dbname == 'hoo':
        finaleSrv = secret['hooserver']
        finaleDB = secret['hoodb']
        finaleUsr = secret['hoousername']
        finalPass = secret['hoopassword']
    elif dbname == 'gms':
        finaleSrv = secret['gmsserver']
        finaleDB = secret['gmsdb']
        finaleUsr = secret['gmsusername']
        finalPass = secret['gmspassword']
    elif dbname == 'coinbit':
        finaleSrv = secret['coinserver']
        finaleDB = secret['coindb']
        finaleUsr = secret['coinusername']
        finalPass = secret['coinpassword']
    elif dbname == 'torder':
        finaleSrv = secret['torderserver']
        finaleDB = secret['torderdb']
        finaleUsr = secret['torderusername']
        finalPass = secret['torderpassword']

    # on windows os use below connection string
    # params = urllib.parse.quote_plus(
    #     'DRIVER={SQL Server Native Client 11.0};SERVER=%s;DATABASE=%s;UID=%s;PWD=%s' % (secret['server'], secret['db'], secret['username'], secret['password']))
    # db = create_engine("mssql+pyodbc:///?odbc_connect=%s" % params)

    # on Linux os use below connection string
    db = create_engine("mssql+pyodbc://%s:%s@%s/%s?driver=ODBC+Driver+17+for+SQL+Server" %
                       (finaleUsr, finalPass, finaleSrv, finaleDB))

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
    StaffID: int


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

# app = FastAPI(docs_url=None)
app = FastAPI()

origins = []

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


def get_user(username: str, dbname: str):
    result = callProcedure('UserGet', '{"username":"%s"}' % username, dbname)
    return json.loads(result)[0]


def authenticate_user(username: str, password: str, dbname: str):
    user = get_user(username, dbname)
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


def get_current_user_bytoken(token: str, dbname: str):
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
    user = get_user(username=token_data.username, dbname=dbname)
    if user is None:
        raise credentials_exception
    return user


@app.get("/")
async def get():
    return ('Marshal Backend Server')

#HOO##################################


async def get_current_user_hoo(token: str = Depends(oauth2_scheme)):
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
    user = get_user(username=token_data.username, dbname="hoo")
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user_hoo(current_user: User = Depends(get_current_user_hoo)):
    # user_id = current_user.get("ID", None)
    if not current_user:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token_hoo(tokenEntity: TokenEntity):
    dir = '%s/secret.json' % (os.path.dirname(__file__))
    with open(dir) as json_file:
        secret = json.load(json_file)

    user = authenticate_user(tokenEntity.username, tokenEntity.password, "hoo")
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
            "MemberID": user.get("MemberID", None), "StaffID": user.get("StaffID", None)}


@app.post("/UserInfoByToken", response_model=Token)
async def login_for_access_token_userinfo(token: str):
    user = get_current_user_bytoken(token, "hoo")

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"access_token": token, "token_type": "bearer", "UserID": user.get("UserID", None),
            "UserName": user.get("UserName", ""), "IsActive": user.get("IsActive", None),
            "FirstName": user.get("FirstName", ""), "LastName": user.get("LastName", ""),
            "MemberID": user.get("MemberID", None), "StaffID": user.get("StaffID", None)}


@app.post("/SsCZC7hJxulnQ4l")
async def SsCZC7hJxulnQ4l_hoo(token: str, textstr: str):
    user = get_current_user_bytoken(token, "hoo")

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    newpwd = get_password_hash(textstr)
    return callProcedure("UserResetPwd", '{"ID":"%s","pwd":"%s"}' % (str(user.get("UserID", None)), newpwd), "hoo")


@app.post("/BackendEngine/")
async def BackendEngine_hoo(procname: str, params: str, current_user: User = Depends(get_current_active_user_hoo)):
    return callProcedure(procname, params, "hoo")


@app.post("/BackendEngineBody/")
async def BackendEngineBody_hoo(backendEntity: BackendEntity, current_user: User = Depends(get_current_active_user_hoo)):
    return callProcedure(backendEntity.procname, backendEntity.params, "hoo")

#######################################


#GMS###################################

async def get_current_user_gms(token: str = Depends(oauth2_scheme)):
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
    user = get_user(username=token_data.username, dbname="gms")
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user_gms(current_user: User = Depends(get_current_user_gms)):
    # user_id = current_user.get("ID", None)
    if not current_user:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/gms/token", response_model=Token)
async def login_for_access_token_gms(tokenEntity: TokenEntity):
    dir = '%s/secret.json' % (os.path.dirname(__file__))
    with open(dir) as json_file:
        secret = json.load(json_file)

    user = authenticate_user(tokenEntity.username, tokenEntity.password, "gms")
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
            "MemberID": user.get("MemberID", None), "StaffID": user.get("StaffID", None)}


@app.post("/gms/SsCZC7hJxulnQ4l")
async def SsCZC7hJxulnQ4l_gms(token: str, textstr: str):
    user = get_current_user_bytoken(token, "gms")

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    newpwd = get_password_hash(textstr)
    return callProcedure("UserResetPwd", '{"ID":"%s","pwd":"%s"}' % (str(user.get("UserID", None)), newpwd), "gms")


@app.post("/gms/BackendEngine/")
async def BackendEngine_gms(procname: str, params: str, current_user: User = Depends(get_current_active_user_gms)):
    return callProcedure(procname, params, "gms")


@app.post("/gms/BackendEngineBody/")
async def BackendEngineBody_gms(backendEntity: BackendEntity, current_user: User = Depends(get_current_active_user_gms)):
    return callProcedure(backendEntity.procname, backendEntity.params, "gms")

#######################################


#COINBIT###############################

async def get_current_user_coinbit(token: str = Depends(oauth2_scheme)):
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
    user = get_user(username=token_data.username, dbname="coinbit")
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user_coinbit(current_user: User = Depends(get_current_user_coinbit)):
    # user_id = current_user.get("ID", None)
    if not current_user:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/coinbit/token", response_model=Token)
async def login_for_access_token_coinbit(tokenEntity: TokenEntity):
    dir = '%s/secret.json' % (os.path.dirname(__file__))
    with open(dir) as json_file:
        secret = json.load(json_file)

    user = authenticate_user(tokenEntity.username,
                             tokenEntity.password, "coinbit")
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
            "MemberID": user.get("MemberID", None), "StaffID": user.get("StaffID", None)}


@app.post("/coinbit/SsCZC7hJxulnQ4l")
async def SsCZC7hJxulnQ4l_coinbit(token: str, textstr: str):
    user = get_current_user_bytoken(token, "coinbit")

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    newpwd = get_password_hash(textstr)
    return callProcedure("UserResetPwd", '{"ID":"%s","pwd":"%s"}' % (str(user.get("UserID", None)), newpwd), "coinbit")


@app.post("/coinbit/BackendEngine/")
async def BackendEngine_cointbit(procname: str, params: str, current_user: User = Depends(get_current_active_user_coinbit)):
    return callProcedure(procname, params, "coinbit")


@app.post("/coinbit/BackendEngineBody/")
async def BackendEngineBody_coinbit(backendEntity: BackendEntity, current_user: User = Depends(get_current_active_user_coinbit)):
    return callProcedure(backendEntity.procname, backendEntity.params, "coinbit")


@app.get("/coinbit/e71234d056b056c794a321e54fffc92f/")
async def BackendEngine_coinbit_get_crypto_price(getall: int):
    return callProcedure('CryptoPriceGet', getall, "coinbit")


@app.get("/coinbit/fgttzibz7hdn8c63798u7n3cahxdvbvh/")
async def BackendEngine_coinbit_get_gold_price():
    return callProcedure('GoldPriceGet', '', "coinbit")


@app.get("/coinbit/v2wyy3v9ptdrv27uqug2phxaqhggbwdx/")
async def BackendEngine_coinbit_get_curreny_price():
    return callProcedure('CurrencyPriceGet', '', "coinbit")


#######################################


#TORDER################################

@app.post("/torder/BackendEngine/")
async def BackendEngine_torder(procname: str, params: str):
    return callProcedure(procname, params, "torder")


@app.post("/torder/BackendEngineBody/")
async def BackendEngineBody_torder(backendEntity: BackendEntity):
    return callProcedure(backendEntity.procname, backendEntity.params, "torder")

#######################################
