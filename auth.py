from passlib.context import CryptContext
from jose import jwt, JWTError

from datetime import datetime, timedelta, timezone


SECRET_KEY = "malware_analyzer_secret"

ALGORITHM = "HS256"


pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)



def hash_password(password: str):

    return pwd_context.hash(password)



def verify_password(
    password: str,
    hashed: str
):

    return pwd_context.verify(
        password,
        hashed
    )



def create_token(username: str):

    expire = (
        datetime.now(timezone.utc)
        + timedelta(hours=2)
    )

    data = {
        "sub": username,
        "exp": expire
    }

    return jwt.encode(
        data,
        SECRET_KEY,
        algorithm=ALGORITHM
    )



def decode_token(token: str):

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        return payload.get("sub")


    except JWTError:

        return None