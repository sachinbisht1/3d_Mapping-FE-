"""Controller to manage secretes."""
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from constants import utilities_constants as UTILITIES_CONSTANTS
from constants.error_messages.accounts import ACCESS_REVOKED, PLEASE_LOGIN_AGAIN, INVALID_CREDENTIALS, SECRET_NOT_FOUND
from constants.error_messages.accounts import LOGIN_FAILED, PASSWORD_NOT_FOUND, PASSWORD_IS_NOT_CREATED_BY_USER
from constants.error_messages.accounts import ACCESS_TOKEN_NOT_FOUND_IN_COOKIES, ACCESS_TOKEN_IS_MANIPULATED
from constants.error_messages.accounts import LOGIN_DURATION_EXCEED, FAILED_TO_VERIFY_USER
from jose import jwt, JWTError
from jose.exceptions import JWEInvalidAuth, ExpiredSignatureError
import bcrypt
from typing import Union

from controllers.api_request_error import HandleHTTPException
from fastapi import HTTPException
from anyio import EndOfStream

from constants.dynamodb_column_names import Temp_Password_Created_At, Temp_Password
from constants.http_status_code import PERMISSION_DENIED_ERROR_STATUS_CODE, BAD_REQUEST_ERROR_STATUS_CODE
from constants.http_status_code import COMMON_EXCEPTION_STATUS_CODE, CLIENT_CLOSED_REQUEST_STATUS_CODE

HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute


def get_hashed_secret(secret: Union[str, bool]) -> str:
    """Generate hash secret."""
    if not secret:
        raise HANDLE_HTTP_EXCEPTION(status_code=BAD_REQUEST_ERROR_STATUS_CODE,
                                    error_message=SECRET_NOT_FOUND)
    return bcrypt.hashpw(f"{secret}_-_{UTILITIES_CONSTANTS.PEPPER_TEXT}".encode('utf-8'), bcrypt.gensalt())


def verify_secret(secret: str, hashed_pass: Union[str, bool]) -> bool:
    """Verify hash secret."""
    if not hashed_pass:
        raise Exception(PASSWORD_IS_NOT_CREATED_BY_USER)

    secret_password = f"{secret}_-_{UTILITIES_CONSTANTS.PEPPER_TEXT}".encode('utf-8')
    if bcrypt.checkpw(secret_password, hashed_pass.encode('utf-8')):
        return True
    raise HANDLE_HTTP_EXCEPTION(PERMISSION_DENIED_ERROR_STATUS_CODE, INVALID_CREDENTIALS)


def create_access_token(user_id, secret_key, expire_time: timedelta = UTILITIES_CONSTANTS.ACCESS_TOKEN_EXPIRE_MINUTES):
    """Create a cookies access token."""
    expire_time = datetime.utcnow() + timedelta(expire_time) \
        if not isinstance(expire_time, timedelta) else datetime.utcnow() + expire_time

    jwt_token = jwt.encode({"user_id": f"{user_id}", "secret_key": f"{secret_key}", "exp": expire_time},
                           algorithm=UTILITIES_CONSTANTS.ALGORITHM, key=UTILITIES_CONSTANTS.JWT_SECRET_KEY)
    return {"access_token": jwt_token}


def create_refresh_token(user_id, secret_key,
                         expire_time: timedelta = UTILITIES_CONSTANTS.REFRESH_TOKEN_EXPIRE_MINUTES):
    """Create a cookies refresh token."""
    expire_time = datetime.utcnow() + timedelta(expire_time) \
        if not isinstance(expire_time, timedelta) else datetime.utcnow() + expire_time
    jwt_token = jwt.encode({"user_id": user_id, "secret_key": f"{secret_key}", "exp": expire_time},
                           algorithm=UTILITIES_CONSTANTS.ALGORITHM, key=UTILITIES_CONSTANTS.JWT_REFRESH_SECRET_KEY)
    return {"refresh_token": jwt_token}


def create_temp_password(secret_key: str):
    """Genreate temp password."""
    hashed_password = get_hashed_secret(secret_key)
    current_date_time_utc = datetime.utcnow()
    password_created_at = current_date_time_utc.strftime(UTILITIES_CONSTANTS.DATE_TIME_FORMAT)
    return {"password": hashed_password, "password_created_at": password_created_at}


def cookies_parser(cookie_raw_data: Union[SimpleCookie, dict]):
    """Parse cookies into dict."""
    cookie = SimpleCookie()
    cookie.load(cookie_raw_data)
    cookies = {keys: values.value for keys, values in cookie.items()}
    return cookies


def parse_jwt_access_data(token: str):
    """Parse jwt access data."""
    try:
        jwt_data = jwt.decode(token=token, key=UTILITIES_CONSTANTS.JWT_SECRET_KEY,
                              algorithms=UTILITIES_CONSTANTS.ALGORITHM)
        return jwt_data

    except JWTError as error:
        return {"signature_failed": True, "error": f"{error.args}"}


def parse_jwt_refresh_data(token: str):
    """Parse jwt refresh data."""
    if not token:
        raise HANDLE_HTTP_EXCEPTION(PERMISSION_DENIED_ERROR_STATUS_CODE, f"{PLEASE_LOGIN_AGAIN}")
    try:
        jwt_data = jwt.decode(token=token, key=UTILITIES_CONSTANTS.JWT_REFRESH_SECRET_KEY,
                              algorithms=UTILITIES_CONSTANTS.ALGORITHM)
        return jwt_data
    except ExpiredSignatureError as err:
        return False, f"{err.args}"
    except JWEInvalidAuth as err:
        return False, f"{err.args}"
    except Exception as error:
        return HANDLE_HTTP_EXCEPTION(COMMON_EXCEPTION_STATUS_CODE, LOGIN_FAILED.format(f"{error.args}"))


def regenerate_access_token(cookies: dict):
    """Regenrate access token."""
    refresh_token = cookies.get('refresh_token') or None
    if not refresh_token:
        raise HANDLE_HTTP_EXCEPTION(PERMISSION_DENIED_ERROR_STATUS_CODE, f"{ACCESS_REVOKED.format(PASSWORD_NOT_FOUND)}")
    refresh_data = parse_jwt_refresh_data(token=refresh_token)
    secret_key = refresh_data.get('secret_key')
    if not secret_key:
        raise HANDLE_HTTP_EXCEPTION(PERMISSION_DENIED_ERROR_STATUS_CODE, f"{ACCESS_REVOKED.format(PASSWORD_NOT_FOUND)}")
    access_token = create_access_token(user_id=refresh_data.get('user_id'),
                                       secret_key=secret_key)
    return access_token


def user_data_password_time_check(user_data_password_time: Union[str, datetime]):
    """Check passwod validity."""
    if not isinstance(user_data_password_time, datetime) and isinstance(user_data_password_time, str):
        user_data_password_time = datetime.strptime(user_data_password_time, UTILITIES_CONSTANTS.DATE_TIME_FORMAT)
    current_date_time = datetime.utcnow()
    if current_date_time - timedelta(
            minutes=UTILITIES_CONSTANTS.REFRESH_TOKEN_EXPIRE_MINUTES) <= user_data_password_time:
        return True
    return False


def verify_password(cookies: dict, user_data: dict):
    """Verify password."""
    try:
        access_token = cookies.get("access_token") or None
        refresh_token = cookies.get("refresh_token") or None
        access_token_regenerated = False
        if not access_token and not refresh_token:
            raise HANDLE_HTTP_EXCEPTION(PERMISSION_DENIED_ERROR_STATUS_CODE,
                                        f"{ACCESS_REVOKED.format(ACCESS_TOKEN_NOT_FOUND_IN_COOKIES)}")
        elif not access_token and refresh_token:
            access_data = regenerate_access_token(cookies=cookies)
            access_token_regenerated = True
            access_token = access_data.get("access_token")
        access_data = parse_jwt_access_data(token=access_token)
        if not access_data.get('secret_key'):
            if access_data.get('signature_expired'):
                access_data = regenerate_access_token(cookies=cookies)
                access_token_regenerated = True
            else:
                raise HANDLE_HTTP_EXCEPTION(PERMISSION_DENIED_ERROR_STATUS_CODE,
                                            f"{ACCESS_REVOKED.format(ACCESS_TOKEN_IS_MANIPULATED)}")

        password_created_at = user_data.get(f"{Temp_Password_Created_At}")

        if not password_created_at or not user_data_password_time_check(password_created_at):
            raise HANDLE_HTTP_EXCEPTION(PERMISSION_DENIED_ERROR_STATUS_CODE, LOGIN_DURATION_EXCEED)
        password = user_data.get(f"{Temp_Password}")
        if verify_secret(hashed_pass=password, secret=access_data.get('secret_key', False)):
            if access_token_regenerated:
                return {"user_verified": True, "access_token": access_token}
            return {"user_verified": True}
        raise HANDLE_HTTP_EXCEPTION(PERMISSION_DENIED_ERROR_STATUS_CODE,
                                    f"{ACCESS_REVOKED.format(FAILED_TO_VERIFY_USER)}")

    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)

    except EndOfStream as error:
        return HANDLE_HTTP_EXCEPTION(status_code=CLIENT_CLOSED_REQUEST_STATUS_CODE, error_message=f"{error}")

    except Exception as error:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error.args)
