"""Account router for all account related apis."""
import json
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from models.default import ServerStatusResponseModel
from models.user_login import SignupResponse, AddUser, Login

from controllers import secrets
from controllers.api_request_error import HandleHTTPException

from constants.http_status_code import BAD_REQUEST_ERROR_STATUS_CODE
from constants.http_status_code import UNAUTHORIZED_ACCESS_STATUS_CODE, STATUS_OK, STATUS_CREATED
from constants.api_endpoints.account import ACCOUNT_ROOT, ACCOUNT_ADD_USER, ACCOUNT_LOGIN, ACCOUNT_LOGOUT
from constants.error_messages.accounts import USER_NAME_OR_PASSWORD_IS_WRONG, USERNAME_IS_WRONG
from constants.error_messages.accounts import USER_SIGNUP_IS_INCOMPLETE
from constants.utilities_constants import REFRESH_TOKEN_EXPIRE_MINUTES, ACCESS_TOKEN_EXPIRE_MINUTES
from constants.dynamodb_column_names import Secret_Key


from controllers import api_request_error

from gateways.dynamodb_gateway.UserProfile import User
import gateways.dynamodb_gateway.Queries as Queries

user_resource = User()
HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute
account_router = APIRouter()


@account_router.get(ACCOUNT_ROOT, response_model=ServerStatusResponseModel)
def check_account_status():
    """Check server status of account router."""
    return JSONResponse(content={"server_status": STATUS_OK, "server_name": "Account"},
                        status_code=STATUS_OK)


@account_router.post(ACCOUNT_ADD_USER, response_model=SignupResponse)
def account_signup(data: AddUser):
    """Add user."""
    user = user_resource.add_user(name=data.name, company=data.company, email=data.email, contact_no=data.mobile_no)
    return JSONResponse(content=json.dumps(user), status_code=STATUS_CREATED)


@account_router.put(ACCOUNT_LOGIN)
def account_login(data: Login):
    """Login to account using email."""
    try:
        user_id = Queries.get_user_id(email=data.email)
        user_data: dict = user_resource.get_user(user_id=user_id)
        if not user_data:
            raise HANDLE_HTTP_EXCEPTION(status_code=BAD_REQUEST_ERROR_STATUS_CODE,
                                        error_message=f"{USERNAME_IS_WRONG}")
        secret_key = user_data.get(Secret_Key, False) or None
        if not secret_key:
            raise api_request_error.PermissionException(detail=f"{USER_SIGNUP_IS_INCOMPLETE.format(data.email)}")
        if secrets.verify_secret(data.password.get_secret_value(), secret_key):
            hashed_temp_pass = user_resource.update_temp_password(user_id)
            access_token = secrets.create_access_token(user_id=user_id, secret_key=hashed_temp_pass)
            refresh_token = secrets.create_refresh_token(user_id=user_id, secret_key=hashed_temp_pass)
            response = JSONResponse(content=STATUS_OK,
                                    status_code=STATUS_OK)
            response.set_cookie(key="access_token", value=access_token.get("access_token"),
                                max_age=int(ACCESS_TOKEN_EXPIRE_MINUTES) * 60, secure=True, httponly=True,
                                samesite='none')
            response.set_cookie(key="refresh_token", value=refresh_token.get("refresh_token"),
                                max_age=int(REFRESH_TOKEN_EXPIRE_MINUTES) * 60, secure=True, httponly=True,
                                samesite='none')
            response.set_cookie(key="user_id", value=user_id,
                                max_age=int(REFRESH_TOKEN_EXPIRE_MINUTES) * 60, secure=True, httponly=True,
                                samesite='none')
            return response
        raise HANDLE_HTTP_EXCEPTION(status_code=UNAUTHORIZED_ACCESS_STATUS_CODE,
                                    error_message=f"{USER_NAME_OR_PASSWORD_IS_WRONG}")
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        HANDLE_HTTP_EXCEPTION(status_code=500, error_message=f"{error}")


@account_router.put(ACCOUNT_LOGOUT)
def account_logout(request: Request):
    """Logout from your account."""
    base_url = str(request.base_url)
    if base_url[-1] == "/":
        base_url = base_url[:-1]
    return {"login_url": f"{base_url}/{ACCOUNT_LOGIN}"}
