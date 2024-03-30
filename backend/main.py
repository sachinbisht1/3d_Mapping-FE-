"""Main App."""
# Library Imports
import os
# import json
from typing import Annotated
from mangum import Mangum
from starlette.types import Message
from email_validator import validate_email
from anyio import EndOfStream
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from info import APP_NAME, APP_SUMMARY, APP_CONTACT, APP_VERSION
from constants.error_messages.accounts import ACCESS_REVOKED
from constants.logger import LOGGER
from constants.http_status_code import COMMON_EXCEPTION_STATUS_CODE, CLIENT_CLOSED_REQUEST_STATUS_CODE
from constants.dynamodb_column_names import Current_Project_Policy_Details, Is_Super_Admin
from constants.roles import SUPER_ADMIN, POLICIES_ACCESS_TO_ALL, ONLY_SELF, POLICIES
from constants.utilities_constants import ACCESS_TOKEN_EXPIRE_MINUTES
from constants.api_endpoints.account import DOC, USERS_ME, OPENAPI


from gateways.dynamodb_gateway.Queries import user_details, update_current_project_policy_details
from gateways.dynamodb_gateway.UserProfile import User
# S3 gateway import

# Controllers import
from controllers.api_request_error import HandleHTTPException, PermissionException

# Main Imports
from backend.s3_api import s3_router
from backend.dynamodb_api import dynamodb_router
from backend.account import account_router
from backend.cloudwatch_api import cloudwatch_router
from controllers.secrets import cookies_parser, verify_password, parse_jwt_refresh_data

# Router prefix imports
from constants.api_endpoints.account import ACCOUNT_PREFIX
from constants.api_endpoints.clodwatch import CLOUDWATCH_PREFIX
from constants.api_endpoints.dynamodb import DYNAMODB_PREFIX
from constants.api_endpoints.s3 import S3_PREFIX

# Endpoints import
from constants.api_endpoints.account import ACCOUNT_LOGIN, ACCOUNT_LOGOUT
from constants.api_endpoints.dynamodb import EMAIL_VALIDATE


security = HTTPBasic()
HANDLE_HTTP_EXCEPTION = HandleHTTPException()
app = FastAPI(
    title=APP_NAME,
    # description=app_description,
    summary=APP_SUMMARY,
    version=APP_VERSION,
    contact=APP_CONTACT,
    swagger_ui_parameters={"syntaxHighlight.theme": "obsidian"},
    docs_url=None
)

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """Documentation with favicon."""
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title,
        swagger_favicon_url="static/botlab-dynamics.ico"
    )


async def set_body(request: Request, body: bytes):
    """Set body to print logs as we are using pydantic models."""
    async def receive() -> Message:
        return {"type": "http.request", "body": body}
    request._receive = receive


async def get_body(request: Request) -> bytes:
    """Response body from request."""
    body = await request.body()
    await set_body(request, body)
    return body


@app.middleware("http")
async def print_response_logs(request: Request, call_next):
    """Priniting response logs for every api request."""
    try:
        response: Response = await call_next(request)
        LOGGER.debug(f"Response status code --> {response.status_code}")
        res_body = b''
        async for chunk in response.body_iterator:
            res_body += chunk
        LOGGER.debug(f"Response body --> {res_body}")
        return Response(content=res_body, headers=response.headers, status_code=response.status_code)

    except HTTPException as http_error:
        return Response(content=http_error.detail, status_code=http_error.status_code)
    except EndOfStream as error:
        return Response(content=error, status_code=CLIENT_CLOSED_REQUEST_STATUS_CODE)
    except Exception as error:
        return Response(content=f"{error}", status_code=COMMON_EXCEPTION_STATUS_CODE)


@app.middleware("http")
async def check_headers_authorization(request: Request, call_next):
    """Authorize all users through cookies."""
    try:
        LOGGER.debug(f"headers --> {request.headers}")
        need_to_set_cookies_again = False
        cookies = cookies_parser(request.headers.get('cookie') or {})
        project_id = cookies.get("project_id") or None

        if (ACCOUNT_LOGIN not in str(request.url) and USERS_ME not in str(request.url) and
                not str(request.url) == str(request.base_url) and DOC not in str(request.url) and
                OPENAPI not in str(request.url) and ACCOUNT_LOGOUT not in str(request.url)):

            refresh_data = parse_jwt_refresh_data(cookies.get('refresh_token'))
            if not refresh_data:
                raise PermissionException("User needs to login again redirect to login")
            user_id = refresh_data.get('user_id')
            if not user_id:
                raise PermissionException("User is not login redirect to login")
            url_path = str(request.url.path)
            if "get-project-details" in url_path:
                url_project_id = os.path.basename(url_path)
                update_current_project_policy_details(user_id=user_id, project_id=url_project_id)
            user: dict = user_details(user_id=user_id)
            password_verify_data = verify_password(cookies=cookies, user_data=user)
            user_all_project_policies = user.get(Current_Project_Policy_Details, {}) or {}
            user_current_project_policies = user_all_project_policies.get(project_id) or {}
            if password_verify_data.get("user_verified", False) and password_verify_data.get("access_token", False):
                need_to_set_cookies_again = True
            elif not password_verify_data.get("user_verified", False):
                raise PermissionException(detail=f"{ACCESS_REVOKED.format('verification failed')}")
            if url_path.count("/") > 2:
                url_path = url_path.split("/")[1:3]
                url_path = f'{"/"}{"/".join(url_path)}'
            if not user.get(Is_Super_Admin) and url_path not in POLICIES.get(ONLY_SELF) and \
                    (url_path not in POLICIES.get(POLICIES_ACCESS_TO_ALL)):
                for each_policy in user_current_project_policies:
                    if SUPER_ADMIN in each_policy and "docs" not in str(request.url.path):
                        break
                    if not POLICIES.get(each_policy):
                        continue
                    if url_path in POLICIES.get(each_policy):
                        LOGGER.info("User is verified to access ", request.url)
                        break
                else:
                    raise PermissionException("User do not have access to visit this functionality")

        elif ACCOUNT_LOGOUT in str(request.url):
            refresh_data = parse_jwt_refresh_data(cookies.get('refresh_token'))
            if not refresh_data:
                raise PermissionException("User is already logged out")
            user_id = refresh_data.get('user_id')
            User().delete_temp_password(user_id)

        response: Response = await call_next(request)

        if need_to_set_cookies_again and ACCOUNT_LOGOUT not in str(request.url):
            response.set_cookie('access_token', password_verify_data.get('access_token'),
                                int(ACCESS_TOKEN_EXPIRE_MINUTES) * 60, samesite='none', secure=True)

        elif ACCOUNT_LOGOUT in str(request.url):
            response.delete_cookie(key="access_token")
            response.delete_cookie(key="refresh_token")
            response.delete_cookie(key="user_id")
            response.delete_cookie(key="project_id")
        return response

    except HTTPException as http_error:
        return Response(content=http_error.detail, status_code=http_error.status_code)
    except EndOfStream as error:
        return Response(content=error, status_code=CLIENT_CLOSED_REQUEST_STATUS_CODE)
    except Exception as error:
        return Response(content=f"{error}", status_code=COMMON_EXCEPTION_STATUS_CODE)


@app.middleware("http")
async def print_request_logs(request: Request, call_next):
    """Print Every request detail for every api request."""
    try:
        LOGGER.debug(f"Request url --> {request.url}")
        LOGGER.debug(f"Request base url --> {request.base_url}")
        LOGGER.debug(f"Requested url {request.url}")

        await set_body(request, await request.body())
        request_body = await get_body(request)
        LOGGER.debug(f"Request body --> {request_body}")
        response = await call_next(request)
        return response

    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION.execute(status_code=http_error.status_code, error_message=http_error.detail)
    except EndOfStream as error:
        return HTTPException(status_code=CLIENT_CLOSED_REQUEST_STATUS_CODE, detail=f"{error}")
    except Exception as error:
        return HANDLE_HTTP_EXCEPTION.execute(status_code=COMMON_EXCEPTION_STATUS_CODE,
                                             error_message=f"{error}")


@app.get("/")
def check_server_status():
    """Perform server status check."""
    LOGGER.info(f"{os.getenv('secrets.AWS_DEFAULT_REGION_PROD')}")
    LOGGER.debug("debug server")
    LOGGER.info("Serverless is running smoothly")
    return JSONResponse(content="Server Health is Good", status_code=200)


@app.get(USERS_ME)
def read_current_user(credentials: Annotated[HTTPBasicCredentials, Depends(security)]):
    """Login through creds on docs page."""
    from backend.account import account_login
    from models.user_login import Login
    response = account_login(data=Login(email=credentials.username, password=credentials.password))
    return response


@app.get(EMAIL_VALIDATE)
def email_validate(email: str):
    """Validate email."""
    valid = False
    try:
        validate_email(email)
        valid = True
    except Exception as e:
        LOGGER.error(str(e))
    return valid


app.include_router(account_router, prefix=ACCOUNT_PREFIX)
app.include_router(cloudwatch_router, prefix=CLOUDWATCH_PREFIX)
app.include_router(dynamodb_router, prefix=DYNAMODB_PREFIX)
app.include_router(s3_router, prefix=S3_PREFIX)

handler = Mangum(app=app)
