"""Api router for all S3 apis."""
# fastapi imports
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse

# constants imports
from constants import permissions_constants
from constants.error_messages.s3 import BUCKET_NOT_CREATED, BUCKET_FOUND_BUT_UNABLE_TO_RETURN_ITS_NAME
from constants.error_messages.s3 import BUCKET_NOT_FOUND, BUCKET_CREATED_BUT_UNABLE_TO_FIND
from constants.error_messages.s3 import ONLY_OWNER_IS_ALLOWED_TO_CREATE_BUCKET, FAILED_TO_CREATE_BUCKET
from constants.api_endpoints.s3 import S3_STATUS, CREATE_BUCKET, LIST_ALL_BUCKETS
from constants.api_endpoints.s3 import GET_ENTERPRISE_BUCKET_NAME, GET_PROJECT_ALL_OBJECTS, BROWSE_S3_FILE_PATH
from constants.api_endpoints.s3 import GENERATE_UPLOAD_PRE_SIGNED_S3_URL
from constants.http_status_code import PERMISSION_DENIED_ERROR_STATUS_CODE, BAD_REQUEST_ERROR_STATUS_CODE
from constants.http_status_code import THIRD_PARTY_API_FAILED_ERROR_STATUS_CODE, COMMON_EXCEPTION_STATUS_CODE
from constants.http_status_code import STATUS_OK, STATUS_CREATED
from constants.constants import S3_PRESIGNED_URL_EXPIRE_TIME

# controllers imports
from controllers.api_request_error import HandleHTTPException
from controllers.utilities import get_user_id, get_project_id


# gateway imports
from gateways.s3_gateway import S3
from gateways.dynamodb_gateway import Queries

# import models
from models import s3 as s3_models

S3_CLIENT = S3()
HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute

s3_router = APIRouter()


@s3_router.get(LIST_ALL_BUCKETS)
def list_all_s3_buckets():
    """List all S3 buckets of Enterprise aws account."""
    try:
        response = S3_CLIENT.list_all_bucket()
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error.args)
    return JSONResponse(content=response, status_code=STATUS_OK)


@s3_router.get(S3_STATUS)
def check_s3():
    """Check S3 status of enterprise aws account."""
    try:
        list_all_s3_buckets()

    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error.args)
    return JSONResponse(content=STATUS_OK, status_code=STATUS_OK)


@s3_router.get(GET_ENTERPRISE_BUCKET_NAME)
def get_enterprise_bucket_name(return_bucket_name_only=False):
    """Get enterprise S3 bucket name for 3d mapping from botlab dynamics."""
    try:
        response = S3_CLIENT.get_enterprise_bucket_name()
        if response.get("bucket_name") and not return_bucket_name_only:
            return JSONResponse(content={"bucket_name": response.get("bucket_name")}, status_code=STATUS_OK)
        elif response.get("bucket_name") and return_bucket_name_only:
            return response.get("bucket_name")
        elif not response.get("bucket_name", False) and response.get("bucket_found"):
            return HANDLE_HTTP_EXCEPTION(status_code=BAD_REQUEST_ERROR_STATUS_CODE,
                                         error_message=BUCKET_FOUND_BUT_UNABLE_TO_RETURN_ITS_NAME)
        elif (not response.get("bucket_name", False) and not response.get("bucket_found") and
              response.get("bucket_already_created")):
            return HANDLE_HTTP_EXCEPTION(status_code=BAD_REQUEST_ERROR_STATUS_CODE,
                                         error_message=BUCKET_CREATED_BUT_UNABLE_TO_FIND)
        return HANDLE_HTTP_EXCEPTION(status_code=THIRD_PARTY_API_FAILED_ERROR_STATUS_CODE,
                                     error_message=BUCKET_NOT_CREATED)

    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error)
    except Exception as error:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error.args)


@s3_router.get(GET_PROJECT_ALL_OBJECTS)
def get_project_all_objects(user_id: str = Depends(get_user_id), project_id: str = Depends(get_project_id)):
    """List all objects from a project.

    Parameter

    user_id: User id of user requesting data to read

    project_id: Project of which user is requesting data to read
    """
    try:
        if not Queries.user_has_permission_in_project(user_id=user_id, permission=permissions_constants.S3_READ.lower(),
                                                      project_id=project_id):
            return HANDLE_HTTP_EXCEPTION(status_code=PERMISSION_DENIED_ERROR_STATUS_CODE,
                                         error_message=permissions_constants.S3_READ)
        bucket_name = get_enterprise_bucket_name(return_bucket_name_only=True)
        project_details = Queries.project_details(project_id=project_id)
        project_directory = project_details.get("S3Directory")
        project_objects = S3_CLIENT.list_project_objects(bucket=bucket_name, project_directory=project_directory)
        return JSONResponse(content=project_objects, status_code=STATUS_OK)

    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error.args)


@s3_router.post(CREATE_BUCKET)
def create_bucket(data: s3_models.GetUserIdAndProjectId):
    """Create bucket for enterprise.

    Parameter

    user_id: user_id of user which is creating bucket

    project_id: project_id of where user is currently logged in
    """
    try:
        if not Queries.user_has_permission_in_project(user_id=data.user_id,
                                                      permission=permissions_constants.OWNER.lower(),
                                                      project_id=data.project_id):
            return HANDLE_HTTP_EXCEPTION(status_code=PERMISSION_DENIED_ERROR_STATUS_CODE,
                                         error_message=ONLY_OWNER_IS_ALLOWED_TO_CREATE_BUCKET)

        is_bucket_already_exists = S3_CLIENT.check_bucket_already_exists()

        if not is_bucket_already_exists:
            is_bucket_created = S3_CLIENT.create_bucket()
        else:
            return JSONResponse(content={"bucket_already_created": True, "created_bucket": False},
                                status_code=STATUS_OK)

        if is_bucket_created:
            return JSONResponse(content={"bucket_already_created": False, "created_bucket": True},
                                status_code=STATUS_CREATED)
        return HANDLE_HTTP_EXCEPTION(status_code=THIRD_PARTY_API_FAILED_ERROR_STATUS_CODE,
                                     error_message=FAILED_TO_CREATE_BUCKET)

    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)

    except Exception as error:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error.args)


@s3_router.get(BROWSE_S3_FILE_PATH)
def get_s3_file(object_name: str, expires_in: int = 3600):
    """Browse S3 file."""
    try:
        bucket_name = get_enterprise_bucket_name(return_bucket_name_only=True)
        if not bucket_name:
            return HANDLE_HTTP_EXCEPTION(status_code=THIRD_PARTY_API_FAILED_ERROR_STATUS_CODE,
                                         error_message=BUCKET_NOT_FOUND)
        pre_signed_url_response = S3_CLIENT.genrate_s3_file_presigned_url(
            bucket_name=bucket_name,
            object_name=object_name,
            method="get_file",
            expires_in=expires_in)

        return JSONResponse(content=pre_signed_url_response, status_code=STATUS_OK)

    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error)
    except Exception as error:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error.args)


@s3_router.get(GENERATE_UPLOAD_PRE_SIGNED_S3_URL)
def get_s3_upload_pre_signed_url(project_name: str, survey_name: str = "",
                                 expires_in: int = S3_PRESIGNED_URL_EXPIRE_TIME):
    """Generate a presigned URL that can be used to perform upload of photos.

    Parameter

    project_name: Project name.

    survey_name: Survey name.

    expires_in: The number of seconds the presigned URL is valid for.
    """
    try:
        url = S3_CLIENT.genrate_s3_file_presigned_url(
            bucket_name=get_enterprise_bucket_name(return_bucket_name_only=True),
            object_name=f"{project_name}/{survey_name}",
            expires_in=expires_in or S3_PRESIGNED_URL_EXPIRE_TIME,
            method="upload_file"
        )

        return JSONResponse(content=url, status_code=STATUS_OK)

    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error)
    except Exception as error:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error.args)
