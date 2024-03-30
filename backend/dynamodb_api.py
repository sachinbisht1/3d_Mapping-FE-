"""Apis for interacting with DynamoDB."""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
import json

from constants import dynamodb_column_names
import controllers.api_request_error
from controllers.utilities import get_project_id, get_user_id
from controllers.api_request_error import HandleHTTPException
from constants.error_messages.dynamodb import INVALID_POLICY_DETAILS_INPUT
from constants.api_endpoints.dynamodb import ADD_USER_TO_PROJECT, REMOVE_USER_FROM_PROJECT, ADD_USER, UPDATE_USER
from constants.api_endpoints.dynamodb import GET_USER_DETAILS, USER_PERMISSIONS_IN_PROJECT, PROJECTS_OF_USER
from constants.api_endpoints.dynamodb import GET_PROJECT_DETAILS, USERS_OF_PROJECT, ADMINS_OF_PROJECT, ADD_PROJECT
from constants.api_endpoints.dynamodb import UPDATE_PROJECT, UPDATE_PERMISSION_OF_USER, TOGGLE_STATUS_OF_PROJECT
from constants.api_endpoints.dynamodb import ADD_POLICY, ADD_COMPANY, LIST_COMPANIES, DELETE_COMPANY, GET_USER_ID
from constants.api_endpoints.dynamodb import SET_PASSWORD, ADD_SUPER_ADMIN, REMOVE_SUPER_ADMIN, LIST_ALL_CATEGORIES
from constants.api_endpoints.dynamodb import ALL_PROJECT_DETAILS_OF_USER
from constants.http_status_code import THIRD_PARTY_API_FAILED_ERROR_STATUS_CODE, COMMON_EXCEPTION_STATUS_CODE
from constants.http_status_code import STATUS_OK, STATUS_CREATED
from constants.error_messages.s3 import BUCKET_NOT_FOUND
from constants.utilities_constants import REFRESH_TOKEN_EXPIRE_MINUTES

# Gateways Imports
from gateways.dynamodb_gateway.UserProfile import User
from gateways.dynamodb_gateway.Project import Project
from gateways.dynamodb_gateway.Company import Company
from gateways.dynamodb_gateway.Policy import Policy
from gateways.dynamodb_gateway.SuperAdmin import SuperAdmin
from gateways.dynamodb_gateway import ProjectCategory
from gateways.dynamodb_gateway import Queries
from gateways import s3_gateway

import controllers
from models import dynamodb as dynamodb_models
# from logging import Logger
HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute

# instantiate objects for table classes to query on the tables
user = User()
project = Project()
policy = Policy()
company = Company()
super_admin = SuperAdmin()
project_category = ProjectCategory.ProjectCategory()

dynamodb_router = APIRouter()


@dynamodb_router.post(ADD_USER, status_code=STATUS_CREATED)
def add_user_in_UserProfile_table(data: dynamodb_models.UserDetails):
    """Add user in UserProfile table.

    parameter:

    name: Name of the user as a string

    company: Company name of the user

    email: Email id of the user

    contact_no: Contact no. of the user

    """
    response = {}
    try:
        response = user.add_user(data.user_name, data.company, data.email, data.contact_no)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)
    return JSONResponse(content=response, status_code=STATUS_CREATED)


@dynamodb_router.put(UPDATE_USER)
def update_user_in_UserProfile_table(data: dynamodb_models.UserDetailsWithId):
    """
    Add user in UserProfile table.

    parameter:

     name: Name of the user as a string

     company: Company ID of the user

     email: Email id of the user

     contact_no: Contact no. of the user

    :return: "SUCCESS" if the user details are updated successfully
    """
    response = {}
    try:
        response = user.update_user(data.user_id, data.user_name, None,
                                    data.company, data.email, data.contact_no)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)
    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.get(GET_USER_DETAILS)
def get_user_details(user_id: str = Depends(get_user_id)):
    """
    Add user in UserProfile table.

    parameter:

    id: UserID as a string

    :return: Details of the user
    """
    response = {}
    try:
        response = user.get_user(user_id)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return HandleHTTPException(COMMON_EXCEPTION_STATUS_CODE, f"{error}")
    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.get(USER_PERMISSIONS_IN_PROJECT)
def user_permissions_in_project(user_id: str = Depends(get_user_id), project_id: str = Depends(get_project_id)):
    """
    See the permissions of a user in a project.

    parameter:

     user_id: UserID as a string

     project_id: ProjectID as a string

    :return: Permissions of a user in a project
    """
    response = {}
    """try:
        response = Queries.list_user_permissions_in_project(user_id,project_id)
    except Exception as error:
        response = {}
        LOGGER.error(f"error -------> {error}")"""
    try:
        response = Queries.list_user_permissions_in_project(user_id, project_id)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)
    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.get(PROJECTS_OF_USER)
def projects_of_user(user_id: str = Depends(get_user_id)):
    """
    See the projects of a user.

    parameter:

     user_id: UserID as a string

    :return: Projects of a user
    """
    response = {}
    try:
        response = Queries.list_projects_of_user(user_id)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)
    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.get(GET_PROJECT_DETAILS)
def get_project_details(project_id: str, user_id: str = Depends(get_user_id)):
    """
    See the details of a project.

    parameter:

     project_id: ProjectID as a string

    :return: Details of the project
    """
    response = {}
    try:
        response = JSONResponse(project.get_project(project_id), status_code=STATUS_OK)
        response.set_cookie("project_id", project_id,
                            max_age=int(REFRESH_TOKEN_EXPIRE_MINUTES) * 60, secure=True, httponly=True, samesite=None)
        return response
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)
    # return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.get(USERS_OF_PROJECT)
def user_list_of_project(project_id: str = Depends(get_project_id)):
    """
    See the users of a project.

    parameter:

     project_id: ProjectID as a string

    :return: Users of a project
    """
    response = {}
    try:
        response = Queries.project_details(project_id)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)
    return JSONResponse(content=response[dynamodb_column_names.Project_Users], status_code=STATUS_OK)


@dynamodb_router.get(ADMINS_OF_PROJECT)
def admin_list_of_project(project_id: str = Depends(get_project_id)):
    """
    See the admins of a project.

    parameter:

     project_id: ProjectID as a string

    :return: Admin of a project

    """
    response = {}
    try:
        response = Queries.project_details(project_id)
        admins = {}
        for admin_id in response[dynamodb_column_names.Project_Admins]:
            admins[admin_id] = response[dynamodb_column_names.Project_Users][admin_id]
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)
    return JSONResponse(content=admins, status_code=STATUS_OK)


@dynamodb_router.post(ADD_PROJECT)
def add_project_in_Project_table(data: dynamodb_models.ProjectDetails):
    """
    Add project in Project table.

    parameter:

     project_name: Name of the project as a string

     location: Location where the project is going on

     history: History of the project in terms of which user did what update

     category: Category of the project

     status: True if the project is active and False if it is inactive

     description: Description of the project

    :return: project_id if the project is added successfully

    """
    response = {}
    try:
        bucket = s3_gateway.S3().get_enterprise_bucket_name()
        if "bucket_name" not in bucket:
            return HANDLE_HTTP_EXCEPTION.execute(status_code=THIRD_PARTY_API_FAILED_ERROR_STATUS_CODE,
                                                 error_message=BUCKET_NOT_FOUND)
        s3_directory = f"{bucket['bucket_name']}/{data.project_name}"
        response = project.add_project(data.project_name, data.location, s3_directory, data.history, data.category,
                                       data.status, data.description, data.latitude, data.longitude)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_CREATED)


@dynamodb_router.put(UPDATE_PROJECT)
def update_project_in_Project_table(data: dynamodb_models.ProjectDetailsWithId):
    """
    Update project in Project table.

    parameter:

     project_id: projectID as a string

     project_name: Name of the project as a string

     location: Location where the project is going on

     history: History of the project in terms of which user did what update

     category: Category of the project

     status: True if the project is active and False if it is inactive

     description: Description of the project

    :return: "SUCCESS" if the project is added successfully

    """
    response = {}
    try:
        response = project.update_project(data.project_id, data.project_name, data.location, data.history,
                                          data.category, None, None, data.status, data.description, data.latitude,
                                          data.longitude)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.put(UPDATE_PERMISSION_OF_USER)
def update_permission_of_user(data: dynamodb_models.UserIdProjectIdNewPolicyId):
    """
    Update permission of user for a project.

    parameter:

     user_id: user id as a string

     project_id: ProjectID as a string

     new_policy_id: PolicyID as a string

    :return: "SUCCESS" if the permission is updated successfully
    """
    response = {}
    try:
        response = Queries.update_permission_of_user_in_project(data.user_id, data.project_id, data.new_policy_id)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.put(ADD_USER_TO_PROJECT)
def add_user_to_project(data: dynamodb_models.UserIdProjectIdPolicyId):
    """
    Add a user to a project.

    parameter:

     user_id: user id as a string

     project_id: ProjectID as a string

     policy_id: Policy ID as a string

    :return: "SUCCESS" if the user is added successfully to the project
    """
    response = {}
    try:
        response = Queries.add_user_to_project(data.user_id, data.project_id, data.policy_id)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.put(REMOVE_USER_FROM_PROJECT)
def remove_user_from_project(data: dynamodb_models.UserIdProjectId):
    """
    Remove a user from a project.

    parameter:

     user_id: user id as a string

     project_id: ProjectID as a string

    :return: "SUCCESS" if the user is removed successfully from the project
    """
    response = {}
    try:
        response = Queries.remove_user_from_project(data.user_id, data.project_id)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.put(TOGGLE_STATUS_OF_PROJECT)
def toggle_status_of_project(data: dynamodb_models.ProjectId_Lat_Long):
    """
    Toggle the status of a project from active to inactive and vice versa.

    parameter:

     project_id: ProjectID as a string

    :return: "SUCCESS" if the status of the project is changed successfully
    """
    response = {}
    try:
        response = Queries.toggle_status_of_project(data.project_id, data.Latitude, data.Longitude)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.post(ADD_POLICY)
def add_policy(data: dynamodb_models.PolicyNamePolicyDetails):
    """
    Add a new policy to the Policy table.

    parameter:

     policy_name: Name of the policy as a string

     policy_details: Details of the policy as a json

    :return: "SUCCESS" if the policy is added successfully

    :Format for the input will be :{"S3_READ":true,
    :                               "S3_Write":true}

    :Add the Policy Id to constants/constants.py
    """
    response = {}
    try:
        policy_details = data.policy_details if isinstance(data.policy_details,
                                                           dict) else json.loads(data.policy_details)
        if not isinstance(policy_details, dict):
            error_msg = INVALID_POLICY_DETAILS_INPUT
            return HandleHTTPException().execute(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        response = policy.add_policy(data.policy_name, policy_details)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_CREATED)


@dynamodb_router.post(ADD_COMPANY)
def add_company(data: dynamodb_models.CompanyName):
    """
    Add a new company to the Company table.

    parameter:

     company_name: Name of the company as a string

    :return: "SUCCESS" if the policy is added successfully
    """
    response = {}
    try:
        response = company.add_company(data.company_name)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_CREATED)


@dynamodb_router.get(LIST_COMPANIES)
def list_companies():
    """List all the companies."""
    response = {}
    try:
        response = Queries.list_companies()
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.delete(DELETE_COMPANY)
def delete_company(data: dynamodb_models.CompanyName):
    """Delete the company with its name as input."""
    response = {}
    try:
        response = Queries.delete_company(data.company_name)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.get(GET_USER_ID)
def get_user_id_by_email(email):
    """Given an email of a user, output the user ID."""
    response = {}
    try:
        response = Queries.get_user_id(email)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.put(SET_PASSWORD)
def set_password(data: dynamodb_models.UserIdPassword):
    """Set password of a user."""
    response = {}
    try:
        response = Queries.set_password(data.user_id, data.password)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.put(ADD_SUPER_ADMIN)
def add_super_admin(data: dynamodb_models.UserId):
    """Add a super admin."""
    response = {}
    try:
        response = Queries.add_super_admin(data.user_id)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_CREATED)


@dynamodb_router.put(REMOVE_SUPER_ADMIN)
def remove_super_admin(data: dynamodb_models.UserId):
    """Remove a super admin."""
    response = {}
    try:
        response = Queries.remove_super_admin(data.user_id)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.get(LIST_ALL_CATEGORIES)
def list_all_categories():
    """List all the project categories."""
    response = {}
    try:
        response = project_category.get_all_categories()
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION.execute(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_OK)


@dynamodb_router.get(ALL_PROJECT_DETAILS_OF_USER)
def all_project_details_of_user(user_id: str = Depends(get_user_id)):
    """List the details of all the projects of user."""
    response = {}
    try:
        response = Queries.all_project_details_of_user(user_id)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION.execute(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        return controllers.api_request_error.CommonException(detail=error.args)

    return JSONResponse(content=response, status_code=STATUS_OK)


# @dynamodb_router.put(CURRENT_PROJECT_POLICY_DETAILS_UPDATE)
# def update_current_project_policy_details(data: dynamodb_models.UserIdProjectId):
#     """
#     Update the policy details of the current project in User table
#     """

#     response = {}
#     try:
#         response = Queries.update_current_project_policy_details(data.user_id, data.project_id)
#     except HTTPException as http_error:

#         return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)

#     except Exception as error:
#         return controllers.api_request_error.CommonException(detail=error)

#     return JSONResponse(content=response, status_code=STATUS_OK)
