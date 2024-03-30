"""All queries related to dynamodb tables."""
# import the dynamodb table files
from gateways.dynamodb_gateway.UserProfile import User
from gateways.dynamodb_gateway.Project import Project
from gateways.dynamodb_gateway.Company import Company
from gateways.dynamodb_gateway.Policy import Policy
from gateways.dynamodb_gateway import SuperAdmin
from gateways.dynamodb_gateway import Transactions
import constants.constants as constants
from botocore.exceptions import ClientError
# from constants.logger import LOGGER
from boto3.dynamodb.conditions import Key
import re

from constants import dynamodb_column_names
from constants.http_status_code import COMMON_EXCEPTION_STATUS_CODE
from constants.error_messages.dynamodb import ITEM_MISSING, QUERY_ERROR, INCONSISTENT_RESULT, SCAN_ERROR
from constants.error_messages.dynamodb import USER_NOT_IN_PROJECT, SUPER_ADMIN_PERMISSION_UPDATE, POLICY_SAME
from constants.error_messages.dynamodb import ONLY_ADMIN_CANT_UPDATE, COMMON_ERROR, USER_ALREADY_IN_PROJECT
from constants.error_messages.dynamodb import CANNOT_SUPER_ADMIN_REMOVE_FROM_PROJECT, ONLY_ADMIN_CANT_REMOVE
from constants.error_messages.dynamodb import COMPANY_USER_EXISTS, COMPANY_NOT_EXISTING, DELETION_ERROR
from constants.error_messages.dynamodb import EMAIL_NOT_IN_USER_TABLE, INCORRECT_PASSWORD_LENGTH
from constants.constants import updated, added, removed, deleted

from controllers import secrets

from controllers.api_request_error import HandleHTTPException, QueryException
from starlette.exceptions import HTTPException

HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute

# instantiate objects for table classes to query on the tables
user = User()
project = Project()
policy = Policy()
company = Company()


def is_user_in_project(user_id, project_id):
    """Output whether the given user ID is a part of the given project_ID or not."""
    try:
        response = user.table.query(KeyConditionExpression=Key(dynamodb_column_names.User_ID).eq(user_id))
        if not len(response['Items']):
            error_msg = ITEM_MISSING.format("user", user_id)
            return QueryException(detail=f"{error_msg}")
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as err:
        error_msg = QUERY_ERROR.format("user", user_id, err.response['Error']['Code'], err.response['Error']['Message'])
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        for item in response['Items']:
            if project_id in item[dynamodb_column_names.Project_Permissions]:
                user_in_project_using_UserProfile = True
            else:
                user_in_project_using_UserProfile = False

    try:
        response = project.table.query(KeyConditionExpression=Key(
            dynamodb_column_names.Project_ID).eq(project_id))
        if not len(response['Items']):
            error_msg = ITEM_MISSING.format("project", project_id)
            return QueryException(detail=f"{error_msg}")
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as err:
        error_msg = QUERY_ERROR.format("project", project_id, err.response['Error']['Code'],
                                       err.response['Error']['Message'])
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        for item in response['Items']:
            if user_id in item[dynamodb_column_names.Project_Users]:
                user_in_project_using_Project = True
            else:
                user_in_project_using_Project = False

    if 'user_in_project_using_Project' in locals() and 'user_in_project_using_UserProfile' in locals() and \
            user_in_project_using_UserProfile == user_in_project_using_Project:
        return user_in_project_using_Project
    else:
        error_msg = INCONSISTENT_RESULT
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)


def user_details(user_id):
    """Output the details of the user having the given userID from UserProfile table."""
    try:
        response = user.table.query(KeyConditionExpression=Key(dynamodb_column_names.User_ID).eq(user_id))
        if not len(response['Items']):
            error_msg = ITEM_MISSING.format("user", user_id)
            return QueryException(detail=f"{error_msg}")
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as err:
        error_msg = QUERY_ERROR.format("user", user_id, err.response['Error']['Code'], err.response['Error']['Message'])
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        return response['Items'][0]


def list_projects_of_user(user_id):
    """List of projects for the given user."""
    try:
        response = user.table.query(KeyConditionExpression=Key(dynamodb_column_names.User_ID).eq(user_id))
        if not len(response['Items']):
            error_msg = ITEM_MISSING.format("user", user_id)
            return QueryException(detail=f"{error_msg}")
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as err:
        error_msg = QUERY_ERROR.format("user", user_id, err.response['Error']['Code'], err.response['Error']['Message'])
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        # return {project:response['Items'][0][dynamodb_column_names.Project_Permissions][project][0]
        # for project in response['Items'][0][dynamodb_column_names.Project_Permissions]}
        projects = {}
        projects_output = []
        for project_id in response['Items'][0][dynamodb_column_names.Project_Permissions]:
            if response['Items'][0][dynamodb_column_names.Project_Permissions][project_id][0] not in projects:
                projects[response['Items'][0]
                         [dynamodb_column_names.Project_Permissions][project_id][0]] = {}
            projects[response['Items'][0][dynamodb_column_names.Project_Permissions]
                     [project_id][0]][project_id] = True
        for project_name in projects:
            if len(projects[project_name]) > 1:
                for project_id in projects[project_name]:
                    try:
                        response = project.table.query(
                            KeyConditionExpression=Key(dynamodb_column_names.Project_ID).eq(project_id))
                        if not len(response['Items']):
                            error_msg = ITEM_MISSING.format(
                                "project", project_id)
                            return QueryException(detail=f"{error_msg}")
                    except HTTPException as http_error:
                        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code,
                                                     error_message=http_error.detail)
                    except ClientError as err:
                        error_msg = QUERY_ERROR.format("project", project_id, err.response['Error']['Code'],
                                                       err.response['Error']['Message'])
                        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
                    else:
                        projects[project_name][project_id] = {"category": response['Items'][0]
                                                              [dynamodb_column_names.Category],
                                                              "location": response['Items'][0]
                                                              [dynamodb_column_names.Project_Location]}

                        projects_output.append({"project_id": project_id, "project_name": project_name,
                                                "category": response['Items'][0][dynamodb_column_names.Category],
                                                "location": response['Items'][0]
                                                [dynamodb_column_names.Project_Location]})
            else:
                for project_id in projects[project_name]:
                    projects_output.append(
                        {"project_id": project_id, "project_name": project_name})
        return projects_output


def all_project_details_of_user(user_id):
    """All the details of projects in which a user is present."""
    try:
        response = user.table.query(KeyConditionExpression=Key(dynamodb_column_names.User_ID).eq(user_id))
        if not len(response['Items']):
            error_msg = ITEM_MISSING.format("user", user_id)
            return QueryException(detail=f"{error_msg}")
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as err:
        error_msg = QUERY_ERROR.format("user", user_id, err.response['Error']['Code'], err.response['Error']['Message'])
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        projects_output = []
        for project_id in response['Items'][0][dynamodb_column_names.Project_Permissions]:
            try:
                response = project.table.query(KeyConditionExpression=Key(
                    dynamodb_column_names.Project_ID).eq(project_id))
                if not len(response['Items']):
                    error_msg = ITEM_MISSING.format("project", project_id)
                    return QueryException(detail=f"{error_msg}")
            except HTTPException as http_error:
                return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
            except ClientError as err:
                error_msg = QUERY_ERROR.format(
                    "project", project_id, err.response['Error']['Code'], err.response['Error']['Message'])
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
            else:
                projects_output.append(response['Items'][0])
        return projects_output


def project_details(project_id):
    """Output the details of the project having the given projectID from Project table."""
    try:
        response = project.table.query(KeyConditionExpression=Key(
            dynamodb_column_names.Project_ID).eq(project_id))
        if not len(response['Items']):
            error_msg = ITEM_MISSING.format("project", project_id)
            return QueryException(detail=f"{error_msg}")
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as err:
        error_msg = QUERY_ERROR.format(
            "project", project_id, err.response['Error']['Code'], err.response['Error']['Message'])
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        return response['Items'][0]


def is_admin_of_project(user_id, project_id):
    """Output whether the given user_id is an admin of the project having the given project_id."""
    try:
        response = project.table.query(KeyConditionExpression=Key(
            dynamodb_column_names.Project_ID).eq(project_id))
        if not len(response['Items']):
            error_msg = ITEM_MISSING.format("project", project_id)
            return QueryException(detail=f"{error_msg}")
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as err:
        error_msg = QUERY_ERROR.format(
            "project", project_id, err.response['Error']['Code'], err.response['Error']['Message'])
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        for item in response['Items']:
            if user_id in item[dynamodb_column_names.Project_Admins]:
                admin_of_project = True
            else:
                admin_of_project = False
        return admin_of_project


def admin_in_projects(user_id):
    """Admins list of project."""
    projects = []
    try:
        done = False
        start_key = None
        scan_kwargs = {}
        while not done:
            if start_key:
                scan_kwargs['ExclusiveStartKey'] = start_key
            response = project.table.scan(**scan_kwargs)
            for item in response['Items']:
                if user_id in item[dynamodb_column_names.Project_Admins]:
                    projects.append(item[dynamodb_column_names.Project_ID])
            start_key = response.get('LastEvaluatedKey', None)
            done = start_key is None
    except ClientError as err:
        error_msg = SCAN_ERROR.format(
            "projects", err.response['Error']['Code'], err.response['Error']['Message'])
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    return projects


def projects_at_location(location):
    """All projects from specific locations."""
    projects = []
    try:
        done = False
        start_key = None
        scan_kwargs = {}
        while not done:
            if start_key:
                scan_kwargs['ExclusiveStartKey'] = start_key
            response = project.table.scan(**scan_kwargs)
            for item in response['Items']:
                if item[dynamodb_column_names.Project_Location] == location:
                    projects.append(item[dynamodb_column_names.Project_ID])
            start_key = response.get('LastEvaluatedKey', None)
            done = start_key is None
    except ClientError as err:
        error_msg = SCAN_ERROR.format(
            "projects", err.response['Error']['Code'], err.response['Error']['Message'])
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    return projects


def list_user_permissions_in_project(user_id, project_id):
    """User all permision of a project."""
    try:
        response = user.table.query(KeyConditionExpression=Key(dynamodb_column_names.User_ID).eq(user_id))
        if not len(response['Items']):
            error_msg = ITEM_MISSING.format("user", user_id)
            return QueryException(detail=f"{error_msg}")
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as err:
        error_msg = QUERY_ERROR.format("user", user_id, err.response['Error']['Code'], err.response['Error']['Message'])
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        permissions = []
        if project_id in response['Items'][0][dynamodb_column_names.Project_Permissions]:
            policy_id = response['Items'][0][dynamodb_column_names.Project_Permissions][project_id][1]
            try:
                response = policy.table.query(KeyConditionExpression=Key(
                    dynamodb_column_names.Policy_ID).eq(policy_id))
                if not len(response['Items']):
                    error_msg = ITEM_MISSING.format("policy", policy_id)
                    return QueryException(detail=f"{error_msg}")
            except HTTPException as http_error:
                return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
            except ClientError as err:
                error_msg = QUERY_ERROR.format(
                    "policy", policy_id, err.response['Error']['Code'], err.response['Error']['Message'])
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
            else:
                permissions = list(response['Items'][0][dynamodb_column_names.Policy_Details])

        else:
            error_msg = USER_NOT_IN_PROJECT.format(user_id, project_id)
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

        return permissions


def user_has_permission_in_project(user_id, permission, project_id):
    """User has specific permission in specific project."""
    try:
        response = user.table.query(KeyConditionExpression=Key(dynamodb_column_names.User_ID).eq(user_id))
        if not len(response['Items']):
            error_msg = ITEM_MISSING.format("user", user_id)
            return QueryException(detail=f"{error_msg}")
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as err:
        error_msg = QUERY_ERROR.format("user", user_id, err.response['Error']['Code'], err.response['Error']['Message'])
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        has_permission = False
        if project_id in response['Items'][0][dynamodb_column_names.Project_Permissions]:
            policy_id = response['Items'][0][dynamodb_column_names.Project_Permissions][project_id]
            policy_id = policy_id if not isinstance(policy_id, list) else policy_id[1]
            try:
                response = policy.table.query(KeyConditionExpression=Key(
                    dynamodb_column_names.Policy_ID).eq(policy_id))
                if not len(response['Items']):
                    error_msg = ITEM_MISSING.format("policy", policy_id)
                    return QueryException(detail=f"{error_msg}")
            except HTTPException as http_error:
                return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
            except ClientError as err:
                error_msg = QUERY_ERROR.format(
                    "policy", policy_id, err.response['Error']['Code'], err.response['Error']['Message'])
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
            else:
                if permission.lower() in response['Items'][0][dynamodb_column_names.Policy_Details] and \
                        response['Items'][0][dynamodb_column_names.Policy_Details][permission.lower()]:
                    has_permission = True
        return has_permission


def update_permission_of_user_in_project(user_id: str, project_id: str, new_policy_id: str):
    """Update permission of user for a project."""
    response = {}
    try:
        super_admins_list = SuperAdmin.SuperAdmin().get_all_super_admins()
        if user_id in super_admins_list:
            error_msg = SUPER_ADMIN_PERMISSION_UPDATE
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

        user_details = user.table.query(KeyConditionExpression=Key(
            dynamodb_column_names.User_ID).eq(user_id))
        if not len(user_details['Items']):
            error_msg = ITEM_MISSING.format("user", user_id)
            return QueryException(detail=f"{error_msg}")
        user_details = user_details['Items'][0]

        project_details = project.table.query(KeyConditionExpression=Key(
            dynamodb_column_names.Project_ID).eq(project_id))
        if len(project_details['Items']) == 0:
            error_msg = ITEM_MISSING.format("project", project_id)
            return QueryException(detail=f"{error_msg}")
        project_details = project_details['Items'][0]

        if project_id not in user_details[dynamodb_column_names.Project_Permissions] or \
                user_id not in project_details[dynamodb_column_names.Project_Users]:
            error_msg = USER_NOT_IN_PROJECT.format(user_id, project_id)
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

        policy_id = user_details[dynamodb_column_names.Project_Permissions][project_id][1]

        old_policy_details = policy.table.query(KeyConditionExpression=Key(
            dynamodb_column_names.Policy_ID).eq(policy_id))
        if len(old_policy_details['Items']) == 0:
            error_msg = ITEM_MISSING.format("policy", policy_id)
            return QueryException(detail=f"{error_msg}")

        new_policy_details = policy.table.query(KeyConditionExpression=Key(
            dynamodb_column_names.Policy_ID).eq(new_policy_id))
        if len(new_policy_details['Items']) == 0:
            error_msg = ITEM_MISSING.format("policy", new_policy_id)
            return QueryException(detail=f"{error_msg}")

        old_policy = old_policy_details['Items'][0][dynamodb_column_names.Policy_Name]
        new_policy = new_policy_details['Items'][0][dynamodb_column_names.Policy_Name]

        if policy_id == new_policy_id:
            error_msg = POLICY_SAME
            return QueryException(detail=f"{error_msg}")
        else:
            flag = 0
            if old_policy == constants.admin_policy_name:
                if len(project_details[dynamodb_column_names.Project_Admins]) == 1 and \
                    user_id in project_details[dynamodb_column_names.Project_Admins] and \
                        new_policy != constants.admin_policy_name:
                    error_msg = ONLY_ADMIN_CANT_UPDATE
                    return QueryException(detail=f"{error_msg}")
                del (project_details[dynamodb_column_names.Project_Admins][user_id])
                flag = 1
            if new_policy == constants.admin_policy_name:
                project_details[dynamodb_column_names.Project_Admins][user_id] = True
                flag = 1
            user_details[dynamodb_column_names.Project_Permissions][project_id][1] = new_policy_id
            if flag:
                Transactions.UpdateUserUpdateProject(project_details[dynamodb_column_names.Project_ID],
                                                     project_details[dynamodb_column_names.Name_Project],
                                                     project_details[dynamodb_column_names.Project_Location],
                                                     project_details[dynamodb_column_names.History], project_details[
                                                         dynamodb_column_names.Category],
                                                     project_details[dynamodb_column_names.Project_Users],
                                                     project_details[
                                                         dynamodb_column_names.Project_Admins],
                                                     project_details[dynamodb_column_names.Project_Status],
                                                     user_details[dynamodb_column_names.User_ID],
                                                     user_details[dynamodb_column_names.Name_User],
                                                     user_details[dynamodb_column_names.Project_Permissions],
                                                     user_details[
                                                         dynamodb_column_names.Company],
                                                     user_details[dynamodb_column_names.Email],
                                                     user_details[dynamodb_column_names.Contact_No])
            else:
                # user.update_user(user_details[dynamodb_column_names.User_ID],user_details[dynamodb_column_names.Name_User],user_details[dynamodb_column_names.Project_Permissions],\
                #            user_details[dynamodb_column_names.Company],user_details[dynamodb_column_names.Email],user_details[dynamodb_column_names.Contact_No])
                if project_id in user_details[dynamodb_column_names.Current_Project_Policy_Details]:
                    curr_policy_details = new_policy_details['Items'][0][dynamodb_column_names.Policy_Details]
                    curr_policy_details = {project_id: curr_policy_details}
                    user.table.update_item(
                        Key={dynamodb_column_names.User_ID: user_id},
                        UpdateExpression="set " + dynamodb_column_names.Current_Project_Policy_Details +
                        "=:curr_policy," +
                        dynamodb_column_names.Project_Permissions+"=:pp",
                        ExpressionAttributeValues={
                            ':curr_policy': curr_policy_details,
                            ':pp': user_details[dynamodb_column_names.Project_Permissions]},
                        ReturnValues="UPDATED_NEW")
                else:
                    user.table.update_item(
                        Key={dynamodb_column_names.User_ID: user_id},
                        UpdateExpression="set " + dynamodb_column_names.Project_Permissions+"=:pp",
                        ExpressionAttributeValues={
                            ':pp': user_details[dynamodb_column_names.Project_Permissions]},
                        ReturnValues="UPDATED_NEW")
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        error_msg = COMMON_ERROR.format(error)
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        response = updated

    return response


def add_user_to_project(user_id, project_id, policy_id):
    """Add user to project."""
    response = {}
    try:
        user_details = (user.table.query(KeyConditionExpression=Key(dynamodb_column_names.User_ID).eq(user_id)))
        if not len(user_details['Items']):
            error_msg = ITEM_MISSING.format("user", user_id)
            return QueryException(detail=f"{error_msg}")
        user_details = user_details['Items'][0]
        policy_details = (policy.table.query(KeyConditionExpression=Key(
            dynamodb_column_names.Policy_ID).eq(policy_id)))
        if not len(policy_details['Items']):
            error_msg = ITEM_MISSING.format("policy", policy_id)
            return QueryException(detail=f"{error_msg}")
        policy_details = policy_details['Items'][0]

        project_details = (project.table.query(KeyConditionExpression=Key(
            dynamodb_column_names.Project_ID).eq(project_id)))
        if len(project_details['Items']) == 0:
            error_msg = ITEM_MISSING.format("project", project_id)
            return QueryException(detail=f"{error_msg}")
        project_details = project_details['Items'][0]
        if project_id in user_details[dynamodb_column_names.Project_Permissions] or \
                user_id in project_details[dynamodb_column_names.Project_Users]:
            error_msg = USER_ALREADY_IN_PROJECT
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            user_details[dynamodb_column_names.Project_Permissions][project_id] = [
                project_details[dynamodb_column_names.Name_Project], policy_id]
            project_details[dynamodb_column_names.Project_Users][user_id] = user_details[dynamodb_column_names.
                                                                                         Name_User]
            if policy_details[dynamodb_column_names.Policy_Name] == constants.admin_policy_name:
                project_details[dynamodb_column_names.Project_Admins][user_id] = True
            Transactions.UpdateUserUpdateProject(project_details[dynamodb_column_names.Project_ID],
                                                 project_details[dynamodb_column_names.Name_Project],
                                                 project_details[dynamodb_column_names.Project_Location],
                                                 project_details[dynamodb_column_names.History],
                                                 project_details[dynamodb_column_names.Category],
                                                 project_details[dynamodb_column_names.Project_Users], project_details[
                                                     dynamodb_column_names.Project_Admins],
                                                 project_details[dynamodb_column_names.Project_Status],
                                                 user_details[dynamodb_column_names.User_ID],
                                                 user_details[dynamodb_column_names.Name_User],
                                                 user_details[dynamodb_column_names.Project_Permissions], user_details[
                                                     dynamodb_column_names.Company],
                                                 user_details[dynamodb_column_names.Email],
                                                 user_details[dynamodb_column_names.Contact_No])
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        error_msg = COMMON_ERROR.format(error)
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        response = added
    return response


def remove_user_from_project(user_id: str, project_id: str):
    """Remove user from project."""
    response = {}
    try:
        super_admins_list = SuperAdmin.SuperAdmin().get_all_super_admins()
        if user_id in super_admins_list:
            error_msg = CANNOT_SUPER_ADMIN_REMOVE_FROM_PROJECT
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        user_details = (user.table.query(KeyConditionExpression=Key(dynamodb_column_names.User_ID).eq(user_id)))
        if not len(user_details['Items']):
            error_msg = ITEM_MISSING.format("user", user_id)
            return QueryException(detail=f"{error_msg}")
        user_details = user_details['Items'][0]
        project_details = (project.table.query(KeyConditionExpression=Key(
            dynamodb_column_names.Project_ID).eq(project_id)))
        if not len(project_details['Items']):
            error_msg = ITEM_MISSING.format("project", project_id)
            return QueryException(detail=f"{error_msg}")
        project_details = project_details['Items'][0]
        if project_id not in user_details[dynamodb_column_names.Project_Permissions] or \
                user_id not in project_details[dynamodb_column_names.Project_Users]:
            error_msg = USER_NOT_IN_PROJECT.format(user_id, project_id)
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            policy_id = user_details[dynamodb_column_names.Project_Permissions][project_id][1]
            policy_details = (policy.table.query(KeyConditionExpression=Key(
                dynamodb_column_names.Policy_ID).eq(policy_id)))
            if not len(policy_details['Items']):
                error_msg = ITEM_MISSING.format("policy", policy_id)
                return QueryException(detail=f"{error_msg}")
            policy_details = policy_details['Items'][0]
            if policy_details[dynamodb_column_names.Policy_Name] == constants.admin_policy_name:
                if len(project_details[dynamodb_column_names.Project_Admins]) == 1 and \
                      user_id in project_details[dynamodb_column_names.Project_Admins]:
                    error_msg = ONLY_ADMIN_CANT_REMOVE
                    return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
                del (project_details[dynamodb_column_names.Project_Admins][user_id])
            del (project_details[dynamodb_column_names.Project_Users][user_id])
            del (user_details[dynamodb_column_names.Project_Permissions][project_id])
            Transactions.UpdateUserUpdateProject(project_details[dynamodb_column_names.Project_ID],
                                                 project_details[dynamodb_column_names.Name_Project],
                                                 project_details[dynamodb_column_names.Project_Location],
                                                 project_details[dynamodb_column_names.History],
                                                 project_details[dynamodb_column_names.Category],
                                                 project_details[dynamodb_column_names.Project_Users],
                                                 project_details[
                                                     dynamodb_column_names.Project_Admins],
                                                 project_details[dynamodb_column_names.Project_Status],
                                                 user_details[dynamodb_column_names.User_ID],
                                                 user_details[dynamodb_column_names.Name_User],
                                                 user_details[dynamodb_column_names.Project_Permissions],
                                                 user_details[
                                                     dynamodb_column_names.Company],
                                                 user_details[dynamodb_column_names.Email],
                                                 user_details[dynamodb_column_names.Contact_No])
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        error_msg = COMMON_ERROR.format(error)
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        response = removed
    return response


def toggle_status_of_project(project_id: str, Latitude: str, Longitude: str):
    """Toggle status of project."""
    response = {}
    try:
        project_details = (project.table.query(KeyConditionExpression=Key(dynamodb_column_names.Project_ID).
                                               eq(project_id)))
        if len(project_details['Items']) == 0:
            error_msg = ITEM_MISSING.format("project", project_id)
            return QueryException(detail=f"{error_msg}")
        project_details = project_details['Items'][0]
        project_details[dynamodb_column_names.Project_Status] = not (
            project_details[dynamodb_column_names.Project_Status])
        project.update_project(project_details[dynamodb_column_names.Project_ID],
                               project_details[dynamodb_column_names.Name_Project],
                               project_details[dynamodb_column_names.Project_Location],
                               project_details[dynamodb_column_names.History],
                               project_details[dynamodb_column_names.Category],
                               project_details[dynamodb_column_names.Project_Users],
                               project_details[dynamodb_column_names.Project_Admins],
                               project_details[dynamodb_column_names.Project_Status],
                               project_details[dynamodb_column_names.Project_Description],
                               Latitude,
                               Longitude)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except Exception as error:
        error_msg = COMMON_ERROR.format(error)
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        response = updated
    return response


def list_companies():
    """List companies."""
    response = {}
    try:
        done = False
        start_key = None
        scan_kwargs = {}
        while not done:
            if start_key:
                scan_kwargs['ExclusiveStartKey'] = start_key
            company_details = company.table.scan(**scan_kwargs)
            for item in company_details['Items']:
                response[item[dynamodb_column_names.Company_ID]] = item[dynamodb_column_names.Company_Name]
            start_key = company_details.get('LastEvaluatedKey', None)
            done = start_key is None
    except Exception as error:
        error_msg = COMMON_ERROR.format(error)
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        return response


def company_exists(company_name):
    """Check whether company exists."""
    try:
        company_found = False
        ID = ""
        done = False
        start_key = None
        scan_kwargs = {}
        while not done:
            if start_key:
                scan_kwargs['ExclusiveStartKey'] = start_key
            company_details = company.table.scan(**scan_kwargs)
            for item in company_details['Items']:
                if item[dynamodb_column_names.Company_Name] == company_name:
                    ID = item[dynamodb_column_names.Company_ID]
                    company_found = True
                    break
            start_key = company_details.get('LastEvaluatedKey', None)
            done = start_key is None
    except Exception as error:
        error_msg = COMMON_ERROR.format(error)
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        return [company_found, ID]


def delete_company(company_name):
    """Delte company."""
    try:
        exist_details = company_exists(company_name)
        if exist_details[0]:
            user_found = False
            done = False
            start_key = None
            scan_kwargs = {}
            while not done:
                if start_key:
                    scan_kwargs['ExclusiveStartKey'] = start_key
                user_details = user.table.scan(**scan_kwargs)
                for item in user_details['Items']:
                    if item[dynamodb_column_names.Company] == company_name:
                        user_found = True
                        break
                start_key = user_details.get('LastEvaluatedKey', None)
                done = start_key is None
            if not user_found:
                company.delete_company(exist_details[1])
            else:
                error_msg = COMPANY_USER_EXISTS
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            error_msg = COMPANY_NOT_EXISTING
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as err:
        error_msg = DELETION_ERROR.format("company", company_name, err.response['Error']['Code'],
                                          err.response['Error']['Message'])
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        return deleted


def get_user_id(email: str):
    """Get user id by email."""
    try:
        user_found = False
        user_id = ""
        done = False
        start_key = None
        scan_kwargs = {}
        while not done:
            if start_key:
                scan_kwargs['ExclusiveStartKey'] = start_key
            user_details = user.table.scan(**scan_kwargs)
            for item in user_details['Items']:
                if item[dynamodb_column_names.Email] == email:
                    user_found = True
                    user_id = item[dynamodb_column_names.User_ID]
                    break
            start_key = user_details.get('LastEvaluatedKey', None)
            done = start_key is None
        if not user_found:
            error_msg = EMAIL_NOT_IN_USER_TABLE.format(email)
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as error:
        error_msg = COMMON_ERROR.format(error)
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        return user_id


def set_password(user_id: str, password: str):
    """Set password of a user."""
    try:
        if len(password) < 8 or len(password) > 16 or not re.search("[a-z]", password) or\
              not re.search("[A-Z]", password) or not re.search("[0-9]", password):

            error_msg = INCORRECT_PASSWORD_LENGTH
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

        hashed = secrets.get_hashed_secret(password)
        response = user.set_secret_key(user_id, hashed.decode())
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as error:
        error_msg = COMMON_ERROR.format(error)
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        return response


def add_super_admin(user_id: str):
    """Add super admin."""
    try:
        Transactions.AddSuperAdmin(user_id)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as error:
        error_msg = COMMON_ERROR.format(error)
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        return added


def remove_super_admin(user_id: str):
    """Remove super admin."""
    try:
        Transactions.RemoveSuperAdmin(user_id)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as error:
        error_msg = COMMON_ERROR.format(error)
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        return updated


def update_current_project_policy_details(user_id: str, project_id: str):
    """Update current project policy details."""
    try:
        user_details = (user.table.query(KeyConditionExpression=Key(dynamodb_column_names.User_ID).eq(user_id)))
        if not len(user_details['Items']):
            error_msg = ITEM_MISSING.format("user", user_id)
            return QueryException(detail=error_msg)
        user_details = user_details['Items'][0]
        policy_id = user_details[dynamodb_column_names.Project_Permissions][project_id][1]
        # policy_id = Policy_Id
        policy_details = (policy.table.query(KeyConditionExpression=Key(dynamodb_column_names.Policy_ID).eq(policy_id)))
        if not len(policy_details['Items']):
            error_msg = ITEM_MISSING.format("policy", policy_id)
            return QueryException(detail=f"{error_msg}")
        policy_details = policy_details['Items'][0]
        user.table.update_item(
                Key={dynamodb_column_names.User_ID: user_id},
                UpdateExpression="set " + dynamodb_column_names.Current_Project_Policy_Details + "=:curr_policy",
                ExpressionAttributeValues={':curr_policy': {project_id: policy_details[dynamodb_column_names.
                                                                                       Policy_Details]}},
                ReturnValues="UPDATED_NEW")

    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
    except ClientError as error:
        error_msg = COMMON_ERROR.format(error)
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    else:
        return updated
