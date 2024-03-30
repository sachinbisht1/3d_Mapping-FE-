"""Dynamodb all transactions."""
from constants import dynamodb_column_names
from constants.error_messages.dynamodb import ITEM_MISSING, DUPLICATE_PROJECT, USER_ALREADY_IN_PROJECT
from constants.error_messages.dynamodb import INVALID_CONTACT_NO, UPDATED_EMAIL_EXISTS, ALREADY_A_SUPER_ADMIN
from constants.error_messages.dynamodb import ALREADY_NOT_A_SUPER_ADMIN, SUPER_ADMIN_NOT_REMOVABLE
from constants.aws import DYNAMODB_CLIENT
from constants.http_status_code import COMMON_EXCEPTION_STATUS_CODE
from constants.constants import Project_table_name, UserProfile_table_name, admin_policy_id, Super_Admin_table_name
from controllers.api_request_error import HandleHTTPException, QueryException
from email_validator import validate_email
import phonenumbers
from gateways.dynamodb_gateway import Queries, Company, Project, UserProfile, Policy, SuperAdmin
from boto3.dynamodb.conditions import Key
import datetime

HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute


def UpdateUserUpdateProject(project_id, project_name, location, history, category, project_users, project_admins,
                            status, user_id, user_name, project_permissions, company, email, contact_no):
    """Update user project."""
    # Project related logic
    project_exists = False
    done = False
    start_key = None
    scan_kwargs = {}
    while not done:
        if start_key:
            scan_kwargs['ExclusiveStartKey'] = start_key
        project_details = Project.Project().table.scan(**scan_kwargs)
        for item in project_details['Items']:
            if item[dynamodb_column_names.Name_Project] == project_name and \
                    item[dynamodb_column_names.Project_Location] == location and \
                    item[dynamodb_column_names.Category] == category and \
                    item[dynamodb_column_names.Project_ID] != project_id:
                project_exists = True
                break
        start_key = project_details.get('LastEvaluatedKey', None)
        done = start_key is None

        if project_exists:
            error_msg = DUPLICATE_PROJECT
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

    # User related logic
    validate_email(email)
    phone_number = phonenumbers.parse(contact_no)
    if not phonenumbers.is_valid_number(phone_number) or not contact_no[1:].isnumeric():
        error_msg = INVALID_CONTACT_NO
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
    if UserProfile.User.is_email_in_user_table(email)[0] and \
            UserProfile.User.is_email_in_user_table(email)[1] != user_id:
        error_msg = UPDATED_EMAIL_EXISTS
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

    if not Queries.company_exists(company)[0]:
        Company.Company().add_company(company)

    project_users_input = {}
    for user in project_users:
        project_users_input[user] = {"S": project_users[user]}

    project_admins_input = {}
    for admin in project_admins:
        project_admins_input[admin] = {"BOOL": project_admins[admin]}

    project_permissions_input = {}
    for permission in project_permissions:
        project_permissions_input[permission] = {"L": [
            {"S": project_permissions[permission][0]}, {"S": project_permissions[permission][1]}]}

    user_details = (UserProfile.User.table.query(KeyConditionExpression=Key(dynamodb_column_names.User_ID).eq(user_id)))
    if not len(user_details['Items']):
        error_msg = ITEM_MISSING.format("user", user_id)
        return QueryException(detail=f"{error_msg}")
    user_details = user_details['Items'][0]

    if dynamodb_column_names.Current_Project_Policy_Details in user_details and \
            project_id in user_details[dynamodb_column_names.Current_Project_Policy_Details]:
        if project_id in project_permissions:
            policy_details = (Policy.Policy().table.query(KeyConditionExpression=Key(
                dynamodb_column_names.Policy_ID).eq(project_permissions[project_id][1])))
            if not len(policy_details['Items']):
                error_msg = ITEM_MISSING.format(
                    "policy", project_permissions[project_id][1])
                return QueryException(detail=f"{error_msg}")
            policy_details = policy_details['Items'][0]
            policy = {}
            for detail in policy_details[dynamodb_column_names.Policy_Details]:
                policy[detail] = {"BOOL": True}
            curr_project_policy_details = {"M": {project_id: {"M": policy}}}
        else:
            curr_project_policy_details = {"S": ""}
    else:
        if dynamodb_column_names.Current_Project_Policy_Details in user_details:
            curr_project_policy_details = {"S": ''}
            for project in user_details[dynamodb_column_names.Current_Project_Policy_Details]:
                policy = {}
                for detail in user_details[dynamodb_column_names.Current_Project_Policy_Details][project]:
                    policy[detail] = {"BOOL": True}
                curr_project_policy_details = {"M": {project: {"M": policy}}}
        else:
            curr_project_policy_details = {"S": ""}

    DYNAMODB_CLIENT.transact_write_items(
        TransactItems=[
            {'Update': {
                'TableName': Project_table_name,
                'Key': {
                    dynamodb_column_names.Project_ID: {
                        'S': project_id
                    }
                },
                'UpdateExpression': "set " + dynamodb_column_names.Name_Project + "=:n," +
                dynamodb_column_names.Project_Location+"=:l," +
                dynamodb_column_names.History+"=:h," +
                dynamodb_column_names.Category+"=:c," +
                dynamodb_column_names.Project_Users+"=:p_u," +
                dynamodb_column_names.Project_Admins+"=:p_a," +
                dynamodb_column_names.Project_Status+"=:p_s",
                'ExpressionAttributeValues': {
                    ':n': {'S': project_name}, ':l': {'S': location}, ':h': {'S': history}, ':c': {'S': category},
                    ':p_u': {'M': project_users_input}, ':p_a': {'M': project_admins_input}, ':p_s': {'BOOL': status}}
            }
            },
            {'Update': {
                'TableName': UserProfile_table_name,
                'Key': {
                    dynamodb_column_names.User_ID: {
                        'S': user_id
                    }
                },
                'UpdateExpression': "set " + dynamodb_column_names.Name_User + "=:n," +
                dynamodb_column_names.Company+"=:c," +
                dynamodb_column_names.Email+"=:e," +
                dynamodb_column_names.Contact_No+"=:cn," +
                dynamodb_column_names.Project_Permissions+"=:pp," +
                dynamodb_column_names.Current_Project_Policy_Details+"=:curr_policy",
                'ExpressionAttributeValues': {
                    ':n': {'S': user_name}, ':c': {'S': company}, ':e': {'S': email}, ':cn': {'S': contact_no},
                    ':pp': {'M': project_permissions_input},
                    ':curr_policy': curr_project_policy_details}
            }}
        ])


def AddProjectUpdateUsers(project_id, project_name, location, s3_directory, history, category, status, description,
                          latitude, longitude):
    """Add user project."""
    super_admins_list = SuperAdmin.SuperAdmin().get_all_super_admins()
    project_users = {
        user: {"S": super_admins_list[user]} for user in super_admins_list}
    project_admins = {admin: {"BOOL": True} for admin in super_admins_list}

    time_step = str(datetime.datetime.now())
    time_step = time_step[:4]+time_step[5:7]+time_step[8:10] + \
        'T'+time_step[11:13]+time_step[14:16]+time_step[17:19]

    transaction_items = [
        {
            'Put': {
                'TableName': Project_table_name,
                'Item': {
                    dynamodb_column_names.Project_ID: {"S": project_id},
                    dynamodb_column_names.Name_Project: {"S": project_name},
                    dynamodb_column_names.Project_Location: {"S": location},
                    dynamodb_column_names.S3_Directory: {"S": s3_directory},
                    dynamodb_column_names.History: {"S": history},
                    dynamodb_column_names.Category: {"S": category},
                    dynamodb_column_names.Project_Users: {"M": project_users},
                    dynamodb_column_names.Project_Admins: {"M": project_admins},
                    dynamodb_column_names.Project_Status: {"BOOL": status},
                    dynamodb_column_names.Project_Description: {"S": description},
                    dynamodb_column_names.Latitude: {"S": latitude},
                    dynamodb_column_names.Longitude: {"S": longitude},
                    dynamodb_column_names.Created_At: {"S": time_step}
                }
            }
        }]

    policy_details = (Policy.Policy().table.query(KeyConditionExpression=Key(
        dynamodb_column_names.Policy_ID).eq(admin_policy_id)))
    if not len(policy_details['Items']):
        error_msg = ITEM_MISSING.format("policy", admin_policy_id)
        return QueryException(detail=f"{error_msg}")
    policy_details = policy_details['Items'][0]

    for user_id in super_admins_list:
        user_details = (UserProfile.User.table.query(KeyConditionExpression=Key(dynamodb_column_names.User_ID)
                                                     .eq(user_id)))
        if not len(user_details['Items']):
            error_msg = ITEM_MISSING.format("user", user_id)
            return QueryException(detail=f"{error_msg}")
        project_permissions = user_details['Items'][0][dynamodb_column_names.Project_Permissions]
        if project_id in project_permissions:
            error_msg = USER_ALREADY_IN_PROJECT
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            project_permissions[project_id] = [project_name, admin_policy_id]
            project_permissions_input = {}
            for permission in project_permissions:
                project_permissions_input[permission] = {"L": [
                    {"S": project_permissions[permission][0]}, {"S": project_permissions[permission][1]}]}
            transaction_items.append({
                'Update': {
                    'TableName': UserProfile_table_name,
                    'Key': {
                        dynamodb_column_names.User_ID: {
                            'S': user_id
                        }
                    },
                    'UpdateExpression': "set " + dynamodb_column_names.Project_Permissions+"=:pp",
                    'ExpressionAttributeValues': {':pp': {"M": project_permissions_input}}
                }
            })

    DYNAMODB_CLIENT.transact_write_items(
        TransactItems=transaction_items)


def AddSuperAdmin(user_id: str):
    # UpdateProjectsUpdateUser
    """Add super admin user."""
    super_admins_list = SuperAdmin.SuperAdmin().get_all_super_admins()
    if user_id in super_admins_list:
        error_msg = ALREADY_A_SUPER_ADMIN
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

    user_details = (UserProfile.User.table.query(
        KeyConditionExpression=Key(dynamodb_column_names.User_ID).eq(user_id)))
    if not len(user_details['Items']):
        error_msg = ITEM_MISSING.format("user", user_id)
        return QueryException(detail=f"{error_msg}")
    user_details = user_details['Items'][0]

    policy_details = (Policy.Policy().table.query(KeyConditionExpression=Key(
        dynamodb_column_names.Policy_ID).eq(admin_policy_id)))
    if not len(policy_details['Items']):
        error_msg = ITEM_MISSING.format("policy", admin_policy_id)
        return QueryException(detail=f"{error_msg}")
    policy_details = policy_details['Items'][0]

    transaction_items = []

    project_permissions = {}
    done = False
    start_key = None
    scan_kwargs = {}
    while not done:
        if start_key:
            scan_kwargs['ExclusiveStartKey'] = start_key
        project_details = Project.Project().table.scan(**scan_kwargs)
        for item in project_details['Items']:
            project_permissions[item[dynamodb_column_names.Project_ID]] = [
                item[dynamodb_column_names.Name_Project], admin_policy_id]
            item[dynamodb_column_names.Project_Users][user_id] = user_details[dynamodb_column_names.Name_User]
            item[dynamodb_column_names.Project_Admins][user_id] = True
            project_users_input = {}
            for user in item[dynamodb_column_names.Project_Users]:
                project_users_input[user] = {
                    "S": item[dynamodb_column_names.Project_Users][user]}

            project_admins_input = {}
            for admin in item[dynamodb_column_names.Project_Admins]:
                project_admins_input[admin] = {
                    "BOOL": item[dynamodb_column_names.Project_Admins][admin]}

            transaction_items.append({
                'Update': {
                    'TableName': Project_table_name,
                    'Key': {
                        dynamodb_column_names.Project_ID: {
                            'S': item[dynamodb_column_names.Project_ID]
                        }
                    },
                    'UpdateExpression': "set " + dynamodb_column_names.Project_Users+"=:p_u," +
                    dynamodb_column_names.Project_Admins+"=:p_a",
                    'ExpressionAttributeValues': {':p_u': {"M": project_users_input},
                                                  ':p_a': {"M": project_admins_input}}
                }
            })
        start_key = project_details.get('LastEvaluatedKey', None)
        done = start_key is None

    project_permissions_input = {}
    for permission in project_permissions:
        project_permissions_input[permission] = {"L": [
            {"S": project_permissions[permission][0]}, {"S": project_permissions[permission][1]}]}

    if dynamodb_column_names.Current_Project_Policy_Details in user_details:
        updated_curr_policy = {"S": ''}
        for project_id in user_details[dynamodb_column_names.Current_Project_Policy_Details]:
            policy = {}
            for detail in policy_details[dynamodb_column_names.Policy_Details]:
                policy[detail] = {"BOOL": True}
            updated_curr_policy = {"M": {project_id: {"M": policy}}}
        transaction_items.append({
            'Update': {
                'TableName': UserProfile_table_name,
                'Key': {
                    dynamodb_column_names.User_ID: {
                        'S': user_id
                    }
                },
                'UpdateExpression': "set " + dynamodb_column_names.Project_Permissions+"=:pp,"
                + dynamodb_column_names.Current_Project_Policy_Details+"=:curr_policy,"
                + dynamodb_column_names.Is_Super_Admin+"=:sup_admin",
                'ExpressionAttributeValues': {':pp': {"M": project_permissions_input},
                                              ':curr_policy': updated_curr_policy, ':sup_admin': {"BOOL": True}}
            }
        })
    else:
        transaction_items.append({
            'Update': {
                'TableName': UserProfile_table_name,
                'Key': {
                    dynamodb_column_names.User_ID: {
                        'S': user_id
                    }
                },
                'UpdateExpression': "set " + dynamodb_column_names.Project_Permissions+"=:pp,"
                + dynamodb_column_names.Is_Super_Admin+"=:sup_admin",
                'ExpressionAttributeValues': {':pp': {"M": project_permissions_input}, ':sup_admin': {"BOOL": True}}
            }
        })

    transaction_items.append({
        'Put': {
            'TableName': Super_Admin_table_name,
            'Item': {
                dynamodb_column_names.Super_Admin_User_ID: {"S": user_id},
                dynamodb_column_names.Super_Admin_Name: {
                    "S": user_details[dynamodb_column_names.Name_User]}
            }
        }
    })

    DYNAMODB_CLIENT.transact_write_items(
        TransactItems=transaction_items)


def RemoveSuperAdmin(user_id: str):
    """Remove suoeradmin user."""
    # UpdateProjectsUpdateUser

    super_admins_list = SuperAdmin.SuperAdmin().get_all_super_admins()
    if user_id not in super_admins_list:
        error_msg = ALREADY_NOT_A_SUPER_ADMIN
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

    user_details = (UserProfile.User.table.query(KeyConditionExpression=Key(dynamodb_column_names.User_ID).eq(user_id)))
    if not len(user_details['Items']):
        error_msg = ITEM_MISSING.format("user", user_id)
        return QueryException(detail=f"{error_msg}")
    user_details = user_details['Items'][0]

    transaction_items = []

    done = False
    start_key = None
    scan_kwargs = {}
    while not done:
        if start_key:
            scan_kwargs['ExclusiveStartKey'] = start_key
        project_details = Project.Project().table.scan(**scan_kwargs)
        for item in project_details['Items']:
            Project_id = item[dynamodb_column_names.Project_ID]
            if user_id not in item[dynamodb_column_names.Project_Users] or \
                user_id not in item[dynamodb_column_names.Project_Admins] or \
                    item[dynamodb_column_names.Project_ID] \
                    not in user_details[dynamodb_column_names.Project_Permissions] or \
                    user_details[dynamodb_column_names.Project_Permissions][Project_id][1] != admin_policy_id:
                error_msg = SUPER_ADMIN_NOT_REMOVABLE.format(
                    "project with ID "+item[dynamodb_column_names.Project_ID] +
                    " does not have this user as an admin already")
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            if len(item[dynamodb_column_names.Project_Admins]) == 1:
                error_msg = SUPER_ADMIN_NOT_REMOVABLE.format(
                    "project with ID "+item[dynamodb_column_names.Project_ID]+" has no other admin")
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            del (item[dynamodb_column_names.Project_Users][user_id])
            del (item[dynamodb_column_names.Project_Admins][user_id])

            project_users_input = {}
            for user in item[dynamodb_column_names.Project_Users]:
                project_users_input[user] = {
                    "S": item[dynamodb_column_names.Project_Users][user]}

            project_admins_input = {}
            for admin in item[dynamodb_column_names.Project_Admins]:
                project_admins_input[admin] = {
                    "BOOL": item[dynamodb_column_names.Project_Admins][admin]}

            transaction_items.append({
                'Update': {
                    'TableName': Project_table_name,
                    'Key': {
                        dynamodb_column_names.Project_ID: {
                            'S': item[dynamodb_column_names.Project_ID]
                        }
                    },
                    'UpdateExpression': "set " + dynamodb_column_names.Project_Users+"=:p_u," +
                    dynamodb_column_names.Project_Admins+"=:p_a",
                    'ExpressionAttributeValues': {':p_u': {"M": project_users_input},
                                                  ':p_a': {"M": project_admins_input}}
                }
            })
        start_key = project_details.get('LastEvaluatedKey', None)
        done = start_key is None

    project_permissions_input = {}

    transaction_items.append({
        'Update': {
            'TableName': UserProfile_table_name,
            'Key': {
                dynamodb_column_names.User_ID: {
                    'S': user_id
                }
            },
            'UpdateExpression': "set " + dynamodb_column_names.Project_Permissions+"=:pp," +
            dynamodb_column_names.Current_Project_Policy_Details+"=:curr_policy," +
            dynamodb_column_names.Is_Super_Admin+"=:sup_admin",
            'ExpressionAttributeValues': {':pp': {"M": project_permissions_input}, ':curr_policy': {"S": ''},
                                          ':sup_admin': {"BOOL": False}}
        }
    })

    transaction_items.append({
        'Delete': {
            'TableName': Super_Admin_table_name,
            'Key': {
                dynamodb_column_names.Super_Admin_User_ID: {
                    'S': user_id
                }
            }
        }
    })

    DYNAMODB_CLIENT.transact_write_items(
        TransactItems=transaction_items)
