"""Dynamodb gateway to userprofile table."""
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
# from constants.logger import LOGGER
from constants import dynamodb_column_names
from constants.aws import DYNAMODB_CLIENT
from constants.constants import updated, created
from constants.constants import UserProfile_table_name as table_name, Super_Admin_table_name, Project_table_name
from constants.http_status_code import COMMON_EXCEPTION_STATUS_CODE
import uuid
from email_validator import validate_email
import phonenumbers
from gateways.dynamodb_gateway import Queries, Company, Project, SuperAdmin
from controllers.api_request_error import HandleHTTPException, QueryException
from constants.error_messages.dynamodb import COULD_NOT_CHECK_FOR_ID, INVALID_ID, COULD_NOT_ADD, COULD_NOT_LOAD_DATA
from constants.error_messages.dynamodb import ITEM_MISSING, COULD_NOT_GET_ITEM, COULD_NOT_UPDATE, DELETION_ERROR
from constants.error_messages.dynamodb import COULD_NOT_DELETE_TABLE, USER_NOT_IN_PROJECT, SCAN_ERROR
from constants.error_messages.dynamodb import INVALID_CONTACT_NO, UPDATED_EMAIL_EXISTS, USER_EXISTING
from starlette.exceptions import HTTPException
import datetime
from constants.utilities_constants import PEPPER_TEXT
import bcrypt
from gateways.dynamodb_gateway.DbChecks import Check
HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute


class User:
    """Dynamodb User Table all methods."""
    def __init__(self):
        check = Check()
        """Intialize connection to dynamodb resource."""
        self.table = None
        KeySchema = [
                    {'AttributeName': dynamodb_column_names.User_ID,
                        'KeyType': 'HASH'}  # Partition key
                ],
        AttributeDefinitions = [
                    {'AttributeName': dynamodb_column_names.User_ID,
                        'AttributeType': 'S'}
                ],
        ProvisionedThroughput = {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
        check.execute(self.table, table_name, KeySchema, AttributeDefinitions, ProvisionedThroughput)

    def add_user(self, name, company, email, contact_no):
        """Add user."""
        try:
            validate_email(email)
            phone_number = phonenumbers.parse(contact_no)
            if not phonenumbers.is_valid_number(phone_number) or not contact_no[1:].isnumeric():
                error_msg = INVALID_CONTACT_NO
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            if self.is_email_in_user_table(email)[0]:
                error_msg = USER_EXISTING
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            id_valid = False
            num_loop = 0
            while not id_valid and num_loop < 10:
                num_loop += 1
                try:
                    id = str(uuid.uuid4())[:8]
                    if len((self.table.query(KeyConditionExpression=Key(dynamodb_column_names.User_ID).
                                             eq(id)))['Items']) == 0:
                        id_valid = True
                except Exception as error:
                    error_msg = COULD_NOT_CHECK_FOR_ID.format(
                        id, table_name, error)
                    return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            if not id_valid:
                error_msg = INVALID_ID
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            if not Queries.company_exists(company)[0]:
                Company.Company().add_company(company)
            self.table.put_item(
                Item={
                    dynamodb_column_names.User_ID: id,
                    dynamodb_column_names.Name_User: name,
                    dynamodb_column_names.Project_Permissions: {},
                    dynamodb_column_names.Company: company,
                    dynamodb_column_names.Email: email,
                    dynamodb_column_names.Contact_No: contact_no,
                    dynamodb_column_names.Secret_Key: "",
                    dynamodb_column_names.Account_Created_At: "",
                    dynamodb_column_names.Temp_Password: "",
                    dynamodb_column_names.Temp_Password_Created_At: ""})

        except ClientError as err:
            error_msg = COULD_NOT_ADD.format(
                "user", id, self.table.name, err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return {id: created}

    def write_batch(self, users):
        """Write users in batch."""
        try:
            with self.table.batch_writer() as writer:
                for user in users:
                    writer.put_item(Item=user)
        except ClientError as err:
            error_msg = COULD_NOT_LOAD_DATA.format(
                self.table.name, err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

    def get_user(self, user_id):
        """Get user details from user table."""
        try:
            response = self.table.get_item(
                Key={dynamodb_column_names.User_ID: user_id})
            if 'Item' not in response:
                error_msg = ITEM_MISSING.format("user", user_id)
                return QueryException(detail=f"{error_msg}")
        except HTTPException as http_error:
            return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
        except ClientError as err:
            error_msg = COULD_NOT_GET_ITEM.format(
                "user", id, self.table.name, err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return response['Item']

    def update_user(self, user_id, name, project_permissions, company, email, contact_no):
        """Update user details."""
        try:
            user_details = self.table.query(KeyConditionExpression=Key(
                dynamodb_column_names.User_ID).eq(user_id))
            if not len(user_details['Items']):
                error_msg = ITEM_MISSING.format("user", user_id)
                return QueryException(detail=f"{error_msg}")
            user_details = user_details['Items'][0]

            if name in [None, user_details[dynamodb_column_names.Name_User]] and \
                project_permissions in [None, user_details[dynamodb_column_names.Project_Permissions]] and \
               company in [None, user_details[dynamodb_column_names.Company]] and \
                email in [None, user_details[dynamodb_column_names.Email]] and \
               contact_no in [None, user_details[dynamodb_column_names.Contact_No]]:
                return updated

            if name is None:
                name = user_details[dynamodb_column_names.Name_User]
            if project_permissions is None:
                project_permissions = user_details[dynamodb_column_names.Project_Permissions]
            if company is None:
                company = user_details[dynamodb_column_names.Company]
            if email is None:
                email = user_details[dynamodb_column_names.Email]
            if contact_no is None:
                contact_no = user_details[dynamodb_column_names.Contact_No]

            validate_email(email)
            phone_number = phonenumbers.parse(contact_no)
            if not phonenumbers.is_valid_number(phone_number) or not contact_no[1:].isnumeric():
                error_msg = INVALID_CONTACT_NO
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
            if self.is_email_in_user_table(email)[0] and self.is_email_in_user_table(email)[1] != user_id:
                error_msg = UPDATED_EMAIL_EXISTS
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            if not Queries.company_exists(company)[0]:
                Company.Company().add_company(company)

            if user_details[dynamodb_column_names.Name_User] != name:
                project_permissions_input = {}
                for permission in project_permissions:
                    project_permissions_input[permission] = {"L": [
                        {"S": project_permissions[permission][0]}, {"S": project_permissions[permission][1]}]}
                transaction_items = [{'Update': {
                    'TableName': table_name,
                    'Key': {
                        dynamodb_column_names.User_ID: {
                            'S': user_id
                        }
                    },
                    'UpdateExpression': "set " + dynamodb_column_names.Name_User + "=:n," +
                    dynamodb_column_names.Company+"=:c," +
                    dynamodb_column_names.Email+"=:e," +
                    dynamodb_column_names.Contact_No+"=:cn," +
                    dynamodb_column_names.Project_Permissions+"=:pp",
                    'ExpressionAttributeValues': {
                        ':n': {'S': name}, ':c': {'S': company}, ':e': {'S': email}, ':cn': {'S': contact_no},
                        ':pp': {'M': project_permissions_input}}
                }
                }]

                if user_id in SuperAdmin.SuperAdmin().get_all_super_admins():
                    transaction_items.append(
                        {'Update': {
                            'TableName': Super_Admin_table_name,
                            'Key': {
                                dynamodb_column_names.Super_Admin_User_ID: {
                                    'S': user_id
                                }
                            },
                            'UpdateExpression': "set " + dynamodb_column_names.Super_Admin_Name + "=:n",
                            'ExpressionAttributeValues': {
                                ':n': {'S': name}}
                        }
                        })

                for project_id in user_details[dynamodb_column_names.Project_Permissions]:
                    project_details = Project.Project().table.query(
                        KeyConditionExpression=Key(dynamodb_column_names.Project_ID).eq(project_id))
                    if len(project_details['Items']) == 0:
                        error_msg = ITEM_MISSING.format("project", project_id)
                        return QueryException(detail=f"{error_msg}")
                    project_users = project_details['Items'][0][dynamodb_column_names.Project_Users]

                    if user_id not in project_users:
                        error_msg = USER_NOT_IN_PROJECT.format(
                            user_id, project_id)
                        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
                    project_users[user_id] = name

                    project_users_input = {}
                    for user in project_users:
                        project_users_input[user] = {"S": project_users[user]}

                    transaction_items.append({
                        'Update': {
                            'TableName': Project_table_name,
                            'Key': {
                                dynamodb_column_names.Project_ID: {
                                    'S': project_id
                                }
                            },
                            'UpdateExpression': "set " + dynamodb_column_names.Project_Users+"=:p_u",
                            'ExpressionAttributeValues': {':p_u': {"M": project_users_input}}
                        }
                    })
                DYNAMODB_CLIENT.transact_write_items(
                    TransactItems=transaction_items)

            else:
                self.table.update_item(
                    Key={dynamodb_column_names.User_ID: user_id},
                    UpdateExpression="set " + dynamodb_column_names.Name_User + "=:n," +
                    dynamodb_column_names.Company+"=:c," +
                    dynamodb_column_names.Email+"=:e," +
                    dynamodb_column_names.Contact_No+"=:cn," +
                    dynamodb_column_names.Project_Permissions+"=:pp",
                    ExpressionAttributeValues={
                        ':n': name, ':c': company, ':e': email, ':cn': contact_no, ':pp': project_permissions},
                    ReturnValues="UPDATED_NEW")
        except ClientError as err:
            error_msg = COULD_NOT_UPDATE.format(
                "user", id, self.table.name, err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        except HTTPException as http_error:
            return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
        else:
            return updated

    def update_temp_password(self, user_id):
        """Update user temp password."""
        try:
            temp_password = str(uuid.uuid4())[:16]
            hashed_temp_password = bcrypt.hashpw(
                f"{temp_password}_-_{PEPPER_TEXT}".encode('utf-8'), bcrypt.gensalt())
            time_step = str(datetime.datetime.now())
            time_step = time_step[:4]+time_step[5:7]+time_step[8:10] + \
                'T'+time_step[11:13]+time_step[14:16]+time_step[17:19]
            self.table.update_item(
                Key={dynamodb_column_names.User_ID: user_id},
                UpdateExpression="set " + dynamodb_column_names.Temp_Password + "=:temp_pass," +
                dynamodb_column_names.Temp_Password_Created_At+"=:temp_pass_created_at",
                ExpressionAttributeValues={
                    ':temp_pass': hashed_temp_password.decode(), ':temp_pass_created_at': time_step},
                ReturnValues="UPDATED_NEW")
        except ClientError as err:
            error_msg = COULD_NOT_UPDATE.format(
                "user", id, self.table.name, err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return temp_password

    def delete_temp_password(self, user_id):
        """Delete user temp password."""
        try:
            self.table.update_item(
                Key={dynamodb_column_names.User_ID: user_id},
                UpdateExpression="set " + dynamodb_column_names.Temp_Password + "=:temp_pass," +
                dynamodb_column_names.Temp_Password_Created_At+"=:temp_pass_created_at",
                ExpressionAttributeValues={
                    ':temp_pass': "", ':temp_pass_created_at': ""},
                ReturnValues="UPDATED_NEW")
        except ClientError as err:
            error_msg = COULD_NOT_UPDATE.format(
                "user", id, self.table.name, err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return "SUCCESS"

    def set_secret_key(self, user_id, secret_key):
        """Set user secret key."""
        try:
            user_details = self.get_user(user_id)
            if user_details[dynamodb_column_names.Account_Created_At] == '' and \
                    user_details[dynamodb_column_names.Secret_Key] == '':
                time_step = str(datetime.datetime.now())
                time_step = time_step[:4]+time_step[5:7]+time_step[8:10] + \
                    'T'+time_step[11:13]+time_step[14:16]+time_step[17:19]
            else:
                time_step = user_details[dynamodb_column_names.Account_Created_At]

            self.table.update_item(
                Key={dynamodb_column_names.User_ID: user_id},
                UpdateExpression="set " + dynamodb_column_names.Secret_Key + "=:secret," +
                dynamodb_column_names.Account_Created_At+"=:account_creation",
                ExpressionAttributeValues={
                    ':secret': secret_key, ':account_creation': time_step},
                ReturnValues="UPDATED_NEW")
        except ClientError as err:
            error_msg = COULD_NOT_UPDATE.format(
                "user", id, self.table.name, err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return "SUCCESS"

    def is_email_in_user_table(self, email_id):
        """User exists in user table or not."""
        try:
            is_email_present = False
            id_of_email = None
            done = False
            start_key = None
            scan_kwargs = {}
            while not done:
                if start_key:
                    scan_kwargs['ExclusiveStartKey'] = start_key
                response = self.table.scan(**scan_kwargs)
                for item in response['Items']:
                    if email_id in item[dynamodb_column_names.Email]:
                        is_email_present = True
                        id_of_email = item[dynamodb_column_names.User_ID]
                        break
                if is_email_present:
                    break
                start_key = response.get('LastEvaluatedKey', None)
                done = start_key is None
        except ClientError as err:
            error_msg = SCAN_ERROR.format(
                "users", err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        return [is_email_present, id_of_email]

    def delete_user(self, id):
        """Delete user from user table."""
        try:
            self.table.delete_item(Key={dynamodb_column_names.User_ID: id})
        except ClientError as err:
            error_msg = DELETION_ERROR.format(
                "user", id, err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

    def delete_table(self):
        """Delete user table from server."""
        try:
            self.table.delete()
            self.table = None
        except ClientError as err:
            error_msg = COULD_NOT_DELETE_TABLE.format(
                "user", err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
