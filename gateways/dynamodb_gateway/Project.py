"""All dynamodb gateways related to project table."""
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from constants.constants import Project_table_name as table_name, UserProfile_table_name as user_profile_table_name
from constants import dynamodb_column_names
from constants.constants import updated, created
from constants.aws import DYNAMODB_CLIENT
import uuid
from gateways.dynamodb_gateway import Transactions, UserProfile
from controllers.api_request_error import HandleHTTPException, QueryException
from constants.error_messages.dynamodb import DUPLICATE_PROJECT
from constants.error_messages.dynamodb import INVALID_ID, COULD_NOT_CHECK_FOR_ID, COULD_NOT_ADD, COULD_NOT_LOAD_DATA
from constants.error_messages.dynamodb import ITEM_MISSING, COULD_NOT_GET_ITEM, USER_NOT_IN_PROJECT, COULD_NOT_UPDATE
# from constants.error_messages.dynamodb import DELETION_ERROR, COULD_NOT_DELETE_TABLE
from constants.http_status_code import COMMON_EXCEPTION_STATUS_CODE
from starlette.exceptions import HTTPException
from constants.params.dynamodb import MAX_PROJECT_ID_CHECK
from gateways.dynamodb_gateway.DbChecks import Check
HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute
check = Check()


class Project:
    """Dynamoddb Project table all operations."""

    def __init__(self):
        self.table = None
        """Initialize connection to aws dynamodb."""
        KeySchema = [
                    {'AttributeName': dynamodb_column_names.Project_ID, 'KeyType': 'HASH'}  # Partition key
                ],
        AttributeDefinitions = [
                    {'AttributeName': dynamodb_column_names.Project_ID, 'AttributeType': 'S'}
                ],
        ProvisionedThroughput = {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
        check.execute(self.table, table_name, KeySchema, AttributeDefinitions, ProvisionedThroughput)

    def add_project(self, name, location, s3_directory, history, category, status, description, latitude, longitude):
        """Add project in project table."""
        try:
            project_exists = False
            done = False
            start_key = None
            scan_kwargs = {}
            while not done:
                if start_key:
                    scan_kwargs['ExclusiveStartKey'] = start_key
                project_details = self.table.scan(**scan_kwargs)
                for item in project_details['Items']:
                    if item[dynamodb_column_names.Name_Project] == name and \
                       item[dynamodb_column_names.Project_Location] == location and \
                       item[dynamodb_column_names.Category] == category:
                        project_exists = True
                        break
                start_key = project_details.get('LastEvaluatedKey', None)
                done = start_key is None

            if project_exists:
                error_msg = DUPLICATE_PROJECT
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            id_valid = False
            num_loop = 0
            while not id_valid and num_loop < MAX_PROJECT_ID_CHECK:
                num_loop += 1
                try:
                    id = str(uuid.uuid4())[:8]

                    KeyConditionExpression = Key(dynamodb_column_names.Project_ID)
                    if len(self.table.query(KeyConditionExpression=KeyConditionExpression.eq(id))['Items']) == 0:
                        id_valid = True
                except Exception as error:
                    error_msg = COULD_NOT_CHECK_FOR_ID.format(id, table_name, error)
                    return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
            if not id_valid:
                error_msg = INVALID_ID
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            Transactions.AddProjectUpdateUsers(id, name, location, s3_directory, history, category, status, description,
                                               latitude, longitude)

        except ClientError as err:
            error_msg = COULD_NOT_ADD.format("project", id, self.table.name, err.response['Error']['Code'],
                                             err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return {id: created}

    def write_batch(self, projects):
        """Perform batch operations."""
        try:
            with self.table.batch_writer() as writer:
                for project in projects:
                    writer.put_item(Item=project)
        except ClientError as err:
            error_msg = COULD_NOT_LOAD_DATA.format(self.table.name, err.response['Error']['Code'],
                                                   err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return {"status": "SUCCESS"}

    def get_project(self, project_id) -> dict:
        """Get project from project table."""
        try:
            response = self.table.get_item(Key={dynamodb_column_names.Project_ID: project_id})
            if 'Item' not in response:
                error_msg = ITEM_MISSING.format("project", project_id)
                return QueryException(detail=f"{error_msg}")
        except HTTPException as http_error:
            return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
        except ClientError as err:
            error_msg = COULD_NOT_GET_ITEM.format("project", id, self.table.name, err.response['Error']['Code'],
                                                  err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return response['Item']

    def update_project(self, projectID, name, location, history, category, project_users, project_admins, status,
                       description, latitude, longitude):
        """Update pre existing projects in project table."""
        try:
            key_condition_expression = Key(dynamodb_column_names.Project_ID).eq(projectID)
            project_details = self.table.query(KeyConditionExpression=key_condition_expression)
            if len(project_details['Items']) == 0:
                error_msg = ITEM_MISSING.format("project", projectID)
                return QueryException(detail=f"{error_msg}")
            project_details = project_details['Items'][0]
            if name in [None, project_details[dynamodb_column_names.Name_Project]] and \
                location in [None, project_details[dynamodb_column_names.Project_Location]] and \
               history in [None, project_details[dynamodb_column_names.History]] and \
                category in [None, project_details[dynamodb_column_names.Category]] and \
               project_users in [None, project_details[dynamodb_column_names.Project_Users]] and \
                project_admins in [None, project_details[dynamodb_column_names.Project_Admins]] and \
               status in [None, project_details[dynamodb_column_names.Project_Status]] and \
                description in [None, project_details[dynamodb_column_names.Project_Description]] and \
               latitude in [None, project_details[dynamodb_column_names.Latitude]] and \
               longitude in [None, dynamodb_column_names.Longitude]:
                return updated

            if name is None:
                name = project_details[dynamodb_column_names.Name_Project]
            if location is None:
                location = project_details[dynamodb_column_names.Project_Location]
            if history is None:
                history = project_details[dynamodb_column_names.History]
            if category is None:
                category = project_details[dynamodb_column_names.Category]
            if project_users is None:
                project_users = project_details[dynamodb_column_names.Project_Users]
            if project_admins is None:
                project_admins = project_details[dynamodb_column_names.Project_Admins]
            if status is None:
                status = project_details[dynamodb_column_names.Project_Status]
            if description is None:
                description = project_details[dynamodb_column_names.Project_Description]
            if latitude is None:
                latitude = project_details[dynamodb_column_names.Latitude]
            if longitude is None:
                longitude = project_details[dynamodb_column_names.Longitude]

            project_exists = False
            done = False
            start_key = None
            scan_kwargs = {}
            while not done:
                if start_key:
                    scan_kwargs['ExclusiveStartKey'] = start_key
                project_details_scan = self.table.scan(**scan_kwargs)
                for item in project_details_scan['Items']:
                    if item[dynamodb_column_names.Name_Project] == name and \
                       item[dynamodb_column_names.Project_Location] == location and \
                       item[dynamodb_column_names.Category] == category and \
                       item[dynamodb_column_names.Project_ID] != projectID:
                        project_exists = True
                        break
                start_key = project_details_scan.get('LastEvaluatedKey', None)
                done = start_key is None

            if project_exists:
                error_msg = DUPLICATE_PROJECT
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            if project_details[dynamodb_column_names.Name_Project] != name:
                project_users_input = {}
                for user in project_users:
                    project_users_input[user] = {"S": project_users[user]}

                project_admins_input = {}
                for admin in project_admins:
                    project_admins_input[admin] = {"BOOL": project_admins[admin]}

                transaction_items = [{'Update': {
                    'TableName': table_name,
                    'Key': {
                        dynamodb_column_names.Project_ID: {
                            'S': projectID
                        }
                    },
                    'UpdateExpression': "set " + dynamodb_column_names.Name_Project + "=:n," +
                    dynamodb_column_names.Project_Location+"=:l," +
                    dynamodb_column_names.History+"=:h," +
                    dynamodb_column_names.Category+"=:c," +
                    dynamodb_column_names.Project_Users+"=:p_userIDs," +
                    dynamodb_column_names.Project_Admins+"=:p_admins," +
                    dynamodb_column_names.Project_Status+"=:s," +
                    dynamodb_column_names.Project_Description+"=:desc," +
                    dynamodb_column_names.Latitude+"=:lat," +
                    dynamodb_column_names.Longitude+"=:long",
                    'ExpressionAttributeValues': {
                        ':n': {'S': name}, ':l': {'S': location}, ':h': {'S': history}, ':c': {'S': category},
                        ':p_userIDs': {'M': project_users_input},
                        ':p_admins': {'M': project_admins_input}, ':s': {'BOOL': status}, ':desc': {'S': description},
                        ':lat': {'S': latitude}, ':long': {'S': longitude}}
                }
                }]

                for user_id in project_details[dynamodb_column_names.Project_Users]:
                    KeyConditionExpression = Key(dynamodb_column_names.User_ID).eq(user_id)
                    user_details = UserProfile.User().table.query(KeyConditionExpression=KeyConditionExpression)
                    if not len(user_details['Items']):
                        error_msg = ITEM_MISSING.format("user", user_id)
                        return QueryException(detail=f"{error_msg}")
                    projects = user_details['Items'][0][dynamodb_column_names.Project_Permissions]

                    if project_details[dynamodb_column_names.Project_ID] not in projects:
                        error_msg = USER_NOT_IN_PROJECT.format(user_id,
                                                               project_details[dynamodb_column_names.Project_ID])
                        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
                    projects[project_details[dynamodb_column_names.Project_ID]][0] = name

                    project_permissions_input = {}
                    for permission in projects:
                        project_permissions_input[permission] = {"L": [{"S": projects[permission][0]},
                                                                       {"S": projects[permission][1]}]}

                    transaction_items.append({
                     'Update': {
                        'TableName': user_profile_table_name,
                        'Key': {
                            dynamodb_column_names.User_ID: {
                                'S': user_id
                            }
                        },
                        'UpdateExpression': "set " + dynamodb_column_names.Project_Permissions+"=:pp",
                        'ExpressionAttributeValues': {':pp': {"M": project_permissions_input}}
                     }
                    })
                DYNAMODB_CLIENT.transact_write_items(TransactItems=transaction_items)
            else:
                self.table.update_item(
                    Key={dynamodb_column_names.Project_ID: projectID},
                    UpdateExpression="set " + dynamodb_column_names.Name_Project + "=:n," +
                    dynamodb_column_names.Project_Location + "=:l,"
                    + dynamodb_column_names.History + "=:h," + dynamodb_column_names.Category + "=:c," +
                    dynamodb_column_names.Project_Users+"=:p_userIDs," +
                    dynamodb_column_names.Project_Admins + "=:p_admins,"
                    + dynamodb_column_names.Project_Status + "=:s," +
                    dynamodb_column_names.Project_Description + "=:desc,"
                    + dynamodb_column_names.Latitude + "=:lat," + dynamodb_column_names.Longitude + "=:long",
                    ExpressionAttributeValues={
                        ':n': name, ':l': location, ':h': history, ':c': category,
                        ':p_userIDs': project_users, ':p_admins': project_admins, ':s': status, ':desc': description,
                        ':lat': latitude, ':long': longitude},
                    ReturnValues="UPDATED_NEW")
        except ClientError as err:
            error_msg = COULD_NOT_UPDATE.format("project", id, self.table.name, err.response['Error']['Code'],
                                                err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return {"update_status": updated}

    # def delete_project(self, id):
    #     """Delete specific project from project table."""
    #     try:
    #         self.table.delete_item(Key={dynamodb_column_names.Project_ID: id})
    #     except ClientError as err:
    #         error_msg = DELETION_ERROR.format("project", id, err.response['Error']['Code'],
    #                                           err.response['Error']['Message'])
    #         return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

    # def delete_table(self):
    #     """Delete project table from server"""
    #     try:
    #         self.table.delete()
    #         self.table = None
    #     except ClientError as err:
    #         error_msg = COULD_NOT_DELETE_TABLE.format("project", err.response['Error']['Code'],
    #                                                   err.response['Error']['Message'])
            # return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
