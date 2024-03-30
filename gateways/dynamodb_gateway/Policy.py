"""All dynamodb gateway of policy table."""

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from constants.constants import Policy_table_name as table_name
from constants import dynamodb_column_names
from constants.constants import updated, created
import uuid
from controllers.api_request_error import HandleHTTPException, QueryException
from starlette.exceptions import HTTPException
from constants.http_status_code import COMMON_EXCEPTION_STATUS_CODE
from constants.error_messages.dynamodb import COULD_NOT_CHECK_FOR_ID, INVALID_ID, COULD_NOT_ADD, COULD_NOT_LOAD_DATA
from constants.error_messages.dynamodb import ITEM_MISSING, COULD_NOT_GET_ITEM, COULD_NOT_UPDATE, DELETION_ERROR
from constants.error_messages.dynamodb import COULD_NOT_DELETE_TABLE
from gateways.dynamodb_gateway.DbChecks import Check

HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute


class Policy:
    """All operation of policy table."""

    def __init__(self):
        check = Check()
        self.table = None
        """Intialize connection to dynamodb resource."""
        KeySchema = [
                    {'AttributeName': dynamodb_column_names.Policy_ID, 'KeyType': 'HASH'}  # Partition key
                ],
        AttributeDefinitions = [
                    {'AttributeName': dynamodb_column_names.Policy_ID, 'AttributeType': 'S'}
                ],
        ProvisionedThroughput = {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
        check.execute(self.table, table_name, KeySchema, AttributeDefinitions, ProvisionedThroughput)

    def add_policy(self, name, details):
        """Add new policy to policy table data."""
        try:
            id_valid = False
            num_loop = 0
            while not id_valid and num_loop < 10:
                num_loop += 1
                try:
                    id = str(uuid.uuid4())[:8]
                    if len((self.table.query(
                            KeyConditionExpression=Key(dynamodb_column_names.Policy_ID).eq(id)))['Items']) == 0:
                        id_valid = True
                except Exception as error:
                    error_msg = COULD_NOT_CHECK_FOR_ID.format(id, table_name, error)
                    return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            if not id_valid:
                error_msg = INVALID_ID
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            self.table.put_item(
                Item={
                    dynamodb_column_names.Policy_ID: id,
                    dynamodb_column_names.Policy_Name: name,
                    dynamodb_column_names.Policy_Details: details})
        except HTTPException as http_error:
            return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
        except ClientError as err:
            error_msg = COULD_NOT_ADD.format(
                "policy", id, self.table.name, err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return {id: created}

    def write_batch(self, policies):
        """Write multiple policies."""
        try:
            with self.table.batch_writer() as writer:
                for policy in policies:
                    writer.put_item(Item=policy)
        except ClientError as err:
            error_msg = COULD_NOT_LOAD_DATA.format(self.table.name, err.response['Error']['Code'],
                                                   err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

    def get_policy(self, policy_id):
        """Get policy details using policy id."""
        try:
            response = self.table.get_item(Key={dynamodb_column_names.Policy_ID: policy_id})
            if 'Item' not in response:
                error_msg = ITEM_MISSING.format("policy", policy_id)
                return QueryException(detail=f"{error_msg}")
        except HTTPException as http_error:
            return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
        except ClientError as err:
            error_msg = COULD_NOT_GET_ITEM.format("policy", policy_id, self.table.name, err.response['Error']['Code'],
                                                  err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return response['Item']

    def update_policy(self, policy_id, name, details):
        """Update policy name and details using policy id."""
        try:
            self.table.update_item(
                Key={dynamodb_column_names.Policy_ID: policy_id},
                UpdateExpression="set " + dynamodb_column_names.Policy_Name + "=:n" +
                                 dynamodb_column_names.Policy_Details + "=:d",
                ExpressionAttributeValues={':n': name, ':d': details},
                ReturnValues="UPDATED_NEW")
        except ClientError as err:
            error_msg = COULD_NOT_UPDATE.format("policy", policy_id, self.table.name, err.response['Error']['Code'],
                                                err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return updated

    def delete_policy(self, policy_id):
        """Delete policy using policy id."""
        try:
            self.table.delete_item(Key={dynamodb_column_names.Policy_ID: policy_id})
        except ClientError as err:
            error_msg = DELETION_ERROR.format("policy", policy_id, err.response['Error']['Code'],
                                              err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

    def delete_table(self):
        """Delete policy table."""
        try:
            self.table.delete()
            self.table = None
        except ClientError as err:
            error_msg = COULD_NOT_DELETE_TABLE.format("policy", err.response['Error']['Code'],
                                                      err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
