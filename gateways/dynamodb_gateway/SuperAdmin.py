"""All dynamodb gateway of SuperAdmin table."""
from botocore.exceptions import ClientError
# from boto3.dynamodb.conditions import Key
from constants.http_status_code import COMMON_EXCEPTION_STATUS_CODE
from constants.constants import Super_Admin_table_name as table_name
from constants import dynamodb_column_names
from controllers.api_request_error import HandleHTTPException
from constants.error_messages.dynamodb import COULD_NOT_DELETE_TABLE
from constants.error_messages.dynamodb import COULD_NOT_GET_ITEM
from starlette.exceptions import HTTPException
from gateways.dynamodb_gateway.DbChecks import Check
HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute


class SuperAdmin:
    """All operations related to SuperAdmin table."""

    def __init__(self):
        """Initialize connection to dynamodb resource."""
        check = Check()
        self.table = None
        KeySchema = [
                    {'AttributeName': dynamodb_column_names.Super_Admin_User_ID,
                        'KeyType': 'HASH'}  # Partition key
                ],
        AttributeDefinitions = [
                    {'AttributeName': dynamodb_column_names.Super_Admin_User_ID,
                        'AttributeType': 'S'}
                ],
        ProvisionedThroughput = {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
        check.execute(self.table, table_name, KeySchema, AttributeDefinitions, ProvisionedThroughput)

    def get_all_super_admins(self) -> dict:
        """Get all data of available super admins."""
        try:
            super_admins = {}
            done = False
            start_key = None
            scan_kwargs = {}
            while not done:
                if start_key:
                    scan_kwargs['ExclusiveStartKey'] = start_key
                super_admins_details = self.table.scan(**scan_kwargs)
                for item in super_admins_details['Items']:
                    super_admins[item[dynamodb_column_names.Super_Admin_User_ID]
                                 ] = item[dynamodb_column_names.Super_Admin_Name]
                start_key = super_admins_details.get('LastEvaluatedKey', None)
                done = start_key is None
        except HTTPException as http_error:
            return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
        except ClientError as err:
            error_msg = COULD_NOT_GET_ITEM.format(
                "super ", "admins", self.table.name, err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return super_admins

    def delete_table(self):
        """Delete SuperAdmin table from server."""
        try:
            self.table.delete()
            self.table = None
        except ClientError as err:
            error_msg = COULD_NOT_DELETE_TABLE.format(
                "super admin", err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
