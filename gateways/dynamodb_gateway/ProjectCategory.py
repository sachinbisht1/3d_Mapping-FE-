"""Dynamodb gateway to perform operations on Projectcategory table."""
from botocore.exceptions import ClientError
# from boto3.dynamodb.conditions import Key
import constants.constants as constants
from constants import dynamodb_column_names
from constants.aws import DYNAMODB_RESOURCE
from controllers.api_request_error import HandleHTTPException
from constants import error_messages as ERROR_MESSAGES
from starlette.exceptions import HTTPException
from gateways.dynamodb_gateway.DbChecks import Check
dyn_resource = DYNAMODB_RESOURCE
table_name = constants.Project_Category_table_name

HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute


class ProjectCategory:
    """All operation of ProjectCategory table."""

    def __init__(self):
        check = Check()
        """Intialize connection to dynamodb resource."""
        self.table = None
        KeySchema = [
                    {'AttributeName': dynamodb_column_names.Project_Category_ID, 'KeyType': 'HASH'}  # Partition key
                ],
        AttributeDefinitions = [
                    {'AttributeName': dynamodb_column_names.Project_Category_ID, 'AttributeType': 'S'}
                ],
        ProvisionedThroughput = {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
        check.execute(self.table, table_name, KeySchema, AttributeDefinitions, ProvisionedThroughput)

    def get_all_categories(self) -> list:
        """Get list of all categories available."""
        try:
            categories = []
            done = False
            start_key = None
            scan_kwargs = {}
            while not done:
                if start_key:
                    scan_kwargs['ExclusiveStartKey'] = start_key
                category_details = self.table.scan(**scan_kwargs)
                for item in category_details['Items']:
                    categories.append(item)
                start_key = category_details.get('LastEvaluatedKey', None)
                done = start_key is None
        except HTTPException as http_error:
            return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
        except ClientError as err:
            error_msg = ERROR_MESSAGES.COULD_NOT_GET_ITEM.format("project ", "categories", self.table.name,
                                                                 err.response['Error']['Code'],
                                                                 err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=constants.COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return categories

    def delete_table(self):
        """Delete category table."""
        try:
            self.table.delete()
            self.table = None
        except ClientError as err:
            error_msg = ERROR_MESSAGES.COULD_NOT_DELETE_TABLE.format("project category", err.response['Error']['Code'],
                                                                     err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=constants.COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
