"""All dynamodb gateway of Company table."""
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from constants.constants import Company_table_name as table_name
from constants import dynamodb_column_names
from constants.constants import created, updated
import uuid
from gateways.dynamodb_gateway import Queries
from controllers.api_request_error import HandleHTTPException, QueryException
from constants.error_messages.dynamodb import COMPANY_ALREADY_EXISTS, COULD_NOT_DELETE_TABLE, DELETION_ERROR
from constants.error_messages.dynamodb import COULD_NOT_UPDATE, COULD_NOT_GET_ITEM, ITEM_MISSING, COULD_NOT_LOAD_DATA
from constants.error_messages.dynamodb import COULD_NOT_ADD, INVALID_ID, COULD_NOT_CHECK_FOR_ID
from constants.http_status_code import COMMON_EXCEPTION_STATUS_CODE
from starlette.exceptions import HTTPException
from gateways.dynamodb_gateway.DbChecks import Check

HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute


class Company:
    """All operations of company table."""

    def __init__(self):
        """Intialize dynamodb connection."""
        self.table = None
        check = Check()
        KeySchema = [
                    {'AttributeName': dynamodb_column_names.Company_ID, 'KeyType': 'HASH'}  # Partition key
                ],
        AttributeDefinitions = [
                    {'AttributeName': dynamodb_column_names.Company_ID, 'AttributeType': 'S'}
                ],
        ProvisionedThroughput = {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
        check.execute(self.table, table_name, KeySchema, AttributeDefinitions, ProvisionedThroughput)

    def add_company(self, name):
        """Add company information to comapny table."""
        try:
            if Queries.company_exists(name)[0]:
                error_msg = COMPANY_ALREADY_EXISTS
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
            id_valid = False
            num_loop = 0
            while not id_valid and num_loop < 10:
                num_loop += 1
                try:
                    id = str(uuid.uuid4())[:8]
                    if len((self.table.query(
                            KeyConditionExpression=Key(dynamodb_column_names.Company_ID).eq(id)))['Items']) == 0:
                        id_valid = True
                except Exception as error:
                    error_msg = COULD_NOT_CHECK_FOR_ID.format(id, table_name, error)
                    return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            if not id_valid:
                error_msg = INVALID_ID
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

            self.table.put_item(
                Item={
                    dynamodb_column_names.Company_ID: id,
                    dynamodb_column_names.Company_Name: name})
        except ClientError as err:
            error_msg = COULD_NOT_ADD.format("company", id, self.table.name,
                                             err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return {id: created}

    def write_batch(self, companies):
        """Add multiple copanies to company table."""
        try:
            with self.table.batch_writer() as writer:
                for company in companies:
                    writer.put_item(Item=company)
        except ClientError as err:
            error_msg = COULD_NOT_LOAD_DATA.format(self.table.name, err.response['Error']['Code'],
                                                   err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

    def get_company(self, company_id):
        """Get specific company using company id."""
        try:
            response = self.table.get_item(Key={dynamodb_column_names.Company_ID: company_id})
            if 'Item' not in response:
                error_msg = ITEM_MISSING.format("company", company_id)
                return QueryException(detail=f"{error_msg}")
        except HTTPException as http_error:
            return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=http_error.detail)
        except ClientError as err:
            error_msg = COULD_NOT_GET_ITEM.format("company", company_id, self.table.name, err.response['Error']['Code'],
                                                  err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return response['Item']

    def update_company(self, company_id, name):
        """Update company details. Currently we only update and store company name."""
        try:
            self.table.update_item(
                Key={dynamodb_column_names.Company_ID: company_id},
                UpdateExpression="set" + dynamodb_column_names.Company_Name + "=:n",
                ExpressionAttributeValues={':n': name},
                ReturnValues="UPDATED_NEW")
        except ClientError as err:
            error_msg = COULD_NOT_UPDATE.format("company", company_id, self.table.name, err.response['Error']['Code'],
                                                err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return updated

    def delete_company(self, company_id):
        """Delete comapny from comapny table."""
        try:
            self.table.delete_item(Key={dynamodb_column_names.Company_ID: company_id})
        except ClientError as err:
            error_msg = DELETION_ERROR.format("company", company_id, err.response['Error']['Code'],
                                              err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)

    def delete_table(self):
        """Delete company table."""
        try:
            self.table.delete()
            self.table = None
        except ClientError as err:
            error_msg = COULD_NOT_DELETE_TABLE.format("company", err.response['Error']['Code'],
                                                      err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
