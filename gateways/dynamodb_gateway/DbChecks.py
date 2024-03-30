"""Does Checks for Table and Create if does not exists"""
from botocore.exceptions import ClientError
from constants.aws import DYNAMODB_RESOURCE as dyn_resource
from controllers.api_request_error import HandleHTTPException
from constants.error_messages.dynamodb import COULD_NOT_CREATE_TABLE
from constants.error_messages.dynamodb import COULD_NOT_CHECK_FOR_EXISTENCE
from constants.http_status_code import COMMON_EXCEPTION_STATUS_CODE
HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute


class Check:
    """Operation regarding all the tables"""
    def execute(self, table, table_name, KeySchema, AttributeDefinitions, ProvisionedThroughput):
        """Intialize connection to dynamodb resource."""
        self.dyn_resource = dyn_resource
        self.table = table

        table_exists = self.exists(table_name)
        if not table_exists:
            self.create_table(table_name, KeySchema, AttributeDefinitions, ProvisionedThroughput)

    def exists(self, table_name):
        """Check whether table exists or not."""
        try:
            table = self.dyn_resource.Table(table_name)
            table.load()
            exists = True
        except ClientError as err:
            if err.response['Error']['Code'] == 'ResourceNotFoundException':
                exists = False
            else:
                error_msg = COULD_NOT_CHECK_FOR_EXISTENCE.format(table_name, err.response['Error']['Code'],
                                                                 err.response['Error']['Message'])
                return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            self.table = table
        return exists

    def create_table(self, table_name, KeySchema, AttributeDefinitions, ProvisionedThroughput):
        """Create table on server."""
        try:
            self.table = self.dyn_resource.create_table(
                TableName=table_name,
                KeySchema=KeySchema,
                AttributeDefinitions=AttributeDefinitions,
                ProvisionedThroughput=ProvisionedThroughput)
            self.table.wait_until_exists()
        except ClientError as err:
            error_msg = COULD_NOT_CREATE_TABLE.format(table_name,
                                                      err.response['Error']['Code'], err.response['Error']['Message'])
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE, error_message=error_msg)
        else:
            return self.table
