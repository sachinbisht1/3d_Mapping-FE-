"""All details related to AWS."""
import boto3
import os

AWS_ACCESS_KEY_ID = os.environ.get("ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("SECRET_ACCESS_KEY")
AWS_REGION_NAME = os.environ.get("DEFAULT_REGION")

BOTO_SESSION = boto3.Session(
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION_NAME
)

DYNAMODB_CLIENT = BOTO_SESSION.client('dynamodb',
                                      #   endpoint_url="http://localhost:8000"    # uncomment for local development
                                      )

DYNAMODB_RESOURCE = BOTO_SESSION.resource("dynamodb",
                                          region_name=AWS_REGION_NAME,
                                          aws_access_key_id=AWS_ACCESS_KEY_ID,
                                          aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                                          #   endpoint_url="http://localhost:8000"    # uncomment for local development
                                          )
S3_CLIENT = BOTO_SESSION.client("s3")

CLOUDWATCH_CLIENT = BOTO_SESSION.client("logs")
