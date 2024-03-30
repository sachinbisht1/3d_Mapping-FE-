"""All S3 gateway."""
from constants.aws import AWS_REGION_NAME
from constants.constants import MAIN_BUCKET_NAME, BOTLAB_DYNAMICS
from constants.logger import LOGGER
from constants.aws import S3_CLIENT
import re

import uuid
from controllers.api_request_error import ThirdPartyAPIException, BadRequestException


class S3:
    """All operations related to S3."""

    def __init__(self) -> None:
        """Intialize connection to S3 client."""
        self.s3_client = S3_CLIENT

    def list_all_bucket(self):
        """List all available s3 buckets."""
        s3_response = self.s3_client.list_buckets()
        buckets_name = []
        for bucket in s3_response['Buckets']:
            buckets_name.append(f"{bucket['Name']}")

        return buckets_name

    # def upload_file(self, file, project_directory, bucket, object_name=None):
    #     file_name = file.filename
    #     if object_name is None:
    #         folder_additional_name = controllers.utilities.folder_name_by_datetime()
    #         object_name = f"{project_directory}/{folder_additional_name}/{file_name}"
    #     try:

    #         self.s3_client.upload_fileobj(file.file, bucket, object_name)
    #         # contents = await file.read()
    #     except:
    #         return False
    #     return True

    # def upload_multiple_file(self, files, bucket, project_directory):
    #     all_file_upload_status = dict()
    #     folder_additional_name = controllers.utilities.folder_name_by_datetime()
    #     for each_file in files:
    #         upload_status = self.upload_file(file=each_file, bucket=bucket,
    #                                          project_directory=project_directory,
    #                                          object_name=f"{project_directory}/{folder_additional_name}/{each_file.filename}")
    #         all_file_upload_status[f"{each_file.filename}"] = f"{upload_status}"

    #     return all_file_upload_status

    def check_bucket_already_exists(self) -> bool:
        """Check whether 3d mapping bucket already exists on aws or not."""
        buckets = self.list_all_bucket()
        for each_bucket in buckets:
            if (MAIN_BUCKET_NAME.lower() in each_bucket.lower()
                    and BOTLAB_DYNAMICS.lower().replace(' ', '-') in each_bucket.lower()):
                # remove 'and not '3d' in each_bucket.lower()' for production
                return True
        return False

    def create_bucket(self):
        """Create 3d mapping bucket on S3."""
        location = {'LocationConstraint': AWS_REGION_NAME}
        s3_unique_id = re.sub(r'\d*-*', '', str(uuid.uuid4()))
        bucket_name = f"{MAIN_BUCKET_NAME}-{BOTLAB_DYNAMICS.lower().replace(' ', '-')}-{s3_unique_id}"
        LOGGER.info(f"bucket name --> {bucket_name}")
        self.s3_client.create_bucket(Bucket=bucket_name.lower(), CreateBucketConfiguration=location)
        return True

    def list_project_objects(self, bucket, project_directory):
        """List all s3 object of specific project."""
        all_object_data = {}
        s3_object_paginator = self.s3_client.get_paginator('list_objects_v2')
        for each_page in s3_object_paginator.paginate(Bucket=bucket, Prefix=project_directory):
            for obj in each_page.get('Contents', {}):
                filename = obj['Key'].split('/')[-1]
                all_object_data[filename] = obj['Key']
            else:
                LOGGER.error("No object found")
                return {"Message": "No data found in "+project_directory}
        return all_object_data

    def get_enterprise_bucket_name(self):
        """Get bucket name."""
        if self.check_bucket_already_exists():
            buckets_name = self.list_all_bucket()
            for each_bucket_name in buckets_name:
                if ("mapping" in each_bucket_name.lower() and
                        BOTLAB_DYNAMICS.lower().replace(' ', '-') in each_bucket_name.lower()):
                    return {"bucket_already_created": True, "bucket_found": True, "bucket_name": each_bucket_name}
            else:
                return {"bucket_already_created": True, "bucket_found": True}
        return {"bucket_already_created": False}

    def genrate_s3_file_presigned_url(self, *, bucket_name: str, object_name: str, expires_in: int = 3600,
                                      method: str = ("get_file", "upload_file")):
        """Generate presigned url of s3 to perform get and put operations."""
        if method == "get_file":
            client_method = "get_object"
        elif method == "upload_file":
            client_method = "put_object"
        else:
            return BadRequestException(detail="Select method either get_file or upload_file not"+str(client_method))

        if not object_name:
            return ThirdPartyAPIException(detail="Object name required to create presigned url")
        if not bucket_name:
            return ThirdPartyAPIException(detail="Bucket name required to create presigned url")

        bucket_name = bucket_name if isinstance(bucket_name, str) else str(bucket_name)
        object_name = object_name if isinstance(object_name, str) else str(object_name)

        presigned_url = self.s3_client.generate_presigned_url(client_method, Params={
            'Bucket': f"{bucket_name}",
            'Key': f"{object_name}"},
            ExpiresIn=expires_in)
        file_name = str(object_name).split("/")[-1]
        return {"pre_signed_url": f"{presigned_url}", "bucket_name": f"{bucket_name}", "object_name": f"{object_name}",
                "file_name": f"{file_name}", "type": method}
