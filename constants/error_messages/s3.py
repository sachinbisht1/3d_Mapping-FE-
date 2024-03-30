"""S3 error messages."""
from constants.error_messages.common_error import CONTACT_MANAGER

BUCKET_NOT_CREATED = f"Main Bucket is not yet created, please create bucket. {CONTACT_MANAGER}"
BUCKET_FOUND_BUT_UNABLE_TO_RETURN_ITS_NAME = f"Bucket found but unable to return its name. {CONTACT_MANAGER}"
BUCKET_NOT_FOUND = f"Bucket not found. {CONTACT_MANAGER}"
BUCKET_CREATED_BUT_UNABLE_TO_FIND = f"Bucket is created on aws but we are unable to found it. {CONTACT_MANAGER}"
ONLY_OWNER_IS_ALLOWED_TO_CREATE_BUCKET = "Only owner is allowed to create bucket once"
FAILED_TO_CREATE_BUCKET = "AWS API Failed for creating bucket"
