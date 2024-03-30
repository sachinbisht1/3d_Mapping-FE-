"""Default constants."""
import os

BOTLAB_DYNAMICS = "Botlab Dynamics"
BOTLAB_DYNAMICS_URL = "https://botlabdynamics.com/"
BOTLAB_DYNAMICS_EMAIL = 'info@botlabdynamics.com'


# URLS
BASE_URL = "http://localhost:5000"  # test
BASE_ENDPOINT = os.environ.get("BASE_ENDPOINT")


# dynamodb table names
UserProfile_table_name = "UserProfile"
Project_table_name = "Project"
Company_table_name = "Company"
Policy_table_name = "Policy"
Super_Admin_table_name = "SuperAdmin"
Project_Category_table_name = "ProjectCategory"

# Global Constants
ENTERPRISE_NAME = "Kalputru"
MAIN_BUCKET_NAME = "Mapping"
S3_PRESIGNED_URL_EXPIRE_TIME = 3600    # seconds


# request method
GET = "GET"
POST = "POST"
PUT = "PUT"
DELETE = "DELETE"

# Policy names in policy table
admin_policy_name = "Admin"
admin_policy_id = "13b9f0bb"


# Output messages for put and post requests
updated = "UPDATED"
created = "CREATED"
added = "ADDED"
removed = "REMOVED"
deleted = "DELETED"
