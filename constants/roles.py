"""Project wide all roles."""
from constants.api_endpoints import dynamodb
from constants.api_endpoints import s3

USER_MANAGEMENT = "read"
SUPER_ADMIN = "super_admin"
PROJECT_ADMIN = "project_admin"
PROJECT_USER = "project_user"
POLICIES_ACCESS_TO_ALL = "POLICIES_ACCESS_TO_ALL"
SUPER_ADMIN_ONLY = "SUPER_ADMIN_ONLY"
PROJECT_MANAGEMENT = "PROJECT_MANAGEMENT"
PROJECT_DETAILS_VIEW = 'PROJECT_DETAILS_VIEW'
VIEW_COMMON_PROJECT_USERS_DETAILS = 'VIEW_COMMON_PROJECT_USERS_DETAILS'
ONLY_SELF = "ONLY_SELF"
SELF_AND_SUPER_ADMIN = "SELF_AND_SUPER_ADMIN"
FRONTEND_SPECIFIC = "FRONTEND_SPECIFIC"
DEVELOPER = 'DEVELOPER'
OWNER = "OWNER"

POLICIES = {
    USER_MANAGEMENT: [f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.ADD_USER_TO_PROJECT}",
                      f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.GET_USER_DETAILS}",
                      f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.USERS_OF_PROJECT}"],
    OWNER: ['*'],
    PROJECT_USER: [f"{s3.S3_PREFIX}/{s3.GET_PROJECT_ALL_OBJECTS}",
                   f"{dynamodb.DYNAMODB_PREFIX}/get-project-details"],
    POLICIES_ACCESS_TO_ALL: ["/docs", f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.PROJECTS_OF_USER}"],
    SUPER_ADMIN_ONLY: [f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.ADD_USER}",
                       f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.UPDATE_USER}",
                       f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.ADD_PROJECT}",
                       f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.LIST_COMPANIES}"],
    PROJECT_MANAGEMENT: [f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.UPDATE_PROJECT}",
                         f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.ADD_USER_TO_PROJECT}",
                         f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.REMOVE_USER_FROM_PROJECT}",
                         f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.UPDATE_PERMISSION_OF_USER}",
                         f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.TOGGLE_STATUS_OF_PROJECT}"],
    PROJECT_DETAILS_VIEW: [f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.GET_PROJECT_DETAILS}",
                           f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.USERS_OF_PROJECT}",
                           f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.ADMINS_OF_PROJECT}"],
    VIEW_COMMON_PROJECT_USERS_DETAILS: [f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.GET_USER_DETAILS}",
                                        f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.USER_PERMISSIONS_IN_PROJECT}"],
    ONLY_SELF: [f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.SET_PASSWORD}"],
    SELF_AND_SUPER_ADMIN: [f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.PROJECTS_OF_USER}",
                           f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.GET_USER_DETAILS}"],
    FRONTEND_SPECIFIC: [f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.GET_USER_ID}",
                        f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.LIST_ALL_CATEGORIES}",
                        f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.LIST_COMPANIES}",
                        f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.CURRENT_PROJECT_POLICY_DETAILS_UPDATE}"],
    DEVELOPER: [f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.ADD_POLICY}", f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.ADD_COMPANY}",
                f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.ADD_SUPER_ADMIN}",
                f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.REMOVE_SUPER_ADMIN}",
                f"{dynamodb.DYNAMODB_PREFIX}{dynamodb.DELETE_COMPANY}"]
}
