"""All automated test operations on our Apis."""
# import os
# path = os.path(os.curdir)
# print(path)

# from models import user_login, dynamodb, s3
from constants import constants as constants
from constants import dynamodb_column_names
from fastapi.testclient import TestClient
import json
import random
from backend.main import app
from constants.api_endpoints.account import ACCOUNT_PREFIX, ACCOUNT_LOGIN
from constants.api_endpoints.dynamodb import REMOVE_SUPER_ADMIN, ADD_SUPER_ADMIN, LIST_COMPANIES, ADD_COMPANY
from constants.api_endpoints.dynamodb import TOGGLE_STATUS_OF_PROJECT, UPDATE_PERMISSION_OF_USER, UPDATE_PROJECT
from constants.api_endpoints.dynamodb import ADD_PROJECT, UPDATE_USER, ADD_USER, REMOVE_USER_FROM_PROJECT
from constants.api_endpoints.dynamodb import ADD_USER_TO_PROJECT, DYNAMODB_PREFIX
from constants.http_status_code import COMMON_EXCEPTION_STATUS_CODE, STATUS_OK, STATUS_CREATED
client = TestClient(app=app)


def test_account_login():
    """Credentials to perform test operations on our apis."""
    data = {
        "email": "info9@botlabdynamics.com",
        "password": "320fad23"
    }
    response = client.put(constants.BASE_URL +
                          ACCOUNT_PREFIX + ACCOUNT_LOGIN, json=data)
    assert response.status_code == STATUS_OK


"""
def test_docs():
    response = client.get(constants.BASE_URL+"/docs")
    assert response.status_code == STATUS_OK"""

"""def test_dynamodb_add_user():
    data = {
        "user_name": "Firstname Lastname",
        "company": "BotLab",
        "email": "info211@botlabdynamics.com",
        "contact_no": "+919999999999"
    }
    response = client.post(constants.BASE_URL+DYNAMODB_PREFIX+constants.ADD_USER, json = data)
    assert response.status_code == constants.CREATED"""

"""def test_get_user_id_update_user():
    response = client.get(constants.BASE_URL+DYNAMODB_PREFIX+"/get-user-id/a@gmail.com")
    user_id = response.content
    assert response.status_code == STATUS_OK

def test_update_user():
    data = {
        "user_id": "763be51c",
        "user_name": "HEY",
        "company": "BotLab",
        "email": "a@gmail.com",
        "contact_no": "+919999999999"
    }
    response = client.put(constants.BASE_URL+DYNAMODB_PREFIX+constants.UPDATE_USER, json = data)
    assert response.status_code ==  STATUS_OK"""


def test_overall():
    """All operations to perform test of our App."""
    name_of_user = "Firstname Lastname"
    company = "BotLab"
    email = "info"+str(random.random())+"@botlabdynamics.com"
    contact_no = "+919999999999"
    data = {
        "user_name": name_of_user,
        "company": company,
        "email": email,
        "contact_no": contact_no
    }
    response = client.post(
        constants.BASE_URL+DYNAMODB_PREFIX+ADD_USER, json=data)
    assert response.status_code == STATUS_CREATED

    response = client.get(constants.BASE_URL +
                          DYNAMODB_PREFIX+"/get-user-id/"+email)
    user_id = response.content.decode('ascii')[1:9]
    assert response.status_code == STATUS_OK

    response = client.get(constants.BASE_URL +
                          DYNAMODB_PREFIX+"/user-details/"+user_id)
    response_content = json.loads(response.content.decode())
    assert response_content[dynamodb_column_names.Name_User] == name_of_user and \
        response_content[dynamodb_column_names.Company] == company \
        and response_content[dynamodb_column_names.Email] == email and \
        response_content[dynamodb_column_names.Contact_No] == contact_no
    assert response.status_code == STATUS_OK

    name_of_user = "HEY"
    company = "BLD"
    email = "a"+str(random.random())+"@botlabdynamics.com"
    contact_no = "+919999999999"

    data = {
        "user_id": user_id,
        "user_name": name_of_user,
        "company": company,
        "email": email,
        "contact_no": contact_no
    }
    response = client.put(constants.BASE_URL +
                          DYNAMODB_PREFIX+UPDATE_USER, json=data)
    assert response.status_code == STATUS_OK

    response = client.get(constants.BASE_URL +
                          DYNAMODB_PREFIX+"/user-details/"+user_id)
    response_content = json.loads(response.content.decode())
    assert response_content[dynamodb_column_names.Name_User] == name_of_user and \
        response_content[dynamodb_column_names.Company] == company \
        and response_content[dynamodb_column_names.Email] == email \
        and response_content[dynamodb_column_names.Contact_No] == contact_no
    assert response.status_code == STATUS_OK

    response = client.get(constants.BASE_URL +
                          DYNAMODB_PREFIX+"/projects-of-user/"+user_id)
    response_content = json.loads(response.content.decode())
    assert response.status_code == STATUS_OK
    assert response_content == []

    name_of_project = "Project"+str(random.random())[:6]
    loc = "Delhi"
    history = "d2ed23"
    category = "AIR"
    status = True

    data = {
        "project_name": name_of_project,
        "location": loc,
        "history": history,
        "category": category,
        "status": status,
        "description": ""
    }

    response = client.post(
        constants.BASE_URL+DYNAMODB_PREFIX+ADD_PROJECT, json=data)
    project_id = response.content.decode('ascii')[1:9]
    assert response.status_code == STATUS_CREATED

    response = client.get(constants.BASE_URL +
                          DYNAMODB_PREFIX+"/project-details/"+project_id)
    response_content = json.loads(response.content.decode())
    assert response_content[dynamodb_column_names.Name_Project] == name_of_project and \
        response_content[dynamodb_column_names.Project_Location] == loc \
        and response_content[dynamodb_column_names.History] == history and \
        response_content[dynamodb_column_names.Category] == category \
        and response_content[dynamodb_column_names.Project_Status] == status
    assert response.status_code == STATUS_OK

    data = {
        "project_id": project_id,
        "project_name": name_of_project,
        "location": loc,
        "history": "wrefgrg",
        "category": "WATER",
        "status": status,
        "description": ""
    }
    response = client.put(constants.BASE_URL +
                          DYNAMODB_PREFIX+UPDATE_PROJECT, json=data)

    response = client.get(constants.BASE_URL +
                          DYNAMODB_PREFIX+"/project-details/"+project_id)
    response_content = json.loads(response.content.decode())
    assert response_content[dynamodb_column_names.Name_Project] == data["project_name"] and \
        response_content[dynamodb_column_names.Project_Location] == data["location"] \
        and response_content[dynamodb_column_names.History] == data["history"] and \
        response_content[dynamodb_column_names.Category] == data["category"] \
        and response_content[dynamodb_column_names.Project_Status] == data["status"]
    assert response.status_code == STATUS_OK

    data = {
        "user_id": user_id,
        "project_id": project_id,
        "policy_id": "5d2d3587"
    }
    response = client.put(constants.BASE_URL +
                          DYNAMODB_PREFIX+ADD_USER_TO_PROJECT, json=data)
    assert response.status_code == STATUS_OK

    response = client.get(constants.BASE_URL +
                          DYNAMODB_PREFIX+"/users-of-project/"+project_id)
    response_content = json.loads(response.content.decode())
    assert user_id in response_content
    assert response.status_code == STATUS_OK

    response = client.get(constants.BASE_URL +
                          DYNAMODB_PREFIX+"/projects-of-user/"+user_id)
    response_content = json.loads(response.content.decode())
    flag = False
    for project in response_content:
        if project['project_id'] == project_id:
            flag = True
            break
    assert flag
    assert response.status_code == STATUS_OK

    data = {
        "user_id": user_id,
        "project_id": project_id
    }

    response = client.get(constants.BASE_URL +
                          DYNAMODB_PREFIX+"/admins-of-project/"+project_id)
    json.loads(response.content.decode())
    response = client.put(constants.BASE_URL+DYNAMODB_PREFIX +
                          REMOVE_USER_FROM_PROJECT, json=data)
    response_content = json.loads(response.content.decode())

    if len(response_content) > 1:
        assert response.status_code == STATUS_OK
    else:
        assert response.status_code == COMMON_EXCEPTION_STATUS_CODE

    # data = {
    #    "policy_name":"{\"S\":\"Member\"}",
    #    "policy_details": "{\"M\":{\"read\":{\"BOOL\":True}, \"write\":{\"BOOL\":True}}}"
    # }
    # data = {
    #    "policy_name": "MEMBER",
    #    "policy_details": "{\"read\":{\"M\":{\"BOOL\":True}}}"
    # }
    # assert data["policy_details"]==200

    # response = client.post(constants.BASE_URL+constants.DYNAMODB+constants.ADD_POLICY, json=data)
    # assert response.status_code == constants.CREATED

    data = {
        "user_id": user_id
    }
    response = client.put(constants.BASE_URL +
                          DYNAMODB_PREFIX+ADD_SUPER_ADMIN, json=data)
    assert response.status_code == STATUS_CREATED

    data = {
        "user_id": user_id
    }
    response = client.put(constants.BASE_URL +
                          DYNAMODB_PREFIX+REMOVE_SUPER_ADMIN, json=data)
    assert response.status_code == STATUS_OK

    data = {
        "company_name": "COMPANY"+str(random.random())[:6]
    }
    response = client.post(
        constants.BASE_URL+DYNAMODB_PREFIX+ADD_COMPANY, json=data)
    assert response.status_code == STATUS_CREATED

    response = client.get(constants.BASE_URL+DYNAMODB_PREFIX+LIST_COMPANIES)
    assert response.status_code == STATUS_OK

    data = {
        "project_id": project_id
    }
    response = client.put(constants.BASE_URL+DYNAMODB_PREFIX +
                          TOGGLE_STATUS_OF_PROJECT, json=data)
    assert response.status_code == STATUS_OK

    data = {
        "user_id": user_id,
        "project_id": project_id,
        "policy_id": "dfd9a52d"
    }
    response = client.put(constants.BASE_URL +
                          DYNAMODB_PREFIX+ADD_USER_TO_PROJECT, json=data)
    assert response.status_code == STATUS_OK

    data = {
        "user_id": user_id,
        "project_id": project_id,
        "new_policy_id": "dfd9a52d"
    }
    response = client.put(constants.BASE_URL+DYNAMODB_PREFIX +
                          UPDATE_PERMISSION_OF_USER, json=data)
    assert response.status_code == STATUS_OK

    response = client.get(constants.BASE_URL+DYNAMODB_PREFIX +
                          "/user-permissions-in-project/"+user_id+"/"+project_id)
    assert response.status_code == STATUS_OK

# def test_main_resource():
#     response_auth = client.get("/")
#     assert response_auth.status_code == 200


# def test_dynamodb_user_resource():
#     response_auth = client.get("/dynamodb_user")
#     assert response_auth.status_code == 201

# def test_dynamodb_project_resource():
#      response_auth = client.get("/dynamodb_project")
#      assert response_auth.status_code == 201

# def test_dynamodb_company_resource():
#      response_auth = client.get("/dynamodb_company")
#      assert response_auth.status_code == 201

# def test_dynamodb_policy_resource():
#      response_auth = client.get("/dynamodb_policy")
#      assert response_auth.status_code == 201

# def test_dynamodb_queries_resource():
#      response_auth = client.get("/dynamodb_queries")
#      assert response_auth.status_code == 201

# def test_s3_resource():
#     response_auth = client.get("/s3")
#     assert response_auth.status_code == 200

# def test_s3_list_all_buckets():
#      response_auth = client.get("/s3/list-all-buckets")
#      assert response_auth.status_code == 200

# def test_s3_create_bucket():
#      response_auth = client.post("/s3/create-bucket")
#      assert response_auth.status_code == 200 or response_auth.status_code == 201

# # def test_child_resource():
# #     response_auth = client.get("/api/v1/test")
# #     assert response_auth.status_code == 200
