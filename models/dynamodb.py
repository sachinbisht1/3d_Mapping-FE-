"""This file Define the input format for the DynamoDb Api."""
from pydantic import BaseModel, Field, EmailStr
from typing import Union


class UserIdProjectIdPolicyId(BaseModel):
    """define the input for the add_user_to_project Api."""

    user_id: str = Field(description="User id")
    project_id: str = Field(description="Project id")
    policy_id: str = Field(description="Policy id")


class UserIdProjectId(BaseModel):
    """define the input for the Remover_user_from_project Api."""

    user_id: str = Field(description="User id")
    project_id: str = Field(description="Project id")


class UserId(BaseModel):
    """define the input for the add_super_admin and remove_super_admin Api."""

    user_id: str = Field(description="User id")


class ProjectId(BaseModel):
    """Its Unused Right Now."""

    project_id: str = Field(description="Project id")


class ProjectId_Lat_Long(BaseModel):
    """define the input for the toggle_status_of_project Api."""

    project_id: str = Field(description="Project id")
    Latitude: str = Field(description="latitude")
    Longitude: str = Field(description="longitude")


class CompanyName(BaseModel):
    """define the input for the add_company and delete_company Api."""

    company_name: str = Field(description="Company Name")


class Email(BaseModel):
    """Its Unused Right Now."""

    email: EmailStr = Field(description="Email id of user")


class PolicyNamePolicyDetails(BaseModel):
    """define the input for the add_Policy Api."""

    policy_name: str = Field(description="Policy Name")
    policy_details: Union[dict, str] = Field(description="Policy Details")


class UserIdProjectIdNewPolicyId(BaseModel):
    """define the input for the Update_permission_of_user Api."""

    user_id: str = Field(description="User id")
    project_id: str = Field(description="Project id")
    new_policy_id: str = Field(description="New policy id")


class UserDetails(BaseModel):
    """define the input for the add_User_in_UserProfile_table Api."""

    user_name: str = Field(description="User's name")
    company: str = Field(description="Company name for the user")
    email: EmailStr = Field(description="User's email id")
    contact_no: str = Field(description="Contact No. of the user")


class UserDetailsResponse(BaseModel):
    """Its Unused Right Now."""

    message: str = Field(description="Added")


class UserDetailsWithId(BaseModel):
    """define the input for the Upadate_user Api."""

    user_id: str = Field(description="User id")
    user_name: str = Field(description="User's name", default=None)
    company: str = Field(description="Company name for the user", default=None)
    email: EmailStr = Field(description="User's email id", default=None)
    contact_no: str = Field(
        description="Contact No. of the user", default=None)


class ProjectDetails(BaseModel):
    """define the input for the add_project Api."""

    project_name: str = Field(description="Project Name")
    location: str = Field(description="Location of the project")
    history: str = Field(
        description="path for the file where history is stored")
    category: str = Field(description="Category of the project")
    status: bool = Field(description="Status of the project (True/False)")
    description: str = Field(description="Description of the project")
    latitude: str = Field(description="Latitude of the project location")
    longitude: str = Field(description="Longitude of the project location")


class ProjectDetailsWithId(BaseModel):
    """define the input for the Update_project Api."""

    project_id: str = Field(description="Project id")
    project_name: str = Field(description="Project Name", default=None)
    location: str = Field(description="Location of the project", default=None)
    history: str = Field(
        description="path for the file where history is stored", default=None)
    category: str = Field(description="Category of the project", default=None)
    status: bool = Field(
        description="Status of the project (True/False)", default=None)
    description: str = Field(
        description="Description of the project", default=None)
    latitude: str = Field(
        description="Latitude of the project location", default=None)
    longitude: str = Field(
        description="Longitude of the project location", default=None)


class UserIdPassword(BaseModel):
    """define the input for the Set_password Api."""

    user_id: str = Field(description="User id")
    password: str = Field(description="Password")
