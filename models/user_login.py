"""All models related to user login."""
from pydantic import BaseModel, Field, EmailStr, SecretStr
from constants.constants import BOTLAB_DYNAMICS_EMAIL


class AddUser(BaseModel):
    """Add user body."""

    mobile_no: str
    email: EmailStr = Field(examples=[BOTLAB_DYNAMICS_EMAIL])
    name: str
    user_type: str
    password: SecretStr = Field(description="Password")
    company: str


class SignupResponse(BaseModel):
    """Signup Api response."""

    mobile_no: str = Field(examples=["+919711491975", "+918882911016"], default="+919711491975",
                           description="Mobile no of user")
    email: EmailStr = Field(examples=[BOTLAB_DYNAMICS_EMAIL], default=BOTLAB_DYNAMICS_EMAIL,
                            description="Email of user. It will be the username of the user")
    name: str = Field(examples=['Om', "Om Prakash", "Om Prakash Prasad"], default="Om Prakash",
                      description="Full name of the user")
    user_type: str = Field(examples=["admin", "video_upload", "video_read"], default="video_upload",
                           description="""user type of the user according to their job""")
    verification_url: str = Field(description="An email will be ent to user email. For his verification")
    change_password_at_verification: bool = Field(description="user is allowed to change password or not",
                                                  default=False, examples=["True", False])


class Login(BaseModel):
    """Login required data."""

    email: EmailStr = Field(examples=[BOTLAB_DYNAMICS_EMAIL], description="Email of user")
    password: SecretStr = Field(description='Password')
