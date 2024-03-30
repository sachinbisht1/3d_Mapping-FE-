"""All S3 api models."""
from pydantic import BaseModel, Field


class GetUserIdAndProjectId(BaseModel):
    """Get user id and project id in request."""

    user_id: str = Field(description="User id of who is logged in")
    project_id: str = Field(description="Project id of resource")
