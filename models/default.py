"""All indepemdemt models."""
from pydantic import BaseModel


class ServerStatusResponseModel(BaseModel):
    """Server status parameter."""

    server_status: int
    server_name: str
