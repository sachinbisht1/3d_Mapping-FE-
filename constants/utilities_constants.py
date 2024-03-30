"""All constants of utilities."""
from dotenv import load_dotenv
import os
load_dotenv()

ACCESS_TOKEN_EXPIRE_MINUTES = 30    # 30 minutes
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
ALGORITHM = "HS256"
JWT_SECRET_KEY = os.environ['JWT_SECRET_KEY']   # should be kept secret
JWT_REFRESH_SECRET_KEY = os.environ['JWT_REFRESH_SECRET_KEY']
PEPPER_TEXT = os.environ['PEPPER_TEXT']
TOKEN_TYPE = "Bearer"
DATE_TIME_FORMAT = "%Y%m%dT%H%M%S"
CLOUDWATCH_LOG = os.environ['CLOUDWATCH_LOG']   # Log group name
INTERLEAVED = bool(os.environ['INTERLEAVED'])   # True
