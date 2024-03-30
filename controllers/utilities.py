"""All utilities functions."""
from datetime import datetime, timedelta
from constants.utilities_constants import DATE_TIME_FORMAT
from controllers.api_request_error import CommonException, BadRequestException
from constants.error_messages.utilities import DATE_TIME_FORMAT_IS_WRONG
from constants.error_messages.common_error import PROJECT_ID_IN_COOKIES_IS_MISSING, USER_ID_IN_COOKIES_IS_MISSSING
from typing import Union, Optional
from fastapi import Cookie


def folder_name_by_datetime() -> str:
    """UTC current date time in format DDMMYYYYTHHMMSS."""
    current_date_time = datetime.utcnow()
    return current_date_time.strftime("%d%m%YT%H%M%S")


def parse_date_time_from_str(date_time: str) -> datetime:
    """Parse date time from str."""
    try:
        return datetime.strptime(date_time, DATE_TIME_FORMAT)
    except Exception:
        return CommonException(detail=DATE_TIME_FORMAT_IS_WRONG)


def get_unix_millionseconds_count(date_time: Union[str, datetime]) -> int:
    """Get current unix mSecond count."""
    date_time: datetime = parse_date_time_from_str(date_time) if not isinstance(date_time, datetime) else date_time
    return int(date_time.timestamp()) * 1000


def parse_start_and_end_date_time_from_string(start_date_time: str, end_date_time: str) -> Union[datetime, datetime]:
    """Parse date time from str."""
    if start_date_time and not end_date_time:
        start_date_time = parse_date_time_from_str(date_time=start_date_time)
        end_date_time = start_date_time - timedelta(days=2)
    if not start_date_time and end_date_time:
        end_date_time = parse_date_time_from_str(date_time=end_date_time)
        start_date_time = end_date_time - timedelta(days=2)
    else:
        start_date_time = parse_date_time_from_str(date_time=start_date_time)
        end_date_time = parse_date_time_from_str(date_time=end_date_time)
    return start_date_time, end_date_time


def convert_date_time_object_to_str(date_time: datetime) -> str:
    """Convert datetime object to str."""
    return date_time.strftime(DATE_TIME_FORMAT)


def get_two_days_start_and_end_date_time() -> Union[str, str]:
    """Get date time around 2 days."""
    start_date_time = convert_date_time_object_to_str(datetime.now())
    end_date_time = convert_date_time_object_to_str(datetime.now() - timedelta(days=2))
    return start_date_time, end_date_time


def get_project_id(project_id: Optional[str] = Cookie(None)):
    """Get project id from cookies."""
    if project_id is None:
        return BadRequestException(detail=PROJECT_ID_IN_COOKIES_IS_MISSING)
    return project_id


def get_user_id(user_id: Optional[str] = Cookie(None)):
    """Get user id from cookies."""
    if user_id is None:
        return BadRequestException(detail=USER_ID_IN_COOKIES_IS_MISSSING)
    return user_id
