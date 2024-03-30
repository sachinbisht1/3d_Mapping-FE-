"""Controls all api errors."""
from fastapi.exceptions import HTTPException
from constants.http_status_code import PERMISSION_DENIED_ERROR_STATUS_CODE, BAD_REQUEST_ERROR_STATUS_CODE
from constants.http_status_code import THIRD_PARTY_API_FAILED_ERROR_STATUS_CODE, COMMON_EXCEPTION_STATUS_CODE
from constants.http_status_code import UNAUTHORIZED_ACCESS_STATUS_CODE, PAGE_NOT_FOUND_STATUS_CODE
from constants.http_status_code import QUERY_EXCEPTION_STATUS_CODE
from constants.error_messages.api import THIRD_PARTY_API_FAILED, PERMISSION_DENIED, UNAUTHORIZED_ACCESS, PAGE_NOT_FOUND

import traceback


# Define a custom exception for third-party API call failure
class ThirdPartyAPIException(HTTPException):
    """Manage thrid party http exception."""

    def __init__(self, detail: str = THIRD_PARTY_API_FAILED):
        """Traceback thrid party api error."""
        super().__init__(status_code=int(THIRD_PARTY_API_FAILED_ERROR_STATUS_CODE), detail=detail)
        traceback.print_exc()
        raise HTTPException(status_code=int(THIRD_PARTY_API_FAILED_ERROR_STATUS_CODE), detail=detail)


# Define a custom exception for common errors
class BadRequestException(HTTPException):
    """Manage bad request http exception."""

    def __init__(self, detail: str):
        """Traceback bad request error."""
        super().__init__(status_code=int(BAD_REQUEST_ERROR_STATUS_CODE), detail=detail)
        traceback.print_exc()
        raise HTTPException(status_code=int(BAD_REQUEST_ERROR_STATUS_CODE), detail=f"{detail}")


class CommonException(HTTPException):
    """Manage common http exceptions."""

    def __init__(self, detail: str):
        """Traceback common error."""
        super().__init__(status_code=int(COMMON_EXCEPTION_STATUS_CODE), detail=detail)
        traceback.print_exc()
        raise HTTPException(status_code=int(COMMON_EXCEPTION_STATUS_CODE), detail=f"{detail}")


class QueryException(HTTPException):
    """Manage all query http exceptions."""

    def __init__(self, detail: str):
        """Traceback query error."""
        super().__init__(status_code=int(QUERY_EXCEPTION_STATUS_CODE), detail=detail)
        traceback.print_exc()
        raise HTTPException(status_code=int(QUERY_EXCEPTION_STATUS_CODE), detail=f"{detail}")


class PermissionException(HTTPException):
    """Manage permissions http exception."""

    def __init__(self, detail: str):
        """Traceback permission error."""
        super().__init__(status_code=int(PERMISSION_DENIED_ERROR_STATUS_CODE), detail=detail)
        traceback.print_exc()
        detail = detail.replace(PERMISSION_DENIED.format(''), '').replace("-->", '').rstrip()
        raise HTTPException(status_code=int(PERMISSION_DENIED_ERROR_STATUS_CODE),
                            detail=f"{PERMISSION_DENIED.format(detail)}")


class UnAuthorizedException(HTTPException):
    """Manage unauthorized http exceptions."""

    def __init__(self, detail: str):
        """Traceback unauthorized error."""
        super().__init__(status_code=int(UNAUTHORIZED_ACCESS_STATUS_CODE), detail=detail)
        traceback.print_exc()
        detail = detail.replace(UNAUTHORIZED_ACCESS.format(''), '').replace("-->", '').rstrip()
        raise HTTPException(status_code=int(UNAUTHORIZED_ACCESS_STATUS_CODE),
                            detail=f"{UNAUTHORIZED_ACCESS.format(detail)}")


class PageNotFoundException(HTTPException):
    """Manage thrid party http exception."""

    def __init__(self, detail: str = PAGE_NOT_FOUND):
        """Traceback page not found error."""
        super().__init__(status_code=int(PAGE_NOT_FOUND_STATUS_CODE), detail=detail)
        traceback.print_exc()
        detail = detail.replace(PAGE_NOT_FOUND.format(''), '').replace("-->", '').rstrip()
        raise HTTPException(status_code=int(PAGE_NOT_FOUND_STATUS_CODE),
                            detail=f"{PAGE_NOT_FOUND.format(detail)}")


class HandleHTTPException:
    """Handle all http exceptions."""

    def __init__(self) -> None:
        """Intialize all http error status code."""
        self.permission_denied_error_code = int(PERMISSION_DENIED_ERROR_STATUS_CODE)
        self.third_party_api_failed_error_code = int(THIRD_PARTY_API_FAILED_ERROR_STATUS_CODE)
        self.unauthorized_access_error_code = int(UNAUTHORIZED_ACCESS_STATUS_CODE)
        self.bad_request_error_status_code = int(BAD_REQUEST_ERROR_STATUS_CODE)
        self.query_error_status_code = int(QUERY_EXCEPTION_STATUS_CODE)

    def execute(self, status_code, error_message):
        """Handle all http exception respective to their http error status code."""
        status_code = int(status_code) if not isinstance(status_code, int) else status_code
        if status_code == self.permission_denied_error_code:
            return PermissionException(detail=PERMISSION_DENIED.format(error_message))
        if status_code == self.bad_request_error_status_code:
            return BadRequestException(detail=error_message)
        if status_code == self.third_party_api_failed_error_code:
            return ThirdPartyAPIException(detail=error_message)
        if status_code == self.unauthorized_access_error_code:
            return UnAuthorizedException(detail=error_message)
        if status_code == self.query_error_status_code:
            return QueryException(detail=error_message)
        return CommonException(detail=error_message)
