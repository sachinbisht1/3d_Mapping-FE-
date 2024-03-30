"""Api router for all cloudwatch apis."""
from fastapi import APIRouter, responses, HTTPException
from gateways.cloudwatch_gateway import CloudwatchGateway
from constants.error_messages.cloudwatch import CLOUDWATCH_PARAMS_VALIDATION_FAILED, CLOUDWATCH_IS_NOT_WORKING
from constants.error_messages.cloudwatch import FAILED_TO_RETRIEVE_SPECIFIC_CLOUDWATCH_LOGS
from constants.error_messages.cloudwatch import COMMON_ERROR, UNABLE_TO_GET_LOGS_FROM_CLOUDWATCH
from constants.api_endpoints.clodwatch import CLOUDWATCH_STATUS, CLOUDWATCH_DASHBOARD, CLOUDWATCH_RESUME_DASHBOARD
from constants.api_endpoints.clodwatch import CLOUDWATCH_FILTER_STRING, CLOUDWATCH_FILTER_STRING_DATE
from constants.api_endpoints.clodwatch import CLOUDWATCH_FILTER_DATE, CLOUDWATCH_LOAD_MORE_SPECIFIC_LOGS
from constants.http_status_code import COMMON_EXCEPTION_STATUS_CODE, STATUS_OK
from controllers.api_request_error import HandleHTTPException
from controllers.utilities import parse_start_and_end_date_time_from_string, get_two_days_start_and_end_date_time

cloudwatch_router = APIRouter()

CLOUDWATCH_GATEWAY = CloudwatchGateway()
HANDLE_HTTP_EXCEPTION = HandleHTTPException().execute


def get_logs_with_filter(string='', start_date_time='', end_date_time=''):
    """Get cloud watch logs using filter of word or/and time."""
    if not string:
        if not start_date_time or not end_date_time:
            error = CLOUDWATCH_PARAMS_VALIDATION_FAILED.format('Either searched string or both start_date_time and '
                                                               'end_date_time_required')
            return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE,
                                         error_message=error.args)
        start_date_time, end_date_time = parse_start_and_end_date_time_from_string(start_date_time, end_date_time)
    else:
        if not start_date_time and not end_date_time:
            start_date_time, end_date_time = get_two_days_start_and_end_date_time()
    try:
        return CLOUDWATCH_GATEWAY.get_specific_logs(start_date_time=start_date_time,
                                                    end_date_time=end_date_time,
                                                    searched_string=string)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=f"{http_error}")
    except Exception:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE,
                                     error_message=FAILED_TO_RETRIEVE_SPECIFIC_CLOUDWATCH_LOGS)


@cloudwatch_router.get(CLOUDWATCH_STATUS)
def cloudwatch_status():
    """Return status ok if cloudwatch server is running fine."""
    try:
        CLOUDWATCH_GATEWAY.get_latest_log_streams()
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=f"{http_error}")
    except Exception:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE,
                                     error_message=COMMON_ERROR.format(CLOUDWATCH_IS_NOT_WORKING))
    return responses.JSONResponse(content=STATUS_OK, status_code=STATUS_OK)


@cloudwatch_router.get(CLOUDWATCH_DASHBOARD)
def get_latest_log_group_name():
    """Return List of latest log group name."""
    try:
        latest_log_streams = CLOUDWATCH_GATEWAY.get_latest_log_streams()
        next_token = latest_log_streams.get('nextToken')
        log_stream_name = CLOUDWATCH_GATEWAY.get_log_stream_name_list(log_streams=latest_log_streams.get('logStreams'))
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=f"{http_error}")
    except Exception:
        return HANDLE_HTTP_EXCEPTION(COMMON_EXCEPTION_STATUS_CODE,
                                     COMMON_ERROR.format(UNABLE_TO_GET_LOGS_FROM_CLOUDWATCH))
    return responses.JSONResponse(content={"log_streams": log_stream_name,
                                           "next_token": next_token},
                                  status_code=STATUS_OK)


@cloudwatch_router.get(CLOUDWATCH_RESUME_DASHBOARD)
def next_latest_log_group_name(next_token: str):
    """Help to get next logs.

    Parameter

    next_token: next_token fro previous logs
    """
    try:
        latest_log_streams = CLOUDWATCH_GATEWAY.load_more_logs(next_token=next_token)
        log_stream_name = CLOUDWATCH_GATEWAY.get_log_stream_name_list(log_streams=latest_log_streams.get('logStreams'))
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=f"{http_error}")
    except Exception:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE,
                                     error_message=COMMON_ERROR.format(CLOUDWATCH_IS_NOT_WORKING))
    return responses.JSONResponse(content={"log_streams": log_stream_name,
                                           "next_token": latest_log_streams.get('nextToken')},
                                  status_code=STATUS_OK)


@cloudwatch_router.get(CLOUDWATCH_FILTER_DATE)
def get_all_logs_between_dates(start_date_time: str, end_date_time: str):
    """Retrieve all logs between two dates.

    Parameter

    start_date_time: Start date time format is YYYYMMDDTHHMMSS.

    end_date_time: End date time format is YYYYMMDDTHHMMSS.
    """
    try:
        response = get_logs_with_filter(start_date_time=start_date_time, end_date_time=end_date_time)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=f"{http_error}")
    except Exception:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE,
                                     error_message=COMMON_ERROR.format(UNABLE_TO_GET_LOGS_FROM_CLOUDWATCH))
    return responses.JSONResponse(content=response, status_code=STATUS_OK)


@cloudwatch_router.get(CLOUDWATCH_FILTER_STRING)
def get_logs_for_specific_string(searched_string: str):
    """Retrieve specific logs for a query between days.

    Parameter

    searched_string: String for which logs need to retrieve

    """
    try:
        response = get_logs_with_filter(string=searched_string)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=f"{http_error}")
    except Exception:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE,
                                     error_message=COMMON_ERROR.format(UNABLE_TO_GET_LOGS_FROM_CLOUDWATCH))
    return responses.JSONResponse(content=response, status_code=STATUS_OK)


@cloudwatch_router.get(CLOUDWATCH_FILTER_STRING_DATE)
def get_specific_logs_between_two_strings(string: str, start_date_time: str, end_date_time: str):
    """Retrieve specific logs for a query between two dates.

    Parameter

    searched_string: String for which logs need to retrieve
    start_date_time: Start date time format is YYYYMMDDTHHMMSS.
    end_date_time: End date time format is YYYYMMDDTHHMMSS.
    """
    try:
        response = get_logs_with_filter(string=string, start_date_time=start_date_time, end_date_time=end_date_time)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=f"{http_error}")
    except Exception:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE,
                                     error_message=COMMON_ERROR.format(UNABLE_TO_GET_LOGS_FROM_CLOUDWATCH))
    return responses.JSONResponse(content=response, status_code=STATUS_OK)


@cloudwatch_router.get(CLOUDWATCH_LOAD_MORE_SPECIFIC_LOGS)
def load_more_specific_logs(next_token: str):
    """Get more logs for specific search.

    Parameter

    next_token: next_token fro previous logs
    """
    try:
        response = CLOUDWATCH_GATEWAY.load_more_specific_logs(next_token)
    except HTTPException as http_error:
        return HANDLE_HTTP_EXCEPTION(status_code=http_error.status_code, error_message=f"{http_error}")
    except Exception:
        return HANDLE_HTTP_EXCEPTION(status_code=COMMON_EXCEPTION_STATUS_CODE,
                                     error_message=COMMON_ERROR.format(UNABLE_TO_GET_LOGS_FROM_CLOUDWATCH))
    return responses.JSONResponse(content=response, status_code=STATUS_OK)
