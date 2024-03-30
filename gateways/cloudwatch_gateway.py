"""All gateways of aws cloudwatch."""
from constants.utilities_constants import CLOUDWATCH_LOG, INTERLEAVED
from constants.aws import CLOUDWATCH_CLIENT
from controllers.utilities import get_unix_millionseconds_count


class CloudwatchGateway:
    """AWS cloudwatch all operations."""

    def __init__(self) -> None:
        """Intialize connection with aws cloudwatch client."""
        self.client = CLOUDWATCH_CLIENT

    def get_latest_log_streams(self):
        """Get cloudwatch latest logs."""
        return self.client.describe_log_streams(
            logGroupName=CLOUDWATCH_LOG if isinstance(CLOUDWATCH_LOG, str) else str(CLOUDWATCH_LOG),
            descending=True
        )

    def get_log_events(self, log_name_streams: list):
        """Get log all events."""
        return self.client.filter_log_events(
            logGroupName=CLOUDWATCH_LOG,
            logStreamNames=[log_name_streams] if not isinstance(log_name_streams, list) else log_name_streams,
            # filterPattern="prod"
        )

    def get_log_stream_name_list(self, log_streams: list):
        """Get streams of cloudwatch logs."""
        return [log_stream.get('logStreamName') for log_stream in log_streams]

    def load_more_logs(self, next_token):
        """Load more logs."""
        return self.client.describe_log_streams(
            logGroupName=CLOUDWATCH_LOG if isinstance(CLOUDWATCH_LOG, str) else str(CLOUDWATCH_LOG),
            descending=True,
            nextToken=next_token
        )

    def get_specific_logs(self, start_date_time: str, end_date_time: str, searched_string: str):
        """Get specific cloudwatch logs between two dates or filter using specific string."""
        start_date_time_millisecond = get_unix_millionseconds_count(start_date_time)
        end_date_time_millisecond = get_unix_millionseconds_count(end_date_time)

        return self.client.filter_log_events(
                        logGroupName=CLOUDWATCH_LOG,
                        startTime=start_date_time_millisecond,
                        endTime=end_date_time_millisecond,
                        filterPattern=searched_string,
                        interleaved=INTERLEAVED
                    )

    def load_more_specific_logs(self, next_token: str):
        """Load more specific logs."""
        return self.client.filter_log_events(
                        logGroupName=CLOUDWATCH_LOG,
                        nextToken=next_token,
                        interleaved=INTERLEAVED
                    )
