"""Botlab dynamics 3d mapping survey project logger switcher."""
import logging
logging.getLogger().handlers = []
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)
log_format = '%(levelname)s: %(message)s'

# Create a log formatter and set it for the logger
log_formatter = logging.Formatter(log_format)
handler = logging.StreamHandler()  # You can use different handlers depending on where you want to log
handler.setFormatter(log_formatter)
LOGGER.addHandler(handler)
