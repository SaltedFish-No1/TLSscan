# modules/utils.py

import logging
import traceback

def log_exception(e, domain_name=None):
    """Log exception information, including stack trace."""
    if domain_name:
        logging.error(
            f"Error scanning {domain_name}: {str(e)}\n{traceback.format_exc()}"
        )
    else:
        logging.error(f"{str(e)}\n{traceback.format_exc()}")
