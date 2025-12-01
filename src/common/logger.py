import logging
import json
import os
from datetime import datetime

LOG_DIR = "/app/logs"

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)


class JSONFormatter(logging.Formatter):
    """Format logs as JSON for analysis."""
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "process": record.name,
            "message": record.getMessage(),
        }

        if hasattr(record, "extra_data"):
            log_record["extra"] = record.extra_data

        return json.dumps(log_record)


def get_logger(name):
    """Return a JSON logger writing to /app/logs."""
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # prevent duplicate handlers

    logger.setLevel(logging.INFO)

    log_file = os.path.join(LOG_DIR, f"{name}.log")
    handler = logging.FileHandler(log_file)
    handler.setFormatter(JSONFormatter())

    logger.addHandler(handler)

    return logger
