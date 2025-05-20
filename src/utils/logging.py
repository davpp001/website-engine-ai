import logging
import json
import sys

def setup_logging(level='INFO'):
    logging.basicConfig(
        level=getattr(logging, level),
        format='%(message)s',
        stream=sys.stdout
    )

def log_json(data, level='INFO'):
    msg = json.dumps(data, ensure_ascii=False)
    getattr(logging, level.lower())(msg)
