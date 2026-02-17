import logging
import os

_LOGGING_READY = False

def setup_logging(log_dir: str):
    global _LOGGING_READY
    if _LOGGING_READY:
        return

    os.makedirs(log_dir, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s . %(name)s . %(levelname)s . %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(log_dir, "honeypot.log")),
            logging.StreamHandler(),
        ],
    )
    _LOGGING_READY = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
