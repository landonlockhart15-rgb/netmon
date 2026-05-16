import ipaddress
import os

from fastapi import HTTPException

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "security_uploads")


def is_private_ip(target: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return target.lower() in ("localhost",)


def require_local_target(target: str, authorization_confirmed: bool = False):
    if not is_private_ip(target) and not authorization_confirmed:
        raise HTTPException(
            status_code=400,
            detail="Set authorization_confirmed=true to test targets outside your local network.",
        )


def require_authorization(authorization_confirmed: bool):
    if not authorization_confirmed:
        raise HTTPException(status_code=400, detail="Authorization required.")


def validate_upload_path(path: str, upload_dir: str = UPLOAD_DIR):
    real_path = os.path.realpath(path)
    real_dir = os.path.realpath(upload_dir)
    if not real_path.startswith(real_dir + os.sep) and real_path != real_dir:
        raise ValueError("Path traversal attempt detected.")
