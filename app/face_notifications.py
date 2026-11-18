"""Native face-notification settings; no cloud transport or fake delivery success."""
DEFAULT = {"msg_push_enabled": "off", "familiar_enable": "off", "stranger_enable": "off",
           "alert_limit": "1", "face_id": []}
MESSAGE_TYPES = {"familiar": "familiarFaceDetected", "stranger": "unfamiliarFaceDetected"}


def configuration(changes, previous=None):
    if not isinstance(changes, dict) or set(changes) - set(DEFAULT):
        raise ValueError("Invalid native notification settings")
    result = {**DEFAULT, **(previous or {}), **changes}
    for field in ("msg_push_enabled", "familiar_enable", "stranger_enable"):
        if result[field] not in ("on", "off"):
            raise ValueError("Invalid notification switch")
    limit = result["alert_limit"]
    if type(limit) not in (int, str) or not str(limit).isdigit() or not 1 <= int(limit) <= 20:
        raise ValueError("Invalid unknown-face threshold")
    result["alert_limit"] = str(int(limit))
    ids = result["face_id"]
    if (not isinstance(ids, list) or len(ids) > 300
            or any(type(value) is not int or not 0 < value < 2**63 for value in ids)):
        raise ValueError("Invalid familiar face selection")
    result["face_id"] = sorted(set(ids))
    return result
