"""Read-only Tapo disk status for the isolated recording filesystem."""
import os

from camera_media import STORE


def disk_info():
    total, free, status, writable = 0, 0, "offline", False
    try:
        if os.path.ismount(STORE) and os.path.isfile(STORE / '.tapo-hub-store'):
            usage = os.statvfs(STORE)
            total = usage.f_blocks * usage.f_frsize
            # The setup accepts only an explicitly selected dedicated recording mount.
            if os.stat(STORE).st_dev == os.stat("/").st_dev:
                total, status = 0, "abnormal"
            else:
                free = max(0, min(total, usage.f_bavail * usage.f_frsize))
                writable = not usage.f_flag & os.ST_RDONLY and os.access(STORE, os.W_OK)
                status = "abnormal" if not writable else "normal" if free else "full"
    except OSError:
        total, free, status, writable = 0, 0, "abnormal", False

    # The reference app parses these MB/GB labels in powers of 1024.
    def space(size):
        return f"{size / 1048576:.6f}MB"

    return {"disk_name": "1", "type": "local", "status": status, "detect_status": status,
            "rw_attr": "rw" if writable else "r", "write_protect": "0" if writable else "1",
            "total_space": space(total), "free_space": space(free), "used_space": space(total - free),
            "video_total_space": space(total), "video_free_space": space(free),
            "picture_total_space": "0MB", "picture_free_space": "0MB",
            "msg_push_total_space": "0MB", "msg_push_free_space": "0MB", "percent": "0"}


def command(params):
    section = params.get("harddisk_manage") if isinstance(params, dict) else None
    if (not isinstance(section, dict) or set(params) != {"harddisk_manage"}
            or set(section) != {"table"} or section["table"] not in (["hd_info"], "hd_info")):
        return {"error_code": -40209}
    return {"error_code": 0, "result": {"harddisk_manage": {"hd_info": [{"hd_info_1": disk_info()}]}}}
