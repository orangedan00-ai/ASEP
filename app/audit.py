from .db import add_audit

def log(cfg, action, target="", status="OK", details=""):
    add_audit(cfg, action, target, status, details)
