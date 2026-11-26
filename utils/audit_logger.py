from models import db, AuditLog

def log_audit_event(user_id: int | None, event_type: str, details: str = "", ip_address: str = "127.0.0.1"):
    """
    Log security event to audit_logs table.
    """
    try:
        log_entry = AuditLog(
            user_id=user_id,
            event_type=event_type,
            ip_address=ip_address or "127.0.0.1",
            details=details
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[AuditLogger] Exception recording audit log: {e}")
