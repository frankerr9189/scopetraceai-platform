"""
Audit logger for Jira write-back operations.

Persists audit trail of all write-back operations for compliance and debugging.
"""
import json
import os
from datetime import datetime
from typing import Dict, Any
from pathlib import Path


class AuditLogger:
    """Audit logger for write-back operations."""
    
    def __init__(self, log_dir: str = "audit_logs"):
        """
        Initialize audit logger.
        
        Args:
            log_dir: Directory to store audit logs (default: "audit_logs")
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
    
    def log_event(self, event: Dict[str, Any]) -> None:
        """
        Log an audit event to persistent storage.
        
        Persists:
        - package_id
        - jira_issue_key
        - fields_modified
        - approved_by
        - executed_at
        - checksum
        - jira_response_id
        - result (success | skipped)
        
        Args:
            event: Event dictionary with required fields
        """
        # Ensure required fields are present
        required_fields = [
            "package_id",
            "jira_issue_key",
            "fields_modified",
            "approved_by",
            "executed_at",
            "checksum",
            "result"
        ]
        
        for field in required_fields:
            if field not in event:
                raise ValueError(f"Missing required audit field: {field}")
        
        # Add timestamp if not present
        if "executed_at" not in event or not event["executed_at"]:
            event["executed_at"] = datetime.now().isoformat()
        
        # Create log entry
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "package_id": event.get("package_id"),
            "jira_issue_key": event.get("jira_issue_key"),
            "fields_modified": event.get("fields_modified", []),
            "approved_by": event.get("approved_by"),
            "executed_at": event.get("executed_at"),
            "checksum": event.get("checksum"),
            "jira_response_id": event.get("jira_response_id"),
            "result": event.get("result")
        }
        
        # Write to log file (one file per day for easier management)
        log_date = datetime.now().strftime("%Y-%m-%d")
        log_file = self.log_dir / f"audit_{log_date}.jsonl"
        
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            # Log to stderr if file write fails (don't fail the operation)
            import sys
            print(f"Failed to write audit log: {e}", file=sys.stderr)

