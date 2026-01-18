"""
Jira client for fetching ticket data, sub-tickets, and attachment metadata.

This module provides safe, read-only access to Jira tickets for contextual analysis.
It does NOT write back to Jira, parse attachment contents, or modify tickets.
"""
from typing import Dict, Any, List, Optional
import os
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime


class JiraClientError(Exception):
    """Raised when Jira API calls fail."""
    pass


class JiraClient:
    """Client for fetching Jira ticket data."""
    
    def __init__(
        self,
        jira_base_url: Optional[str] = None,
        jira_email: Optional[str] = None,
        jira_api_token: Optional[str] = None
    ):
        """
        Initialize Jira client.
        
        Args:
            jira_base_url: Jira instance URL (e.g., "https://yourcompany.atlassian.net")
            jira_email: Jira user email for authentication
            jira_api_token: Jira API token for authentication
        """
        self.jira_url = (jira_base_url or os.getenv("JIRA_BASE_URL", "")).rstrip("/")
        self.jira_email = jira_email or os.getenv("JIRA_EMAIL", "")
        self.jira_api_token = jira_api_token or os.getenv("JIRA_API_TOKEN", "")
        
        if not self.jira_url:
            raise JiraClientError("JIRA_BASE_URL environment variable not set")
        if not self.jira_email:
            raise JiraClientError("JIRA_EMAIL environment variable not set")
        if not self.jira_api_token:
            raise JiraClientError("JIRA_API_TOKEN environment variable not set")
    
    def _make_request(self, endpoint: str) -> Dict[str, Any]:
        """
        Make authenticated request to Jira API.
        
        Args:
            endpoint: API endpoint (e.g., "/rest/api/3/issue/KEY-123")
            
        Returns:
            JSON response from Jira API
            
        Raises:
            JiraClientError: If request fails
        """
        url = f"{self.jira_url}{endpoint}"
        auth = HTTPBasicAuth(self.jira_email, self.jira_api_token)
        headers = {"Accept": "application/json"}
        
        try:
            response = requests.get(url, auth=auth, headers=headers, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise JiraClientError(f"Jira API request failed: {str(e)}")
    
    def fetch_ticket(self, ticket_id: str) -> Dict[str, Any]:
        """
        Fetch a Jira ticket with full details.
        
        Args:
            ticket_id: Jira ticket ID (e.g., "ATA-36")
            
        Returns:
            Dictionary containing ticket data:
            - ticket_id
            - summary
            - description
            - acceptance_criteria (if present)
            - status
            - issue_type
            - priority
        """
        try:
            # Fetch issue with fields
            issue = self._make_request(
                f"/rest/api/3/issue/{ticket_id}?fields=summary,description,status,issuetype,priority,customfield_*"
            )
            
            # Extract acceptance criteria if present (common custom fields)
            acceptance_criteria = None
            for field_key, field_value in issue.get("fields", {}).items():
                if "acceptance" in field_key.lower() and field_value:
                    if isinstance(field_value, str):
                        acceptance_criteria = field_value
                    elif isinstance(field_value, dict) and "content" in field_value:
                        # ADF format - extract text
                        acceptance_criteria = self._extract_adf_text(field_value)
                    break
            
            # Build ticket data
            fields = issue.get("fields", {})
            ticket_data = {
                "ticket_id": ticket_id,
                "summary": fields.get("summary", ""),
                "description": self._extract_description(fields.get("description")),
                "acceptance_criteria": acceptance_criteria,
                "status": fields.get("status", {}).get("name", "Unknown"),
                "issue_type": fields.get("issuetype", {}).get("name", "Unknown"),
                "priority": fields.get("priority", {}).get("name", "Unknown") if fields.get("priority") else None
            }
            
            return ticket_data
        except JiraClientError:
            raise
        except Exception as e:
            raise JiraClientError(f"Failed to fetch ticket {ticket_id}: {str(e)}")
    
    def fetch_sub_tickets(self, parent_ticket_id: str) -> List[Dict[str, Any]]:
        """
        Fetch sub-tickets (sub-tasks) for a parent ticket (metadata only).
        
        This method is non-blocking - all failures return empty list to ensure
        parent ticket analysis is never blocked by sub-ticket fetch issues.
        
        Args:
            parent_ticket_id: Parent Jira ticket ID
            
        Returns:
            List of dictionaries containing sub-ticket metadata:
            - sub_ticket_id
            - summary/title
            - issue_type
            - status
            Returns empty list if fetch fails (non-blocking)
        """
        try:
            # Approach 1: Try fetching subtasks field directly from parent ticket
            # This is more reliable than JQL search and works with most Jira instances
            try:
                issue = self._make_request(
                    f"/rest/api/3/issue/{parent_ticket_id}?fields=subtasks"
                )
                fields = issue.get("fields", {})
                
                sub_tickets = []
                # Check for subtasks field
                if "subtasks" in fields and fields["subtasks"]:
                    for subtask in fields["subtasks"]:
                        sub_tickets.append({
                            "sub_ticket_id": subtask.get("key", ""),
                            "summary": subtask.get("fields", {}).get("summary", ""),
                            "issue_type": subtask.get("fields", {}).get("issuetype", {}).get("name", "Unknown"),
                            "status": subtask.get("fields", {}).get("status", {}).get("name", "Unknown")
                        })
                
                if sub_tickets:
                    return sub_tickets
            except (JiraClientError, Exception):
                # Subtasks field approach failed, try JQL
                pass
            
            # Approach 2: Use parent field in JQL (fallback)
            try:
                jql = f'parent = {parent_ticket_id}'
                response = self._make_request(
                    f"/rest/api/3/search?jql={jql}&fields=summary,issuetype,status&maxResults=100"
                )
                
                sub_tickets = []
                for issue in response.get("issues", []):
                    fields = issue.get("fields", {})
                    sub_tickets.append({
                        "sub_ticket_id": issue.get("key", ""),
                        "summary": fields.get("summary", ""),
                        "issue_type": fields.get("issuetype", {}).get("name", "Unknown"),
                        "status": fields.get("status", {}).get("name", "Unknown")
                    })
                
                return sub_tickets
            except (JiraClientError, Exception):
                # JQL search failed - return empty list (non-blocking)
                pass
            
            # No sub-tickets found or all approaches failed - return empty list (non-blocking)
            return []
        except Exception:
            # Catch-all: If any unexpected error occurs, return empty list (non-blocking)
            # This ensures sub-ticket fetch failures never block parent ticket analysis
            return []
    
    def fetch_attachment_metadata(self, ticket_id: str) -> List[Dict[str, Any]]:
        """
        Fetch attachment metadata for a ticket (no content download).
        
        Args:
            ticket_id: Jira ticket ID
            
        Returns:
            List of dictionaries containing attachment metadata:
            - filename
            - file_type
            - size
            - upload_date
        """
        try:
            issue = self._make_request(f"/rest/api/3/issue/{ticket_id}?fields=attachment")
            
            attachments = []
            for attachment in issue.get("fields", {}).get("attachment", []):
                attachments.append({
                    "filename": attachment.get("filename", ""),
                    "file_type": attachment.get("mimeType", ""),
                    "size": attachment.get("size", 0),
                    "upload_date": attachment.get("created", "")
                })
            
            return attachments
        except JiraClientError:
            raise
        except Exception as e:
            # If attachment fetch fails, return empty list (non-blocking)
            return []
    
    def _extract_description(self, description_field: Any) -> str:
        """
        Extract text from Jira description field (handles ADF format).
        
        Args:
            description_field: Description field from Jira (can be string or ADF dict)
            
        Returns:
            Plain text description
        """
        if not description_field:
            return ""
        
        if isinstance(description_field, str):
            return description_field
        
        if isinstance(description_field, dict):
            return self._extract_adf_text(description_field)
        
        return ""
    
    def _extract_adf_text(self, adf_content: Dict[str, Any]) -> str:
        """
        Extract plain text from Atlassian Document Format (ADF).
        
        Args:
            adf_content: ADF content dictionary
            
        Returns:
            Plain text representation
        """
        if not isinstance(adf_content, dict):
            return ""
        
        text_parts = []
        
        def extract_node(node: Dict[str, Any]) -> None:
            if node.get("type") == "text":
                text_parts.append(node.get("text", ""))
            elif "content" in node:
                for child in node["content"]:
                    extract_node(child)
        
        if "content" in adf_content:
            for node in adf_content["content"]:
                extract_node(node)
        
        return " ".join(text_parts)
    
    def build_jira_context(
        self,
        ticket_id: str
    ) -> Dict[str, Any]:
        """
        Build complete Jira context object for internal use.
        
        Args:
            ticket_id: Jira ticket ID to fetch
            
        Returns:
            Dictionary containing:
            - parent_ticket: Full ticket data
            - sub_tickets: List of sub-ticket metadata
            - attachments: List of attachment metadata
        """
        try:
            parent_ticket = self.fetch_ticket(ticket_id)
            sub_tickets = self.fetch_sub_tickets(ticket_id)
            attachments = self.fetch_attachment_metadata(ticket_id)
            
            return {
                "jira_context": {
                    "parent_ticket": parent_ticket,
                    "sub_tickets": sub_tickets,
                    "attachments": attachments
                }
            }
        except Exception as e:
            raise JiraClientError(f"Failed to build Jira context: {str(e)}")


def extract_ticket_id_from_text(text: str) -> Optional[str]:
    """
    Extract Jira ticket ID from input text.
    
    Looks for patterns like "ATA-36", "PROJ-123", etc.
    
    Args:
        text: Input text that may contain ticket ID
        
    Returns:
        Ticket ID if found, None otherwise
    """
    import re
    # Pattern: 2-10 uppercase letters, hyphen, 1+ digits
    pattern = r'\b([A-Z]{2,10}-\d+)\b'
    matches = re.findall(pattern, text)
    if matches:
        return matches[0]  # Return first match
    return None

