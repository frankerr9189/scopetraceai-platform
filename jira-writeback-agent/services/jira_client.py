"""
Jira client for read-only and write access to Jira issues.

This module provides safe access to Jira tickets with allow-listed write operations.
"""
from typing import Dict, Any, Optional, List
import requests
from requests.auth import HTTPBasicAuth
import json
import urllib.parse
import os


class JiraClientError(Exception):
    """Raised when Jira API calls fail."""
    pass


class JiraClient:
    """Client for fetching Jira ticket data (read-only)."""
    
    def __init__(self, base_url: str, username: str, api_token: str, timeout: Optional[int] = None):
        """
        Initialize Jira client.
        
        Args:
            base_url: Jira instance URL (e.g., "https://yourcompany.atlassian.net")
            username: Jira user email for authentication
            api_token: Jira API token for authentication
            timeout: Request timeout in seconds (default: 90, or JIRA_API_TIMEOUT env var)
        """
        self.jira_url = base_url.rstrip("/")
        self.username = username
        self.api_token = api_token
        # Default timeout: 90 seconds (Jira can be slow), configurable via env var
        self.timeout = timeout or int(os.getenv("JIRA_API_TIMEOUT", "90"))
        
        if not self.jira_url:
            raise JiraClientError("JIRA_BASE_URL cannot be empty")
        if not self.username:
            raise JiraClientError("JIRA_USERNAME cannot be empty")
        if not self.api_token:
            raise JiraClientError("JIRA_API_TOKEN cannot be empty")
    
    def _make_request(
        self, 
        endpoint: str, 
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make authenticated request to Jira API.
        
        Args:
            endpoint: API endpoint (e.g., "/rest/api/3/issue/KEY-123")
            method: HTTP method (GET, PUT, POST)
            data: Optional request body data
            
        Returns:
            JSON response from Jira API
            
        Raises:
            JiraClientError: If request fails
        """
        url = f"{self.jira_url}{endpoint}"
        auth = HTTPBasicAuth(self.username, self.api_token)
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        
        try:
            if method == "GET":
                response = requests.get(url, auth=auth, headers=headers, timeout=self.timeout)
            elif method == "PUT":
                response = requests.put(
                    url, 
                    auth=auth, 
                    headers=headers, 
                    data=json.dumps(data) if data else None,
                    timeout=self.timeout
                )
            elif method == "POST":
                response = requests.post(
                    url,
                    auth=auth,
                    headers=headers,
                    data=json.dumps(data) if data else None,
                    timeout=self.timeout
                )
            else:
                raise JiraClientError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            # Some responses may be empty (204 No Content)
            if response.content:
                return response.json()
            return {}
        except requests.exceptions.Timeout as e:
            raise JiraClientError(
                f"Jira API request timed out after {self.timeout} seconds. "
                f"This may indicate Jira is slow or experiencing issues. "
                f"Please try again or check your Jira instance status."
            )
        except requests.exceptions.RequestException as e:
            raise JiraClientError(f"Jira API request failed: {str(e)}")
    
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
    
    def get_issue(self, issue_key: str, acceptance_criteria_field_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch a Jira issue with full details (read-only).
        
        Args:
            issue_key: Jira issue key (e.g., "ABC-123")
            acceptance_criteria_field_id: Optional custom field ID for acceptance criteria
                                          (e.g., "customfield_10026")
            
        Returns:
            Dictionary containing issue data:
            - summary: Issue summary/title
            - description: Plain text description
            - acceptance_criteria: Acceptance criteria text (if present)
            - updated_at: Last update timestamp or revision marker
        """
        try:
            # Build fields query
            fields = "summary,description,status,issuetype,priority,updated"
            if acceptance_criteria_field_id:
                fields += f",{acceptance_criteria_field_id}"
            else:
                # Include all custom fields to search for acceptance criteria
                fields += ",customfield_*"
            
            # Fetch issue with fields
            issue = self._make_request(
                f"/rest/api/3/issue/{issue_key}?fields={fields}"
            )
            
            fields_data = issue.get("fields", {})
            
            # Extract description
            description = self._extract_description(fields_data.get("description"))
            
            # Extract acceptance criteria
            acceptance_criteria = None
            if acceptance_criteria_field_id:
                # Use specific field ID if provided
                field_value = fields_data.get(acceptance_criteria_field_id)
                if field_value:
                    if isinstance(field_value, str):
                        acceptance_criteria = field_value
                    elif isinstance(field_value, dict):
                        acceptance_criteria = self._extract_adf_text(field_value)
            else:
                # Search for acceptance criteria in custom fields
                for field_key, field_value in fields_data.items():
                    if "acceptance" in field_key.lower() and field_value:
                        if isinstance(field_value, str):
                            acceptance_criteria = field_value
                        elif isinstance(field_value, dict):
                            acceptance_criteria = self._extract_adf_text(field_value)
                        break
            
            # Extract updated timestamp
            updated_at = fields_data.get("updated", "")
            
            # Extract summary
            summary = fields_data.get("summary", "")
            
            return {
                "summary": summary,
                "description": description,
                "acceptance_criteria": acceptance_criteria or "",
                "updated_at": updated_at
            }
        except JiraClientError:
            raise
        except Exception as e:
            raise JiraClientError(f"Failed to fetch issue {issue_key}: {str(e)}")
    
    def update_issue_fields(
        self, 
        issue_key: str, 
        fields_dict: Dict[str, Any],
        acceptance_criteria_field_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update allow-listed fields on a Jira issue.
        
        Only allows updates to:
        - description
        - acceptance_criteria (via custom field ID)
        
        Args:
            issue_key: Jira issue key (e.g., "ABC-123")
            fields_dict: Dictionary with keys: "description", "acceptance_criteria"
            acceptance_criteria_field_id: Custom field ID for acceptance criteria
            
        Returns:
            Jira API response
            
        Raises:
            JiraClientError: If update fails or non-allow-listed field is attempted
        """
        # Allow-list: only description and acceptance_criteria
        allowed_fields = {"description", "acceptance_criteria"}
        provided_fields = set(fields_dict.keys())
        
        if not provided_fields.issubset(allowed_fields):
            invalid_fields = provided_fields - allowed_fields
            raise JiraClientError(
                f"Only allow-listed fields can be updated. Invalid fields: {invalid_fields}"
            )
        
        # Build update payload
        update_fields = {}
        
        if "description" in fields_dict:
            # Description as ADF format (required by Jira API v3)
            # Split by newlines to preserve formatting
            description_text = fields_dict["description"]
            lines = description_text.split('\n')
            content = []
            
            for line in lines:
                if line.strip():
                    content.append({
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": line
                            }
                        ]
                    })
                else:
                    # Empty line - add empty paragraph
                    content.append({
                        "type": "paragraph",
                        "content": []
                    })
            
            update_fields["description"] = {
                "type": "doc",
                "version": 1,
                "content": content
            }
        
        if "acceptance_criteria" in fields_dict:
            if not acceptance_criteria_field_id:
                raise JiraClientError(
                    "acceptance_criteria_field_id is required to update acceptance criteria"
                )
            # Acceptance criteria as plain text (Jira will handle ADF conversion if needed)
            update_fields[acceptance_criteria_field_id] = fields_dict["acceptance_criteria"]
        
        if not update_fields:
            raise JiraClientError("No valid fields to update")
        
        try:
            payload = {"fields": update_fields}
            return self._make_request(
                f"/rest/api/3/issue/{issue_key}",
                method="PUT",
                data=payload
            )
        except JiraClientError:
            raise
        except Exception as e:
            raise JiraClientError(f"Failed to update issue {issue_key}: {str(e)}")
    
    def add_comment(self, issue_key: str, comment_text: str) -> Dict[str, Any]:
        """
        Add a comment to a Jira issue.
        
        Args:
            issue_key: Jira issue key (e.g., "ABC-123")
            comment_text: Plain text comment to add (preserves newlines)
            
        Returns:
            Jira API response with comment ID
            
        Raises:
            JiraClientError: If comment addition fails
        """
        try:
            # Format comment as ADF (Atlassian Document Format)
            # Split by newlines to preserve formatting
            lines = comment_text.split('\n')
            content = []
            
            for line in lines:
                if line.strip():
                    content.append({
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": line
                            }
                        ]
                    })
                else:
                    # Empty line - add empty paragraph
                    content.append({
                        "type": "paragraph",
                        "content": []
                    })
            
            payload = {
                "body": {
                    "type": "doc",
                    "version": 1,
                    "content": content
                }
            }
            
            response = self._make_request(
                f"/rest/api/3/issue/{issue_key}/comment",
                method="POST",
                data=payload
            )
            
            return response
        except JiraClientError:
            raise
        except Exception as e:
            raise JiraClientError(f"Failed to add comment to issue {issue_key}: {str(e)}")
    
    def list_comments(self, issue_key: str) -> List[Dict[str, Any]]:
        """
        List all comments on a Jira issue.
        
        Args:
            issue_key: Jira issue key (e.g., "ABC-123")
            
        Returns:
            List of comment dictionaries with body text extracted
        """
        try:
            response = self._make_request(
                f"/rest/api/3/issue/{issue_key}/comment"
            )
            
            comments = []
            for comment in response.get("comments", []):
                # Extract text from comment body (handles ADF format)
                body = comment.get("body", {})
                body_text = self._extract_adf_text(body) if isinstance(body, dict) else str(body)
                
                comments.append({
                    "id": comment.get("id"),
                    "body": body_text,
                    "created": comment.get("created"),
                    "author": comment.get("author", {}).get("displayName", "Unknown")
                })
            
            return comments
        except JiraClientError:
            raise
        except Exception as e:
            raise JiraClientError(f"Failed to list comments for issue {issue_key}: {str(e)}")
    
    def create_issue(
        self,
        project_key: str,
        issue_type: str,
        summary: str,
        description_adf: Dict[str, Any],
        acceptance_criteria: Optional[str] = None,
        acceptance_criteria_field_id: Optional[str] = None,
        labels: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Create a new Jira issue.
        
        Args:
            project_key: Jira project key (e.g., "PROJ")
            issue_type: Issue type ID or name (e.g., "Story", "Task")
            summary: Issue summary/title
            description_adf: Description in ADF format
            acceptance_criteria: Optional acceptance criteria text
            acceptance_criteria_field_id: Optional custom field ID for acceptance criteria
            labels: Optional list of labels to apply
            
        Returns:
            Jira API response with created issue key and ID
            
        Raises:
            JiraClientError: If creation fails
        """
        try:
            # Build fields payload
            fields = {
                "project": {"key": project_key},
                "summary": summary,
                "description": description_adf,
                "issuetype": {"name": issue_type} if isinstance(issue_type, str) else {"id": issue_type}
            }
            
            # Add acceptance criteria if provided (convert to ADF format)
            if acceptance_criteria and acceptance_criteria_field_id:
                fields[acceptance_criteria_field_id] = self._build_adf_from_text(acceptance_criteria)
            
            # Add labels if provided
            if labels:
                fields["labels"] = labels
            
            payload = {"fields": fields}
            
            response = self._make_request(
                "/rest/api/3/issue",
                method="POST",
                data=payload
            )
            
            return response
        except JiraClientError:
            raise
        except Exception as e:
            raise JiraClientError(f"Failed to create issue: {str(e)}")
    
    def search_issues(self, jql: str) -> List[Dict[str, Any]]:
        """
        Search for Jira issues using JQL.
        
        Args:
            jql: JQL query string
            
        Returns:
            List of issue dictionaries with keys: issue_key, summary, etc.
        """
        try:
            # URL encode JQL query
            encoded_jql = urllib.parse.quote(jql)
            response = self._make_request(
                f"/rest/api/3/search?jql={encoded_jql}&fields=key,summary"
            )
            
            issues = []
            for issue in response.get("issues", []):
                fields = issue.get("fields", {})
                issues.append({
                    "issue_key": issue.get("key"),
                    "summary": fields.get("summary", ""),
                    "id": issue.get("id")
                })
            
            return issues
        except JiraClientError:
            raise
        except Exception as e:
            raise JiraClientError(f"Failed to search issues: {str(e)}")
    
    def get_projects(self) -> List[Dict[str, str]]:
        """
        Get list of Jira projects visible to the credentials.
        
        Returns:
            List of project dictionaries with 'key' and 'name'
        """
        try:
            response = self._make_request("/rest/api/3/project")
            
            projects = []
            for project in response:
                projects.append({
                    "key": project.get("key", ""),
                    "name": project.get("name", "")
                })
            
            return projects
        except JiraClientError:
            raise
        except Exception as e:
            raise JiraClientError(f"Failed to get projects: {str(e)}")
    
    def get_issue_types(self, project_key: str) -> List[Dict[str, Any]]:
        """
        Get issue types valid for a project.
        
        Args:
            project_key: Jira project key
            
        Returns:
            List of issue type dictionaries with 'id' and 'name'
        """
        try:
            # Get project metadata which includes issue types
            project = self._make_request(f"/rest/api/3/project/{project_key}")
            
            issue_types = []
            for issue_type in project.get("issueTypes", []):
                issue_types.append({
                    "id": issue_type.get("id", ""),
                    "name": issue_type.get("name", "")
                })
            
            return issue_types
        except JiraClientError:
            raise
        except Exception as e:
            raise JiraClientError(f"Failed to get issue types for project {project_key}: {str(e)}")

