"""
Jira client for creating issues from approved runs (Phase 3).
"""
from typing import Dict, Any, Optional, List
import requests
from requests.auth import HTTPBasicAuth
import json
import os


class JiraClientError(Exception):
    """Raised when Jira API calls fail."""
    pass


class JiraClient:
    """Client for creating Jira issues from approved runs."""
    
    def __init__(self, base_url: str, username: str, api_token: str):
        """
        Initialize Jira client.
        
        Args:
            base_url: Jira instance URL (e.g., "https://yourcompany.atlassian.net")
            username: Jira user email for authentication
            api_token: Jira API token for authentication
        """
        self.jira_url = base_url.rstrip("/")
        self.username = username
        self.api_token = api_token
        
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
            method: HTTP method (GET, POST)
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
                response = requests.get(url, auth=auth, headers=headers, timeout=30)
            elif method == "POST":
                response = requests.post(
                    url,
                    auth=auth,
                    headers=headers,
                    data=json.dumps(data) if data else None,
                    timeout=30
                )
            else:
                raise JiraClientError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            if response.content:
                return response.json()
            return {}
        except requests.exceptions.HTTPError as e:
            error_msg = str(e)
            try:
                error_data = response.json()
                if "errorMessages" in error_data:
                    error_msg = "; ".join(error_data["errorMessages"])
                elif "errors" in error_data:
                    error_msg = "; ".join([f"{k}: {v}" for k, v in error_data["errors"].items()])
            except:
                pass
            raise JiraClientError(f"Jira API request failed: {error_msg}")
        except requests.exceptions.RequestException as e:
            raise JiraClientError(f"Jira API request failed: {str(e)}")
    
    def _text_to_adf(self, text: str) -> Dict[str, Any]:
        """
        Convert plain text to Jira ADF (Atlassian Document Format).
        
        Args:
            text: Plain text content
            
        Returns:
            ADF document structure
        """
        if not text:
            return {
                "type": "doc",
                "version": 1,
                "content": []
            }
        
        # Split text into paragraphs
        paragraphs = text.split("\n\n")
        content = []
        
        for para in paragraphs:
            if not para.strip():
                continue
            
            # Split into lines for potential list detection
            lines = para.split("\n")
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Check if it's a list item
                if line.startswith("- ") or line.startswith("* "):
                    # Simple bullet list
                    text_content = line[2:].strip()
                    if text_content:
                        content.append({
                            "type": "listItem",
                            "content": [{
                                "type": "paragraph",
                                "content": [{
                                    "type": "text",
                                    "text": text_content
                                }]
                            }]
                        })
                else:
                    # Regular paragraph
                    content.append({
                        "type": "paragraph",
                        "content": [{
                            "type": "text",
                            "text": line
                        }]
                    })
        
        if not content:
            content.append({
                "type": "paragraph",
                "content": [{
                    "type": "text",
                    "text": text
                }]
            })
        
        return {
            "type": "doc",
            "version": 1,
            "content": content
        }
    
    def search_issues_by_label(self, label: str) -> List[Dict[str, Any]]:
        """
        Search for Jira issues by label.
        
        Args:
            label: Label to search for
            
        Returns:
            List of matching issues
        """
        try:
            import urllib.parse
            jql = f'labels = "{label}"'
            encoded_jql = urllib.parse.quote(jql)
            endpoint = f"/rest/api/3/search?jql={encoded_jql}&fields=key,summary"
            response = self._make_request(endpoint, method="GET")
            return response.get("issues", [])
        except JiraClientError:
            raise
        except Exception as e:
            raise JiraClientError(f"Failed to search issues by label: {str(e)}")
    
    def create_issue(
        self,
        project_key: str,
        issue_type: str,
        summary: str,
        description_adf: Dict[str, Any],
        labels: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Create a new Jira issue.
        
        Args:
            project_key: Jira project key (e.g., "PROJ")
            issue_type: Issue type name (e.g., "Story", "Task")
            summary: Issue summary/title
            description_adf: Description in ADF format
            labels: Optional list of labels to apply
            
        Returns:
            Jira API response with created issue key and ID
        """
        try:
            fields = {
                "project": {"key": project_key},
                "summary": summary,
                "description": description_adf,
                "issuetype": {"name": issue_type}
            }
            
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
    
    def get_issue_url(self, issue_key: str) -> str:
        """
        Get full URL for a Jira issue.
        
        Args:
            issue_key: Jira issue key (e.g., "PROJ-123")
            
        Returns:
            Full URL to the issue
        """
        return f"{self.jira_url}/browse/{issue_key}"
    
    def get_comments(self, issue_key: str) -> List[Dict[str, Any]]:
        """
        Get all comments for a Jira issue.
        
        Args:
            issue_key: Jira issue key (e.g., "PROJ-123")
            
        Returns:
            List of comment objects with body, author, created, etc.
        """
        try:
            endpoint = f"/rest/api/3/issue/{issue_key}/comment"
            response = self._make_request(endpoint, method="GET")
            return response.get("comments", [])
        except JiraClientError:
            raise
        except Exception as e:
            raise JiraClientError(f"Failed to get comments for issue {issue_key}: {str(e)}")
    
    def add_comment(self, issue_key: str, body_text: str) -> Dict[str, Any]:
        """
        Add a comment to a Jira issue.
        
        Args:
            issue_key: Jira issue key (e.g., "PROJ-123")
            body_text: Comment body text (will be converted to ADF)
            
        Returns:
            Jira API response with created comment details
        """
        try:
            # Convert text to ADF format
            body_adf = self._text_to_adf(body_text)
            
            payload = {
                "body": body_adf
            }
            
            endpoint = f"/rest/api/3/issue/{issue_key}/comment"
            response = self._make_request(endpoint, method="POST", data=payload)
            
            return response
        except JiraClientError:
            raise
        except Exception as e:
            raise JiraClientError(f"Failed to add comment to issue {issue_key}: {str(e)}")
    
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