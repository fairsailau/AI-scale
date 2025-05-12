"""
Centralized API client for Box API interactions.
This module provides a unified interface for all Box API operations,
handling authentication, request formatting, and error handling consistently.
"""
import requests
import time
import logging
import json
import threading
from typing import Dict, Any, Optional, Union, List, Tuple
logger = logging.getLogger(__name__)

class BoxAPIClient:
    """
    Centralized client for Box API interactions with consistent error handling,
    authentication management, and request formatting.
    """

    def __init__(self, client):
        """
        Initialize the API client with a Box SDK client.
        
        Args:
            client: Box SDK client instance
        """
        self.client = client
        self._access_token = None
        self._token_lock = threading.RLock()
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=100, max_retries=0)
        self.session.mount('https://', adapter)
        self.metrics = {'requests': 0, 'successes': 0, 'failures': 0, 'retries': 0, 'total_time': 0, 'endpoints': {}}
        self.metrics_lock = threading.RLock()

    def get_access_token(self) -> str:
        """
        Get the current access token, extracting it from the client if needed.
        
        Returns:
            str: Access token
        """
        with self._token_lock:
            if not self._access_token:
                if hasattr(self.client, '_oauth'):
                    self._access_token = self.client._oauth.access_token
                elif hasattr(self.client, 'auth') and hasattr(self.client.auth, 'access_token'):
                    self._access_token = self.client.auth.access_token
                else:
                    raise ValueError('Could not retrieve access token from Box client')
            return self._access_token

    def refresh_token(self) -> None:
        """
        Force a token refresh by clearing the cached token.
        The next call to get_access_token will extract a fresh token.
        """
        with self._token_lock:
            self._access_token = None

    def call_api(self, endpoint: str, method: str='GET', data: Optional[Dict[str, Any]]=None, params: Optional[Dict[str, Any]]=None, headers: Optional[Dict[str, str]]=None, files: Optional[Dict[str, Any]]=None, max_retries: int=3, retry_codes: List[int]=[429, 500, 502, 503, 504], timeout: int=60) -> Dict[str, Any]:
        """
        Make an API call to the Box API with consistent error handling and retries.
        
        Args:
            endpoint: API endpoint (without base URL)
            method: HTTP method (GET, POST, PUT, DELETE)
            data: Request body data (will be JSON-encoded)
            params: Query parameters
            headers: Additional headers
            files: Files to upload
            max_retries: Maximum number of retry attempts
            retry_codes: HTTP status codes that should trigger a retry
            timeout: Request timeout in seconds
            
        Returns:
            dict: API response data
        """
        url = f"https://api.box.com/2.0/{endpoint.lstrip('/')}"
        request_headers = {'Authorization': f'Bearer {self.get_access_token()}', 'Content-Type': 'application/json'}
        if headers:
            request_headers.update(headers)
        start_time = time.time()
        endpoint_key = endpoint.split('?')[0].split('/')[0]
        retries = 0
        try:
            while True:
                try:
                    if method.upper() in ['GET', 'DELETE']:
                        response = self.session.request(method=method, url=url, headers=request_headers, params=params, timeout=timeout)
                    else:
                        if files:
                            json_data = None
                        else:
                            json_data = data
                        response = self.session.request(method=method, url=url, headers=request_headers, params=params, json=json_data, files=files, timeout=timeout)
                    response.raise_for_status()
                    if response.content:
                        result = response.json()
                    else:
                        result = {'success': True}
                    self._update_metrics(endpoint_key, True, time.time() - start_time, retries)
                    return result
                except requests.exceptions.HTTPError as e:
                    status_code = e.response.status_code
                    if status_code in retry_codes and retries < max_retries:
                        retries += 1
                        backoff = min(2 ** retries, 60)
                        jitter = 0.1 * backoff * (2 * random.random() - 1)
                        sleep_time = backoff + jitter
                        logger.warning(f'API request failed with status {status_code}, retrying in {sleep_time:.2f}s (attempt {retries}/{max_retries})')
                        if status_code == 401:
                            logger.info('Access token may have expired, refreshing')
                            self.refresh_token()
                            request_headers['Authorization'] = f'Bearer {self.get_access_token()}'
                        time.sleep(sleep_time)
                        continue
                    logger.error(f'API request failed: {str(e)}')
                    error_data = {'error': str(e)}
                    try:
                        error_json = e.response.json()
                        if isinstance(error_json, dict):
                            error_data.update(error_json)
                    except:
                        pass
                    self._update_metrics(endpoint_key, False, time.time() - start_time, retries)
                    return error_data
                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, requests.exceptions.RequestException) as e:
                    if retries < max_retries:
                        retries += 1
                        backoff = min(2 ** retries, 60)
                        jitter = 0.1 * backoff * (2 * random.random() - 1)
                        sleep_time = backoff + jitter
                        logger.warning(f'Network error: {str(e)}, retrying in {sleep_time:.2f}s (attempt {retries}/{max_retries})')
                        time.sleep(sleep_time)
                        continue
                    logger.error(f'Network error after {max_retries} retries: {str(e)}')
                    self._update_metrics(endpoint_key, False, time.time() - start_time, retries)
                    return {'error': str(e), 'type': 'network_error'}
        except Exception as e:
            logger.exception(f'Unexpected error in API call: {str(e)}')
            self._update_metrics(endpoint_key, False, time.time() - start_time, retries)
            return {'error': str(e), 'type': 'unexpected_error'}

    def _update_metrics(self, endpoint: str, success: bool, duration: float, retries: int) -> None:
        """
        Update API metrics.
        
        Args:
            endpoint: API endpoint
            success: Whether the call was successful
            duration: Call duration in seconds
            retries: Number of retries performed
        """
        with self.metrics_lock:
            self.metrics['requests'] += 1
            self.metrics['total_time'] += duration
            if success:
                self.metrics['successes'] += 1
            else:
                self.metrics['failures'] += 1
            self.metrics['retries'] += retries
            if endpoint not in self.metrics['endpoints']:
                self.metrics['endpoints'][endpoint] = {'requests': 0, 'successes': 0, 'failures': 0, 'total_time': 0, 'min_time': float('inf'), 'max_time': 0}
            endpoint_metrics = self.metrics['endpoints'][endpoint]
            endpoint_metrics['requests'] += 1
            endpoint_metrics['total_time'] += duration
            if success:
                endpoint_metrics['successes'] += 1
            else:
                endpoint_metrics['failures'] += 1
            endpoint_metrics['min_time'] = min(endpoint_metrics['min_time'], duration)
            endpoint_metrics['max_time'] = max(endpoint_metrics['max_time'], duration)

    def get_metrics(self) -> Dict[str, Any]:
        """
        Get current API metrics.
        
        Returns:
            dict: API metrics
        """
        with self.metrics_lock:
            metrics_copy = {'requests': self.metrics['requests'], 'successes': self.metrics['successes'], 'failures': self.metrics['failures'], 'retries': self.metrics['retries'], 'total_time': self.metrics['total_time'], 'avg_time': self.metrics['total_time'] / max(1, self.metrics['requests']), 'success_rate': self.metrics['successes'] / max(1, self.metrics['requests']) * 100, 'endpoints': {}}
            for endpoint, data in self.metrics['endpoints'].items():
                metrics_copy['endpoints'][endpoint] = {'requests': data['requests'], 'successes': data['successes'], 'failures': data['failures'], 'total_time': data['total_time'], 'avg_time': data['total_time'] / max(1, data['requests']), 'min_time': data['min_time'] if data['min_time'] != float('inf') else 0, 'max_time': data['max_time'], 'success_rate': data['successes'] / max(1, data['requests']) * 100}
            return metrics_copy

    def reset_metrics(self) -> None:
        """Reset all API metrics."""
        with self.metrics_lock:
            self.metrics = {'requests': 0, 'successes': 0, 'failures': 0, 'retries': 0, 'total_time': 0, 'endpoints': {}}

    def get_file_info(self, file_id: str, fields: Optional[List[str]]=None) -> Dict[str, Any]:
        """
        Get file information.
        
        Args:
            file_id: Box file ID
            fields: Specific fields to retrieve (or None for all)
            
        Returns:
            dict: File information
        """
        params = {}
        if fields:
            params['fields'] = ','.join(fields)
        return self.call_api(f'files/{file_id}', params=params)

    def get_folder_items(self, folder_id: str, limit: int=100, offset: int=0, fields: Optional[List[str]]=None) -> Dict[str, Any]:
        """
        Get items in a folder.
        
        Args:
            folder_id: Box folder ID
            limit: Maximum number of items to return
            offset: Pagination offset
            fields: Specific fields to retrieve (or None for all)
            
        Returns:
            dict: Folder items
        """
        params = {'limit': limit, 'offset': offset}
        if fields:
            params['fields'] = ','.join(fields)
        return self.call_api(f'folders/{folder_id}/items', params=params)

    def get_metadata_templates(self, scope: str='enterprise') -> Dict[str, Any]:
        """
        Get metadata templates.
        
        Args:
            scope: Template scope (enterprise or global)
            
        Returns:
            dict: Metadata templates
        """
        return self.call_api(f'metadata_templates/{scope}')

    def get_metadata_template(self, scope: str, template: str) -> Dict[str, Any]:
        """
        Get a specific metadata template.
        
        Args:
            scope: Template scope (enterprise or global)
            template: Template key
            
        Returns:
            dict: Metadata template
        """
        return self.call_api(f'metadata_templates/{scope}/{template}/schema')

    def get_file_metadata(self, file_id: str, scope: str, template: str) -> Dict[str, Any]:
        """
        Get file metadata.
        
        Args:
            file_id: Box file ID
            scope: Metadata scope (enterprise or global)
            template: Template key
            
        Returns:
            dict: File metadata
        """
        return self.call_api(f'files/{file_id}/metadata/{scope}/{template}')

    def apply_metadata(self, file_id: str, metadata: Dict[str, Any], scope: str='enterprise', template: str='default') -> Dict[str, Any]:
        """
        Apply metadata to a file.
        
        Args:
            file_id: Box file ID
            metadata: Metadata to apply
            scope: Metadata scope (enterprise or global)
            template: Template key
            
        Returns:
            dict: Applied metadata
        """
        return self.call_api(f'files/{file_id}/metadata/{scope}/{template}', method='POST', data=metadata)

    def update_metadata(self, file_id: str, operations: List[Dict[str, Any]], scope: str='enterprise', template: str='default') -> Dict[str, Any]:
        """
        Update file metadata using operations.
        
        Args:
            file_id: Box file ID
            operations: List of operations to perform
            scope: Metadata scope (enterprise or global)
            template: Template key
            
        Returns:
            dict: Updated metadata
        """
        return self.call_api(f'files/{file_id}/metadata/{scope}/{template}', method='PUT', data=operations)

    def extract_metadata_ai(self, file_id: str, prompt: str=None, fields: List[Dict[str, Any]]=None) -> Dict[str, Any]:
        """
        Extract metadata using Box AI.
        
        Args:
            file_id: Box file ID
            prompt: Extraction prompt for freeform extraction
            fields: Field definitions for structured extraction
            
        Returns:
            dict: Extracted metadata
        """
        data = {}
        if prompt:
            data = {'mode': 'freeform', 'prompt': prompt}
        elif fields:
            data = {'mode': 'structured', 'fields': fields}
        else:
            raise ValueError('Either prompt or fields must be provided')
        return self.call_api(f'ai/extract/files/{file_id}/metadata', method='POST', data=data)

    def batch_request(self, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Make a batch request.
        
        Args:
            requests: List of request objects
            
        Returns:
            dict: Batch response
        """
        data = {'requests': requests}
        return self.call_api('batch', method='POST', data=data)
import random