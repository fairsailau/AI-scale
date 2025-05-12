"""
Integration module for optimized components.
This module provides integration points for the optimized components
to work together while preserving existing functionality.
"""
import logging
from typing import Dict, Any, Optional, List, Callable, Union, Tuple
from modules.api_client import BoxAPIClient
from modules.cache import PersistentCache, cache_api_call
from modules.retry import CircuitBreaker, RetryManager
from modules.session_state_manager import SessionStateManager as SSM
from modules.background_processing import get_job_manager, run_in_background
from modules.batch_processing import BatchProcessor, AdaptiveBatchProcessor
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OptimizedIntegration:
    """
    Integration class for optimized components.
    Provides a unified interface for the optimized components
    while maintaining compatibility with existing code.
    """

    def __init__(self):
        """Initialize the integration components."""
        self.cache = PersistentCache(cache_dir='.cache', memory_ttl=300, file_ttl=3600, max_memory_items=1000)
        self.circuit_breakers = {'metadata': CircuitBreaker(name='metadata', failure_threshold=5, recovery_timeout=30), 'file_ops': CircuitBreaker(name='file_ops', failure_threshold=3, recovery_timeout=60), 'ai': CircuitBreaker(name='ai', failure_threshold=2, recovery_timeout=120)}
        self.retry_managers = {'metadata': RetryManager(max_retries=3, base_delay=1.0, max_delay=30.0, circuit_breaker=self.circuit_breakers['metadata']), 'file_ops': RetryManager(max_retries=3, base_delay=2.0, max_delay=60.0, circuit_breaker=self.circuit_breakers['file_ops']), 'ai': RetryManager(max_retries=2, base_delay=5.0, max_delay=120.0, circuit_breaker=self.circuit_breakers['ai'])}
        self.batch_processor = AdaptiveBatchProcessor(min_workers=2, max_workers=10, batch_size=10, throttle_rate=0.2, target_success_rate=95.0)
        self.job_manager = get_job_manager()
        self.api_client = None

    def initialize_api_client(self, client):
        """
        Initialize the API client with a Box SDK client.
        
        Args:
            client: Box SDK client instance
        """
        self.api_client = BoxAPIClient(client)

    def get_api_client(self) -> Optional[BoxAPIClient]:
        """
        Get the API client.
        
        Returns:
            BoxAPIClient: API client or None if not initialized
        """
        return self.api_client

    def ensure_api_client(self, client=None):
        """
        Ensure API client is initialized, using the provided client
        or retrieving from session state if not provided.
        
        Args:
            client: Box SDK client instance or None
            
        Returns:
            BoxAPIClient: API client
            
        Raises:
            ValueError: If client is not provided and not in session state
        """
        if self.api_client is None:
            if client is None:
                client = SSM.get('client')
                if client is None:
                    raise ValueError('Box client not initialized')
            self.initialize_api_client(client)
        return self.api_client

    @cache_api_call(cache=None, prefix='file_info')
    def get_file_info(self, file_id: str, fields: Optional[List[str]]=None) -> Dict[str, Any]:
        """
        Get file information with caching.
        
        Args:
            file_id: Box file ID
            fields: Specific fields to retrieve (or None for all)
            
        Returns:
            dict: File information
        """
        api_client = self.ensure_api_client()
        return self.retry_managers['file_ops'].execute(api_client.get_file_info, file_id, fields)

    @cache_api_call(cache=None, prefix='folder_items')
    def get_folder_items(self, folder_id: str, limit: int=100, offset: int=0, fields: Optional[List[str]]=None) -> Dict[str, Any]:
        """
        Get items in a folder with caching.
        
        Args:
            folder_id: Box folder ID
            limit: Maximum number of items to return
            offset: Pagination offset
            fields: Specific fields to retrieve (or None for all)
            
        Returns:
            dict: Folder items
        """
        api_client = self.ensure_api_client()
        return self.retry_managers['file_ops'].execute(api_client.get_folder_items, folder_id, limit, offset, fields)

    @cache_api_call(cache=None, prefix='metadata_templates')
    def get_metadata_templates(self, scope: str='enterprise') -> Dict[str, Any]:
        """
        Get metadata templates with caching.
        
        Args:
            scope: Template scope (enterprise or global)
            
        Returns:
            dict: Metadata templates
        """
        api_client = self.ensure_api_client()
        return self.retry_managers['metadata'].execute(api_client.get_metadata_templates, scope)

    @cache_api_call(cache=None, prefix='metadata_template')
    def get_metadata_template(self, scope: str, template: str) -> Dict[str, Any]:
        """
        Get a specific metadata template with caching.
        
        Args:
            scope: Template scope (enterprise or global)
            template: Template key
            
        Returns:
            dict: Metadata template
        """
        api_client = self.ensure_api_client()
        return self.retry_managers['metadata'].execute(api_client.get_metadata_template, scope, template)

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
        api_client = self.ensure_api_client()
        return self.retry_managers['ai'].execute(api_client.extract_metadata_ai, file_id, prompt, fields)

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
        api_client = self.ensure_api_client()
        return self.retry_managers['metadata'].execute(api_client.apply_metadata, file_id, metadata, scope, template)

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
        api_client = self.ensure_api_client()
        return self.retry_managers['metadata'].execute(api_client.update_metadata, file_id, operations, scope, template)

    def batch_extract_metadata(self, file_ids: List[str], prompt: str=None, fields: List[Dict[str, Any]]=None, batch_size: Optional[int]=None, max_workers: Optional[int]=None, progress_callback: Optional[Callable[[int, int, float], None]]=None) -> List[Tuple[str, Optional[Dict[str, Any]], Optional[Exception]]]:
        """
        Extract metadata for multiple files in batches.
        
        Args:
            file_ids: List of Box file IDs
            prompt: Extraction prompt for freeform extraction
            fields: Field definitions for structured extraction
            batch_size: Batch size (or None for default)
            max_workers: Maximum workers (or None for default)
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of tuples (file_id, metadata, exception) for each file
        """
        api_client = self.ensure_api_client()

        def process_file(file_id):
            return self.extract_metadata_ai(file_id, prompt, fields)
        return self.batch_processor.process_batch(file_ids, process_file, batch_size, max_workers, progress_callback=progress_callback)

    def batch_apply_metadata(self, items: List[Tuple[str, Dict[str, Any]]], scope: str='enterprise', template: str='default', batch_size: Optional[int]=None, max_workers: Optional[int]=None, progress_callback: Optional[Callable[[int, int, float], None]]=None) -> List[Tuple[Tuple[str, Dict[str, Any]], Optional[Dict[str, Any]], Optional[Exception]]]:
        """
        Apply metadata to multiple files in batches.
        
        Args:
            items: List of tuples (file_id, metadata)
            scope: Metadata scope (enterprise or global)
            template: Template key
            batch_size: Batch size (or None for default)
            max_workers: Maximum workers (or None for default)
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of tuples (item, result, exception) for each item
        """
        api_client = self.ensure_api_client()

        def process_item(item):
            file_id, metadata = item
            return self.apply_metadata(file_id, metadata, scope, template)
        return self.batch_processor.process_batch(items, process_item, batch_size, max_workers, progress_callback=progress_callback)

    @run_in_background('Extract Metadata')
    def background_batch_extract_metadata(self, file_ids: List[str], prompt: str=None, fields: List[Dict[str, Any]]=None, batch_size: Optional[int]=None, max_workers: Optional[int]=None) -> List[Tuple[str, Optional[Dict[str, Any]], Optional[Exception]]]:
        """
        Extract metadata for multiple files in batches as a background job.
        
        Args:
            file_ids: List of Box file IDs
            prompt: Extraction prompt for freeform extraction
            fields: Field definitions for structured extraction
            batch_size: Batch size (or None for default)
            max_workers: Maximum workers (or None for default)
            
        Returns:
            List of tuples (file_id, metadata, exception) for each file
        """
        job_id = SSM.get('active_job_id')

        def update_job_progress(items_processed, total_items, progress):
            if job_id:
                self.job_manager.update_progress(job_id, progress, f'Processed {items_processed}/{total_items} files')
        return self.batch_extract_metadata(file_ids, prompt, fields, batch_size, max_workers, update_job_progress)

    @run_in_background('Apply Metadata')
    def background_batch_apply_metadata(self, items: List[Tuple[str, Dict[str, Any]]], scope: str='enterprise', template: str='default', batch_size: Optional[int]=None, max_workers: Optional[int]=None) -> List[Tuple[Tuple[str, Dict[str, Any]], Optional[Dict[str, Any]], Optional[Exception]]]:
        """
        Apply metadata to multiple files in batches as a background job.
        
        Args:
            items: List of tuples (file_id, metadata)
            scope: Metadata scope (enterprise or global)
            template: Template key
            batch_size: Batch size (or None for default)
            max_workers: Maximum workers (or None for default)
            
        Returns:
            List of tuples (item, result, exception) for each item
        """
        job_id = SSM.get('active_job_id')

        def update_job_progress(items_processed, total_items, progress):
            if job_id:
                self.job_manager.update_progress(job_id, progress, f'Applied metadata to {items_processed}/{total_items} files')
        return self.batch_apply_metadata(items, scope, template, batch_size, max_workers, update_job_progress)

    def get_metrics(self) -> Dict[str, Any]:
        """
        Get metrics from all components.
        
        Returns:
            dict: Combined metrics
        """
        metrics = {'api': self.api_client.get_metrics() if self.api_client else {}, 'batch': self.batch_processor.get_metrics(), 'circuit_breakers': {name: cb.get_metrics() for name, cb in self.circuit_breakers.items()}, 'retry_managers': {name: rm.get_metrics() for name, rm in self.retry_managers.items()}}
        return metrics
_integration = None

def get_integration() -> OptimizedIntegration:
    """
    Get the global integration instance, creating it if necessary.
    
    Returns:
        OptimizedIntegration: Global integration instance
    """
    global _integration
    if _integration is None:
        _integration = OptimizedIntegration()
    return _integration