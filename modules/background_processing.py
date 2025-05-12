"""
Background processing system for long-running operations.
This module provides a job queue for asynchronous processing of tasks
without blocking the Streamlit UI.
"""
import uuid
import time
import threading
import logging
import json
from dataclasses import dataclass, field
from typing import Dict, Any, Callable, List, Optional, Union, TypeVar, Generic
logger = logging.getLogger(__name__)
T = TypeVar('T')

@dataclass
class Job:
    """Represents a background job."""
    id: str
    name: str
    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    status: str = 'pending'
    result: Any = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    progress: float = 0.0
    progress_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class BackgroundJobManager:
    """
    Job queue for background processing of long-running operations.
    """

    def __init__(self, num_workers: int=3, job_ttl: int=86400):
        """
        Initialize background job manager.
        
        Args:
            num_workers: Number of worker threads
            job_ttl: Time to live for completed jobs in seconds (default: 24 hours)
        """
        self.jobs: Dict[str, Job] = {}
        self.num_workers = num_workers
        self.job_ttl = job_ttl
        self.running = True
        self.lock = threading.RLock()
        self.workers: List[threading.Thread] = []
        for i in range(num_workers):
            worker = threading.Thread(target=self._worker_loop, name=f'JobWorker-{i}', daemon=True)
            worker.start()
            self.workers.append(worker)
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, name='JobCleanup', daemon=True)
        self.cleanup_thread.start()

    def enqueue(self, name: str, func: Callable[..., T], *args, **kwargs) -> str:
        """
        Add a job to the queue.
        
        Args:
            name: Job name for display
            func: Function to execute
            *args, **kwargs: Arguments to pass to function
            
        Returns:
            str: Job ID
        """
        job_id = str(uuid.uuid4())
        job = Job(id=job_id, name=name, func=func, args=args, kwargs=kwargs)
        with self.lock:
            self.jobs[job_id] = job
        logger.info(f'Job {job_id} ({name}) enqueued')
        return job_id

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get job status and result.
        
        Args:
            job_id: Job ID
            
        Returns:
            dict: Job information or None if not found
        """
        with self.lock:
            if job_id not in self.jobs:
                return None
            job = self.jobs[job_id]
            return {'id': job.id, 'name': job.name, 'status': job.status, 'result': job.result, 'error': job.error, 'created_at': job.created_at, 'started_at': job.started_at, 'completed_at': job.completed_at, 'progress': job.progress, 'progress_message': job.progress_message, 'metadata': job.metadata, 'runtime': (job.completed_at or time.time()) - (job.started_at or job.created_at) if job.started_at else 0}

    def get_all_jobs(self, include_completed: bool=True, limit: int=100) -> List[Dict[str, Any]]:
        """
        Get all jobs, optionally filtering out completed jobs.
        
        Args:
            include_completed: Whether to include completed jobs
            limit: Maximum number of jobs to return
            
        Returns:
            list: List of job information dictionaries
        """
        with self.lock:
            jobs_list = []
            for job_id, job in self.jobs.items():
                if not include_completed and job.status in ['completed', 'failed']:
                    continue
                job_dict = {'id': job.id, 'name': job.name, 'status': job.status, 'created_at': job.created_at, 'started_at': job.started_at, 'completed_at': job.completed_at, 'progress': job.progress, 'progress_message': job.progress_message, 'runtime': (job.completed_at or time.time()) - (job.started_at or job.created_at) if job.started_at else 0}
                if job.status in ['completed', 'failed']:
                    if job.status == 'completed':
                        job_dict['result'] = job.result
                    else:
                        job_dict['error'] = job.error
                jobs_list.append(job_dict)
            return sorted(jobs_list, key=lambda x: x['created_at'], reverse=True)[:limit]

    def update_progress(self, job_id: str, progress: float, message: Optional[str]=None) -> bool:
        """
        Update job progress.
        
        Args:
            job_id: Job ID
            progress: Progress value (0.0 to 1.0)
            message: Optional progress message
            
        Returns:
            bool: True if job was found and updated, False otherwise
        """
        with self.lock:
            if job_id not in self.jobs:
                return False
            job = self.jobs[job_id]
            if job.status != 'running':
                return False
            job.progress = max(0.0, min(1.0, progress))
            if message is not None:
                job.progress_message = message
            return True

    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a pending or running job.
        Note: This marks the job as cancelled but cannot stop an already
        executing function. The function should check for cancellation.
        
        Args:
            job_id: Job ID
            
        Returns:
            bool: True if job was found and cancelled, False otherwise
        """
        with self.lock:
            if job_id not in self.jobs:
                return False
            job = self.jobs[job_id]
            if job.status in ['completed', 'failed', 'cancelled']:
                return False
            job.status = 'cancelled'
            job.completed_at = time.time()
            return True

    def _worker_loop(self):
        """Worker thread main loop."""
        while self.running:
            job_to_process = None
            with self.lock:
                for job in self.jobs.values():
                    if job.status == 'pending':
                        job_to_process = job
                        job.status = 'running'
                        job.started_at = time.time()
                        break
            if job_to_process:
                self._process_job(job_to_process)
            else:
                time.sleep(0.1)

    def _process_job(self, job: Job):
        """
        Process a job.
        
        Args:
            job: Job to process
        """
        logger.info(f'Starting job {job.id} ({job.name})')
        try:
            result = job.func(*job.args, **job.kwargs)
            with self.lock:
                if job.id in self.jobs:
                    job = self.jobs[job.id]
                    if job.status != 'cancelled':
                        job.result = result
                        job.status = 'completed'
                        job.completed_at = time.time()
                        job.progress = 1.0
            logger.info(f'Job {job.id} ({job.name}) completed successfully')
        except Exception as e:
            logger.exception(f'Job {job.id} ({job.name}) failed: {str(e)}')
            with self.lock:
                if job.id in self.jobs:
                    job = self.jobs[job.id]
                    if job.status != 'cancelled':
                        job.error = str(e)
                        job.status = 'failed'
                        job.completed_at = time.time()

    def _cleanup_loop(self):
        """Periodically clean up old completed jobs."""
        while self.running:
            try:
                time.sleep(300)
                with self.lock:
                    current_time = time.time()
                    jobs_to_remove = []
                    for job_id, job in self.jobs.items():
                        if job.status in ['completed', 'failed', 'cancelled']:
                            if job.completed_at and current_time - job.completed_at > self.job_ttl:
                                jobs_to_remove.append(job_id)
                    for job_id in jobs_to_remove:
                        del self.jobs[job_id]
                    if jobs_to_remove:
                        logger.info(f'Cleaned up {len(jobs_to_remove)} old jobs')
            except Exception as e:
                logger.error(f'Error in job cleanup: {str(e)}')

    def shutdown(self):
        """Shutdown the job manager, stopping all threads."""
        logger.info('Shutting down background job manager')
        self.running = False
        for worker in self.workers:
            if worker.is_alive():
                worker.join(timeout=1.0)
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=1.0)
_job_manager = None

def get_job_manager() -> BackgroundJobManager:
    """
    Get the global job manager instance, creating it if necessary.
    
    Returns:
        BackgroundJobManager: Global job manager instance
    """
    global _job_manager
    if _job_manager is None:
        _job_manager = BackgroundJobManager()
    return _job_manager

def run_in_background(name: str) -> Callable:
    """
    Decorator to run a function in the background.
    
    Args:
        name: Job name for display
        
    Returns:
        Decorated function that returns a job ID
    """

    def decorator(func):

        def wrapper(*args, **kwargs):
            job_manager = get_job_manager()
            return job_manager.enqueue(name, func, *args, **kwargs)
        return wrapper
    return decorator