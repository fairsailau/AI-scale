"""
Smart retry logic with exponential backoff, jitter, and circuit breaking.
This module provides robust retry mechanisms for handling transient failures.
"""
import time
import random
import logging
import threading
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar, Generic, Union
logger = logging.getLogger(__name__)
T = TypeVar('T')

class CircuitBreaker:
    """
    Circuit breaker implementation to prevent cascading failures
    when external services are unavailable.
    """
    CLOSED = 'closed'
    OPEN = 'open'
    HALF_OPEN = 'half_open'

    def __init__(self, name: str='default', failure_threshold: int=5, recovery_timeout: int=30, half_open_max_calls: int=3):
        """
        Initialize circuit breaker.
        
        Args:
            name: Circuit breaker name for identification
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before trying again (half-open)
            half_open_max_calls: Maximum calls allowed in half-open state
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self.state = self.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = 0
        self.half_open_calls = 0
        self.lock = threading.RLock()
        self.total_calls = 0
        self.successful_calls = 0
        self.failed_calls = 0
        self.rejected_calls = 0
        self.state_changes = []

    def __call__(self, func):
        """Decorator to wrap a function with circuit breaker."""

        @wraps(func)
        def wrapper(*args, **kwargs):
            return self.execute(func, *args, **kwargs)
        return wrapper

    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute a function with circuit breaker protection.
        
        Args:
            func: Function to execute
            *args, **kwargs: Arguments to pass to function
            
        Returns:
            Function result
            
        Raises:
            CircuitBreakerError: If circuit is open
            Original exception: If function fails and circuit remains closed
        """
        with self.lock:
            self.total_calls += 1
            if self.state == self.OPEN:
                if time.time() - self.last_failure_time > self.recovery_timeout:
                    logger.info(f'Circuit {self.name} state: HALF_OPEN')
                    self.state = self.HALF_OPEN
                    self.half_open_calls = 0
                    self.state_changes.append((time.time(), self.HALF_OPEN))
                else:
                    self.rejected_calls += 1
                    raise CircuitBreakerError(f'Circuit {self.name} is OPEN until ' + f'{self.last_failure_time + self.recovery_timeout}')
            if self.state == self.HALF_OPEN and self.half_open_calls >= self.half_open_max_calls:
                self.rejected_calls += 1
                raise CircuitBreakerError(f'Circuit {self.name} is HALF_OPEN and at max calls limit')
            if self.state == self.HALF_OPEN:
                self.half_open_calls += 1
        try:
            result = func(*args, **kwargs)
            with self.lock:
                self.successful_calls += 1
                if self.state == self.HALF_OPEN:
                    self.success_count += 1
                    if self.success_count >= self.half_open_max_calls:
                        self.state = self.CLOSED
                        self.failure_count = 0
                        self.success_count = 0
                        logger.info(f'Circuit {self.name} state: CLOSED')
                        self.state_changes.append((time.time(), self.CLOSED))
                elif self.state == self.CLOSED:
                    self.failure_count = max(0, self.failure_count - 1)
            return result
        except Exception as e:
            with self.lock:
                self.failed_calls += 1
                self.failure_count += 1
                self.last_failure_time = time.time()
                self.success_count = 0
                if self.state == self.CLOSED and self.failure_count >= self.failure_threshold:
                    self.state = self.OPEN
                    logger.warning(f'Circuit {self.name} state: OPEN ' + f'(failures: {self.failure_count})')
                    self.state_changes.append((time.time(), self.OPEN))
                elif self.state == self.HALF_OPEN:
                    self.state = self.OPEN
                    logger.warning(f'Circuit {self.name} state: OPEN (failed in half-open)')
                    self.state_changes.append((time.time(), self.OPEN))
            raise

    def get_state(self) -> str:
        """Get current circuit state."""
        with self.lock:
            return self.state

    def get_metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics."""
        with self.lock:
            return {'name': self.name, 'state': self.state, 'failure_count': self.failure_count, 'success_count': self.success_count, 'total_calls': self.total_calls, 'successful_calls': self.successful_calls, 'failed_calls': self.failed_calls, 'rejected_calls': self.rejected_calls, 'last_failure_time': self.last_failure_time, 'state_changes': self.state_changes[-10:], 'failure_threshold': self.failure_threshold, 'recovery_timeout': self.recovery_timeout}

    def reset(self) -> None:
        """Reset the circuit breaker to closed state."""
        with self.lock:
            self.state = self.CLOSED
            self.failure_count = 0
            self.success_count = 0
            self.half_open_calls = 0
            self.state_changes.append((time.time(), self.CLOSED))
            logger.info(f'Circuit {self.name} manually reset to CLOSED')

class CircuitBreakerError(Exception):
    """Exception raised when circuit is open."""
    pass

def retry_with_backoff(max_retries: int=3, base_delay: float=1.0, max_delay: float=30.0, backoff_factor: float=2.0, jitter: float=0.1, retry_exceptions: List[type]=None):
    """
    Decorator for retrying functions with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        backoff_factor: Multiplier for exponential backoff
        jitter: Jitter factor (0-1) to randomize delay
        retry_exceptions: List of exception types to retry (or None for all)
    """

    def decorator(func):

        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if retry_exceptions and (not any((isinstance(e, ex) for ex in retry_exceptions))):
                        raise
                    retries += 1
                    if retries > max_retries:
                        logger.error(f'Max retries ({max_retries}) exceeded: {str(e)}')
                        raise
                    delay = min(base_delay * backoff_factor ** (retries - 1), max_delay)
                    jitter_amount = random.uniform(-jitter, jitter) * delay
                    delay = delay + jitter_amount
                    logger.info(f'Retry {retries}/{max_retries} after {delay:.2f}s: {str(e)}')
                    time.sleep(delay)
        return wrapper
    return decorator

class RetryManager:
    """
    Advanced retry manager with configurable strategies and circuit breaker integration.
    """

    def __init__(self, max_retries: int=3, base_delay: float=1.0, max_delay: float=30.0, backoff_factor: float=2.0, jitter: float=0.1, retry_exceptions: List[type]=None, circuit_breaker: Optional[CircuitBreaker]=None):
        """
        Initialize retry manager.
        
        Args:
            max_retries: Maximum number of retry attempts
            base_delay: Initial delay in seconds
            max_delay: Maximum delay in seconds
            backoff_factor: Multiplier for exponential backoff
            jitter: Jitter factor (0-1) to randomize delay
            retry_exceptions: List of exception types to retry (or None for all)
            circuit_breaker: Optional circuit breaker to integrate with
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.jitter = jitter
        self.retry_exceptions = retry_exceptions
        self.circuit_breaker = circuit_breaker
        self.total_calls = 0
        self.successful_calls = 0
        self.failed_calls = 0
        self.retried_calls = 0
        self.total_retries = 0
        self.lock = threading.RLock()

    def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute a function with retry and circuit breaker protection.
        
        Args:
            func: Function to execute
            *args, **kwargs: Arguments to pass to function
            
        Returns:
            Function result
            
        Raises:
            CircuitBreakerError: If circuit is open
            Original exception: If function fails after all retries
        """
        with self.lock:
            self.total_calls += 1
        if self.circuit_breaker:
            execute_func = lambda: self.circuit_breaker.execute(func, *args, **kwargs)
        else:
            execute_func = lambda: func(*args, **kwargs)
        retries = 0
        while True:
            try:
                result = execute_func()
                with self.lock:
                    self.successful_calls += 1
                    if retries > 0:
                        self.retried_calls += 1
                return result
            except CircuitBreakerError:
                with self.lock:
                    self.failed_calls += 1
                raise
            except Exception as e:
                if self.retry_exceptions and (not any((isinstance(e, ex) for ex in self.retry_exceptions))):
                    with self.lock:
                        self.failed_calls += 1
                    raise
                retries += 1
                with self.lock:
                    self.total_retries += 1
                if retries > self.max_retries:
                    with self.lock:
                        self.failed_calls += 1
                    logger.error(f'Max retries ({self.max_retries}) exceeded: {str(e)}')
                    raise
                delay = min(self.base_delay * self.backoff_factor ** (retries - 1), self.max_delay)
                jitter_amount = random.uniform(-self.jitter, self.jitter) * delay
                delay = delay + jitter_amount
                logger.info(f'Retry {retries}/{self.max_retries} after {delay:.2f}s: {str(e)}')
                time.sleep(delay)

    def __call__(self, func):
        """Decorator to wrap a function with retry and circuit breaker."""

        @wraps(func)
        def wrapper(*args, **kwargs):
            return self.execute(func, *args, **kwargs)
        return wrapper

    def get_metrics(self) -> Dict[str, Any]:
        """Get retry manager metrics."""
        with self.lock:
            metrics = {'total_calls': self.total_calls, 'successful_calls': self.successful_calls, 'failed_calls': self.failed_calls, 'retried_calls': self.retried_calls, 'total_retries': self.total_retries, 'success_rate': self.successful_calls / max(1, self.total_calls) * 100, 'retry_rate': self.retried_calls / max(1, self.total_calls) * 100, 'average_retries_per_call': self.total_retries / max(1, self.total_calls)}
            if self.circuit_breaker:
                metrics['circuit_breaker'] = self.circuit_breaker.get_metrics()
            return metrics