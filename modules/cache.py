"""
Persistent caching system for API responses with TTL.
This module provides caching functionality to reduce redundant API calls
and improve response times.
"""
import os
import json
import time
import hashlib
import logging
import threading
from functools import wraps
from typing import Any, Dict, Optional, Callable, Union, List, Tuple
logger = logging.getLogger(__name__)

class PersistentCache:
    """
    Persistent cache for API responses with TTL and multi-level storage.
    Supports memory, file, and optional Redis caching.
    """

    def __init__(self, cache_dir: str='.cache', memory_ttl: int=300, file_ttl: int=3600, max_memory_items: int=1000, redis_client=None, redis_ttl: int=86400):
        """
        Initialize cache with configurable TTLs for different storage levels.
        
        Args:
            cache_dir: Directory to store cache files
            memory_ttl: TTL for memory cache in seconds
            file_ttl: TTL for file cache in seconds
            max_memory_items: Maximum items to store in memory
            redis_client: Optional Redis client for distributed caching
            redis_ttl: TTL for Redis cache in seconds
        """
        self.cache_dir = cache_dir
        self.memory_ttl = memory_ttl
        self.file_ttl = file_ttl
        self.redis_ttl = redis_ttl
        self.max_memory_items = max_memory_items
        self.redis_client = redis_client
        self.memory_cache = {}
        self.access_times = {}
        self.lock = threading.RLock()
        os.makedirs(cache_dir, exist_ok=True)
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()

    def _cleanup_loop(self):
        """Periodically clean up expired cache entries."""
        while self.running:
            try:
                time.sleep(60)
                self._cleanup_memory_cache()
                if random.random() < 0.1:
                    self._cleanup_file_cache()
            except Exception as e:
                logger.error(f'Error in cache cleanup: {str(e)}')

    def _cleanup_memory_cache(self):
        """Remove expired items from memory cache."""
        with self.lock:
            current_time = time.time()
            expired_keys = []
            for key, cache_data in self.memory_cache.items():
                if current_time > cache_data['expires_at']:
                    expired_keys.append(key)
            for key in expired_keys:
                del self.memory_cache[key]
                if key in self.access_times:
                    del self.access_times[key]
            if len(self.memory_cache) > self.max_memory_items:
                sorted_keys = sorted(self.access_times.items(), key=lambda x: x[1])
                to_remove = len(self.memory_cache) - self.max_memory_items
                for key, _ in sorted_keys[:to_remove]:
                    if key in self.memory_cache:
                        del self.memory_cache[key]
                    if key in self.access_times:
                        del self.access_times[key]

    def _cleanup_file_cache(self):
        """Remove expired items from file cache."""
        current_time = time.time()
        try:
            for filename in os.listdir(self.cache_dir):
                if not filename.endswith('.json'):
                    continue
                file_path = os.path.join(self.cache_dir, filename)
                try:
                    if os.path.getmtime(file_path) + self.file_ttl < current_time:
                        os.remove(file_path)
                        continue
                    with open(file_path, 'r') as f:
                        cache_data = json.load(f)
                    if 'expires_at' in cache_data and current_time > cache_data['expires_at']:
                        os.remove(file_path)
                except (json.JSONDecodeError, KeyError, OSError):
                    try:
                        os.remove(file_path)
                    except OSError:
                        pass
        except Exception as e:
            logger.error(f'Error cleaning up file cache: {str(e)}')

    def generate_key(self, prefix: str, *args, **kwargs) -> str:
        """
        Generate a cache key from arguments.
        
        Args:
            prefix: Key prefix
            *args, **kwargs: Arguments to include in key
            
        Returns:
            str: Cache key
        """
        key_data = f'{prefix}:{str(args)}:{str(sorted(kwargs.items()))}'
        return hashlib.md5(key_data.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        """
        Get a value from cache, checking memory, file, and Redis in that order.
        
        Args:
            key: Cache key
            
        Returns:
            Value or None if not found or expired
        """
        memory_result = self._get_from_memory(key)
        if memory_result is not None:
            return memory_result
        file_result = self._get_from_file(key)
        if file_result is not None:
            self._set_in_memory(key, file_result, self.memory_ttl)
            return file_result
        if self.redis_client:
            redis_result = self._get_from_redis(key)
            if redis_result is not None:
                self._set_in_memory(key, redis_result, self.memory_ttl)
                self._set_in_file(key, redis_result, self.file_ttl)
                return redis_result
        return None

    def _get_from_memory(self, key: str) -> Optional[Any]:
        """Get a value from memory cache."""
        with self.lock:
            if key in self.memory_cache:
                cache_data = self.memory_cache[key]
                if time.time() > cache_data['expires_at']:
                    del self.memory_cache[key]
                    if key in self.access_times:
                        del self.access_times[key]
                    return None
                self.access_times[key] = time.time()
                return cache_data['value']
            return None

    def _get_from_file(self, key: str) -> Optional[Any]:
        """Get a value from file cache."""
        cache_file = os.path.join(self.cache_dir, f'{key}.json')
        if not os.path.exists(cache_file):
            return None
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            if time.time() > cache_data['expires_at']:
                os.remove(cache_file)
                return None
            return cache_data['value']
        except (json.JSONDecodeError, KeyError, OSError):
            try:
                os.remove(cache_file)
            except OSError:
                pass
            return None

    def _get_from_redis(self, key: str) -> Optional[Any]:
        """Get a value from Redis cache."""
        if not self.redis_client:
            return None
        try:
            redis_data = self.redis_client.get(f'cache:{key}')
            if not redis_data:
                return None
            cache_data = json.loads(redis_data)
            if time.time() > cache_data['expires_at']:
                self.redis_client.delete(f'cache:{key}')
                return None
            return cache_data['value']
        except (json.JSONDecodeError, KeyError, Exception) as e:
            logger.error(f'Error getting from Redis: {str(e)}')
            return None

    def set(self, key: str, value: Any, memory_ttl: Optional[int]=None, file_ttl: Optional[int]=None, redis_ttl: Optional[int]=None) -> None:
        """
        Set a value in cache (memory, file, and Redis if available).
        
        Args:
            key: Cache key
            value: Value to cache
            memory_ttl: TTL for memory cache (or None for default)
            file_ttl: TTL for file cache (or None for default)
            redis_ttl: TTL for Redis cache (or None for default)
        """
        memory_ttl = memory_ttl if memory_ttl is not None else self.memory_ttl
        file_ttl = file_ttl if file_ttl is not None else self.file_ttl
        redis_ttl = redis_ttl if redis_ttl is not None else self.redis_ttl
        self._set_in_memory(key, value, memory_ttl)
        self._set_in_file(key, value, file_ttl)
        if self.redis_client:
            self._set_in_redis(key, value, redis_ttl)

    def _set_in_memory(self, key: str, value: Any, ttl: int) -> None:
        """Set a value in memory cache."""
        with self.lock:
            self.memory_cache[key] = {'value': value, 'created_at': time.time(), 'expires_at': time.time() + ttl}
            self.access_times[key] = time.time()
            if len(self.memory_cache) > self.max_memory_items:
                self._cleanup_memory_cache()

    def _set_in_file(self, key: str, value: Any, ttl: int) -> None:
        """Set a value in file cache."""
        cache_file = os.path.join(self.cache_dir, f'{key}.json')
        cache_data = {'value': value, 'created_at': time.time(), 'expires_at': time.time() + ttl}
        try:
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f)
        except OSError as e:
            logger.error(f'Error writing to cache file: {str(e)}')

    def _set_in_redis(self, key: str, value: Any, ttl: int) -> None:
        """Set a value in Redis cache."""
        if not self.redis_client:
            return
        try:
            cache_data = {'value': value, 'created_at': time.time(), 'expires_at': time.time() + ttl}
            self.redis_client.setex(f'cache:{key}', ttl, json.dumps(cache_data))
        except Exception as e:
            logger.error(f'Error setting in Redis: {str(e)}')

    def invalidate(self, key: str) -> None:
        """
        Invalidate a cache entry in all storage levels.
        
        Args:
            key: Cache key
        """
        with self.lock:
            if key in self.memory_cache:
                del self.memory_cache[key]
            if key in self.access_times:
                del self.access_times[key]
        cache_file = os.path.join(self.cache_dir, f'{key}.json')
        if os.path.exists(cache_file):
            try:
                os.remove(cache_file)
            except OSError:
                pass
        if self.redis_client:
            try:
                self.redis_client.delete(f'cache:{key}')
            except Exception:
                pass

    def clear(self) -> None:
        """Clear all cache entries in all storage levels."""
        with self.lock:
            self.memory_cache = {}
            self.access_times = {}
        try:
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('.json'):
                    os.remove(os.path.join(self.cache_dir, filename))
        except OSError:
            pass
        if self.redis_client:
            try:
                keys = self.redis_client.keys('cache:*')
                if keys:
                    self.redis_client.delete(*keys)
            except Exception:
                pass

    def shutdown(self) -> None:
        """Shutdown the cache, stopping background threads."""
        self.running = False
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=1.0)

def cache_api_call(cache: PersistentCache, prefix: str, ttl: Optional[int]=None):
    """
    Decorator to cache API calls.
    
    Args:
        cache: PersistentCache instance
        prefix: Cache key prefix
        ttl: TTL in seconds (or None for default)
    """

    def decorator(func):

        @wraps(func)
        def wrapper(*args, **kwargs):
            force_refresh = kwargs.pop('force_refresh', False)
            key = cache.generate_key(prefix, *args, **kwargs)
            if force_refresh:
                cache.invalidate(key)
            else:
                cached_value = cache.get(key)
                if cached_value is not None:
                    return cached_value
            result = func(*args, **kwargs)
            cache.set(key, result, file_ttl=ttl)
            return result
        return wrapper
    return decorator
import random