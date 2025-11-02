"""
Robust scanning utilities with error handling, retry, and resilience
"""
import asyncio
import logging
import time
from typing import Callable, Any, Optional, TypeVar, Coroutine
from functools import wraps

logger = logging.getLogger(__name__)

T = TypeVar('T')

class ScanError(Exception):
    """Base exception for scan errors"""
    pass

class NetworkError(ScanError):
    """Network-related errors"""
    pass

class TimeoutError(ScanError):
    """Timeout errors"""
    pass

class RobustScanner:
    """
    Robust scanner with retry logic, error handling, and resilience
    """

    def __init__(
        self,
        max_retries: int = 5,
        base_timeout: int = 30,
        max_timeout: int = 300,
        backoff_factor: float = 2.0
    ):
        self.max_retries = max_retries
        self.base_timeout = base_timeout
        self.max_timeout = max_timeout
        self.backoff_factor = backoff_factor

    async def execute_with_retry(
        self,
        func: Callable[..., Coroutine[Any, Any, T]],
        *args,
        **kwargs
    ) -> Optional[T]:
        """
        Execute a function with exponential backoff retry

        Args:
            func: Async function to execute
            *args, **kwargs: Arguments for the function

        Returns:
            Function result or None if all retries failed
        """
        last_exception = None
        timeout = self.base_timeout

        for attempt in range(self.max_retries):
            try:
                logger.debug(f"Attempt {attempt + 1}/{self.max_retries} for {func.__name__}")

                # Execute with timeout
                result = await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=timeout
                )

                return result

            except asyncio.TimeoutError:
                logger.warning(f"Timeout after {timeout}s on attempt {attempt + 1}/{self.max_retries}")
                last_exception = TimeoutError(f"Timeout after {timeout}s")

                # Increase timeout for next attempt
                timeout = min(timeout * self.backoff_factor, self.max_timeout)

            except (ConnectionError, OSError) as e:
                logger.warning(f"Network error on attempt {attempt + 1}/{self.max_retries}: {e}")
                last_exception = NetworkError(str(e))

                # Wait before retry with exponential backoff
                wait_time = min(2 ** attempt, 30)  # Max 30 seconds
                await asyncio.sleep(wait_time)

            except Exception as e:
                logger.error(f"Unexpected error on attempt {attempt + 1}/{self.max_retries}: {e}")
                last_exception = e

                # Wait a bit before retry
                await asyncio.sleep(2)

        # All retries failed
        logger.error(f"All {self.max_retries} attempts failed for {func.__name__}: {last_exception}")
        return None

    async def execute_safe(
        self,
        func: Callable[..., Coroutine[Any, Any, T]],
        *args,
        default_value: Optional[T] = None,
        **kwargs
    ) -> T:
        """
        Execute a function safely, returning default value on error

        Args:
            func: Async function to execute
            default_value: Value to return on error
            *args, **kwargs: Arguments for the function

        Returns:
            Function result or default_value on error
        """
        try:
            result = await func(*args, **kwargs)
            return result if result is not None else default_value
        except Exception as e:
            logger.error(f"Safe execution failed for {func.__name__}: {e}")
            return default_value

    async def execute_batch_safe(
        self,
        items: list,
        func: Callable,
        max_concurrent: int = 10,
        continue_on_error: bool = True
    ) -> list:
        """
        Execute function on batch of items with concurrency control

        Args:
            items: List of items to process
            func: Async function to apply to each item
            max_concurrent: Maximum concurrent executions
            continue_on_error: Continue processing on errors

        Returns:
            List of results (None for failed items)
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        results = []

        async def process_item(item):
            async with semaphore:
                try:
                    return await self.execute_with_retry(func, item)
                except Exception as e:
                    if not continue_on_error:
                        raise
                    logger.warning(f"Failed to process item: {e}")
                    return None

        tasks = [process_item(item) for item in items]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions if continue_on_error
        if continue_on_error:
            results = [r if not isinstance(r, Exception) else None for r in results]

        return results


class CircuitBreaker:
    """
    Circuit breaker pattern to prevent overwhelming failing services
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type = Exception
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception

        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'closed'  # closed, open, half-open

    async def call(self, func: Callable, *args, **kwargs):
        """Execute function through circuit breaker"""

        if self.state == 'open':
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self.state = 'half-open'
                logger.info(f"Circuit breaker transitioning to half-open state")
            else:
                raise ScanError("Circuit breaker is OPEN - service unavailable")

        try:
            result = await func(*args, **kwargs)

            # Success - reset if in half-open
            if self.state == 'half-open':
                self.state = 'closed'
                self.failure_count = 0
                logger.info("Circuit breaker closed - service recovered")

            return result

        except self.expected_exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.failure_count >= self.failure_threshold:
                self.state = 'open'
                logger.error(f"Circuit breaker OPENED after {self.failure_count} failures")

            raise e


def with_retry(max_retries: int = 3, backoff: float = 2.0):
    """
    Decorator for adding retry logic to async functions
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            scanner = RobustScanner(max_retries=max_retries, backoff_factor=backoff)
            return await scanner.execute_with_retry(func, *args, **kwargs)
        return wrapper
    return decorator


def safe_execution(default_value=None):
    """
    Decorator for safe execution with default value on error
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            scanner = RobustScanner()
            return await scanner.execute_safe(func, *args, default_value=default_value, **kwargs)
        return wrapper
    return decorator
