"""
BugFlow - Human-like behavior module
=====================================
Makes all requests look like a real browser to avoid bans.
Implements Jason Haddix's philosophy: slow, careful, methodical.
"""

import random
import time
import threading
import logging

logger = logging.getLogger("bugflow.humanize")

# Realistic desktop browser user agents
_USER_AGENTS = [
    # Chrome 120+ on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    # Mobile - iPhone
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    # Mobile - Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36",
]

# Common accept headers
_ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
]

# Common accept-language headers
_LANG_HEADERS = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en;q=0.9",
]


def get_random_headers() -> dict:
    """Return HTTP headers that look like a real browser."""
    return {
        "User-Agent": random.choice(_USER_AGENTS),
        "Accept": random.choice(_ACCEPT_HEADERS),
        "Accept-Language": random.choice(_LANG_HEADERS),
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": random.choice(["no-cache", "max-age=0"]),
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": random.choice(["none", "cross-site"]),
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "DNT": "1",
        "Connection": "keep-alive",
    }


def random_delay(min_sec: float = 2.0, max_sec: float = 8.0, jitter: float = 0.3) -> None:
    """Sleep for a random amount of time (look human).
    
    Args:
        min_sec: Minimum delay in seconds
        max_sec: Maximum delay in seconds
        jitter: Random jitter factor (0.0 - 1.0)
    """
    base = random.uniform(min_sec, max_sec)
    jitter_amount = base * random.uniform(0, jitter)
    delay = base + jitter_amount
    logger.debug(f"Human delay: {delay:.1f}s")
    time.sleep(delay)


def batch_delay(count: int, rate_limit: int = 15) -> None:
    """Delay to respect rate limits.
    
    Args:
        count: Number of requests made so far
        rate_limit: Max requests per minute
    """
    if count > 0 and count % rate_limit == 0:
        pause = random.uniform(30, 60)
        logger.info(f"Rate limit pause: {pause:.0f}s (made {count} requests)")
        time.sleep(pause)


def get_session() -> "requests.Session":
    """Get a requests Session with human-like defaults."""
    import requests
    session = requests.Session()
    session.headers.update(get_random_headers())
    # Don't follow redirects automatically (we want to see them)
    session.max_redirects = 3
    return session


class RequestTracker:
    """Track request timing to look human across a whole session.
    
    Thread-safe: uses a lock to protect shared state across sub-agents.
    """
    
    def __init__(self, min_delay: float = 2.0, max_delay: float = 8.0, 
                 rate_limit: int = 15):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.rate_limit = rate_limit
        self.request_count = 0
        self.last_request_time = 0
        self._lock = threading.Lock()
    
    def wait(self) -> None:
        """Wait appropriate time before next request. Thread-safe."""
        with self._lock:
            elapsed = time.time() - self.last_request_time
            target_delay = random.uniform(self.min_delay, self.max_delay)
            
            if elapsed < target_delay:
                sleep_for = target_delay - elapsed + random.uniform(0, 1)
            else:
                sleep_for = 0
        
        if sleep_for > 0:
            time.sleep(sleep_for)
        
        with self._lock:
            self.request_count += 1
            if self.request_count % self.rate_limit == 0:
                pause = random.uniform(25, 45)
                logger.info(f"Rate limit: pausing {pause:.0f}s after {self.request_count} requests")
            else:
                pause = 0
        
        if pause > 0:
            time.sleep(pause)
        
        with self._lock:
            self.last_request_time = time.time()
    
    def reset(self) -> None:
        """Reset the tracker (e.g., for a new target)."""
        with self._lock:
            self.request_count = 0
            self.last_request_time = 0
