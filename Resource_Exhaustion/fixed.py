import time
import random
import threading
from datetime import datetime
import logging
import os


###########################################################
#    This program contains a LOT of logging
##########################################################


# Set up logging configuration
log_directory = "logs"
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Create a formatter with timestamp and thread info
log_formatter = logging.Formatter('%(asctime)s [%(threadName)s] %(levelname)s: %(message)s')

# Create file handler for saving all output
log_filename = f"{log_directory}/ddos_simulation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
file_handler = logging.FileHandler(log_filename)
file_handler.setFormatter(log_formatter)

# Create console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

# Setup logger
logger = logging.getLogger("DDoSSimulation")
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)



# Simulate HTML responses
class SimulatedResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text
   
    def __str__(self):
        return f"Status: {self.status_code}, Response: {self.text[:50]}{'...' if len(self.text) > 50 else ''}"

def port_funct(method, path, params, headers, response_delay, error_rate, request_count_tracker):
    """
    Simulate a server response on a fake port with enhanced protections against DDoS attacks.
    
    Args:
        method (str): HTTP method ("GET" or "HEAD")
        path (str): Requested path (informational)
        params (dict): Query parameters (informational)
        headers (dict): Request headers (informational)
        response_delay (float): Maximum artificial delay
        error_rate (float): Probability of error response
        request_count_tracker (list): A one-element list used to track the number of requests
        
    Returns:
        SimulatedResponse: a simulated response object with status_code and text.
    """
    # Initialize static data structures for tracking if they don't exist
    if not hasattr(port_funct, 'data'):
        port_funct.data = {
            'ip_requests': {},           # Track IP-specific data
            'ip_blacklist': set(),       # Permanently blocked IPs
            'ip_greylist': {},           # Temporarily suspicious IPs with expiration time
            'request_timestamps': [],    # Global request timestamps
            'request_patterns': {},      # Track repeated request patterns
            'country_limits': {},        # Limit requests by country
            'ip_reputation': {},         # IP reputation scores (lower is worse)
            'burst_protection': {        # Track sudden bursts of traffic
                'last_minute': 0,
                'last_check': time.time()
            },
            'captcha_required': set(),   # IPs that need to solve a captcha
            'trusted_ips': set()         # Known good IPs
        }
    
    # Get client info from headers
    client_ip = headers.get('X-Forwarded-For', headers.get('X-Real-IP', '0.0.0.0')).split(',')[0].strip()
    user_agent = headers.get('User-Agent', '')
    referer = headers.get('Referer', '')
    country_code = headers.get('CF-IPCountry', 'XX')  # Assuming Cloudflare headers or similar
    
    # Current time for all time-based operations
    current_time = time.time()
    
    
    
    
    # Check blacklist and greylist
    if client_ip in port_funct.data['ip_blacklist']:
        return SimulatedResponse(403, "Forbidden: Your IP has been blocked due to suspicious activity")
    
    if client_ip in port_funct.data['ip_greylist']:
        # Greylisted IPs get an exponential backoff response
        return SimulatedResponse(429, "Too Many Requests: Please try again later")
    
    # Country-based rate limiting
    if country_code in port_funct.data['country_limits']:
        port_funct.data['country_limits'][country_code]['count'] += 1
        if port_funct.data['country_limits'][country_code]['count'] > port_funct.data['country_limits'][country_code]['limit']:
            # If this country is exceeding its limit, add a delay but don't block entirely
            time.sleep(random.uniform(1, 3))
    
    # check for required CAPTCHA
    if client_ip in port_funct.data['captcha_required']:
        captcha_token = params.get('captcha_token', '')
        if not captcha_token or captcha_token != f"valid_{client_ip}":  # Simplified CAPTCHA check
            return SimulatedResponse(403, "Access Denied: CAPTCHA required")
        else:
            # Successfully solved CAPTCHA, remove from required list
            port_funct.data['captcha_required'].remove(client_ip)
    
    # Initialize or update IP tracking
    if client_ip not in port_funct.data['ip_requests']:
        port_funct.data['ip_requests'][client_ip] = {
            'count': 0,
            'first_seen': current_time,
            'last_seen': current_time,
            'recent_reqs': [],
            'paths': set(),
            'user_agents': set(),
            'response_errors': 0,
            'suspicious_actions': 0,
            'request_intervals': []
        }
        # New IPs start with a neutral reputation
        port_funct.data['ip_reputation'][client_ip] = 500  # Scale 0-1000, higher is better
    
    # Update global rate limiting data
    port_funct.data['request_timestamps'].append(current_time)
    recent_requests = len(port_funct.data['request_timestamps'])
    
    # Apply global rate limiting tiers
    if recent_requests > 10000:  # Severe attack: > 166 req/sec
        if client_ip not in port_funct.data['trusted_ips']:
            return SimulatedResponse(503, "Service Unavailable: Server under high load")
    elif recent_requests > 6000:  # High load: > 100 req/sec
        # Probabilistic response based on IP reputation
        if client_ip in port_funct.data['ip_reputation']:
            reputation = port_funct.data['ip_reputation'][client_ip]
            # Lower reputation IPs are more likely to be rejected under high load
            if random.randint(0, 1000) > reputation:
                time.sleep(random.uniform(1, 2))  # Add delay for suspicious IPs
                return SimulatedResponse(429, "Too Many Requests: Server under high load")
    
    # Update IP-specific data
    ip_data = port_funct.data['ip_requests'][client_ip]
    ip_data['count'] += 1
    ip_data['last_seen'] = current_time
    ip_data['paths'].add(path)
    ip_data['user_agents'].add(user_agent)
    
    # Calculate request interval if not first request
    if ip_data['recent_reqs']:
        last_req_time = ip_data['recent_reqs'][-1]
        interval = current_time - last_req_time
        ip_data['request_intervals'].append(interval)
        # Keep only last 20 intervals
        if len(ip_data['request_intervals']) > 20:
            ip_data['request_intervals'] = ip_data['request_intervals'][-20:]
    
    # Track recent requests (last 10 seconds)
    ip_data['recent_reqs'].append(current_time)
    ip_data['recent_reqs'] = [t for t in ip_data['recent_reqs'] if t > current_time - 10]
    
    # Behavioral analysis
    # Check for consistent, robotic intervals (bot detection)
    if len(ip_data['request_intervals']) >= 5:
        intervals = ip_data['request_intervals'][-5:]
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        
        # Very low variance indicates bot-like behavior (too consistent)
        if 0 < avg_interval < 1 and variance < 0.01:
            ip_data['suspicious_actions'] += 1
            if ip_data['suspicious_actions'] > 3:
                # Require CAPTCHA after multiple suspicious actions
                port_funct.data['captcha_required'].add(client_ip)
                return SimulatedResponse(403, "Access Denied: Please complete CAPTCHA to continue")
    
    #  Advanced rate limiting
    req_per_second = len(ip_data['recent_reqs'])
    if req_per_second > 30:  # More than 30 req/sec from this IP - severe
        # Add to permanent blacklist after excessive requests
        port_funct.data['ip_blacklist'].add(client_ip)
        return SimulatedResponse(403, "Forbidden: Rate limit exceeded - IP blocked")
    elif req_per_second > 20:  # More than 20 req/sec - high
        # Add to greylist with exponentially increasing timeout
        timeout = 60 * (2 ** min(10, ip_data['suspicious_actions']))  # Max 17 hours
        port_funct.data['ip_greylist'][client_ip] = current_time + timeout
        ip_data['suspicious_actions'] += 1
        return SimulatedResponse(429, "Too Many Requests: Too many requests from your IP")
    elif req_per_second > 10:  # More than 10 req/sec - moderate
        # Decrease reputation score
        port_funct.data['ip_reputation'][client_ip] = max(0, port_funct.data['ip_reputation'][client_ip] - 50)
        if random.random() < 0.7:  # 70% chance of being limited
            time.sleep(random.uniform(0.5, 1.5))  # Add artificial delay
    
    #  User-Agent validation
    if not user_agent or 'bot' in user_agent.lower() or len(user_agent) < 10:
        if ip_data['count'] > 5:  # Allow a few requests without UA for testing
            ip_data['suspicious_actions'] += 1
            return SimulatedResponse(400, "Bad Request: Invalid User-Agent")
    
    # Check for rotating user agents (suspicious behavior)
    if len(ip_data['user_agents']) > 5 and ip_data['count'] < 20:
        # Multiple user agents in a short time period
        ip_data['suspicious_actions'] += 1
    
    #  Request pattern detection
    request_signature = f"{method}:{path}:{sorted(str(params.items()))}"
    if request_signature in port_funct.data['request_patterns']:
        pattern_data = port_funct.data['request_patterns'][request_signature]
        pattern_data['count'] += 1
        pattern_data['ips'].add(client_ip)
        
        # If same request is made too many times from few IPs
        if pattern_data['count'] > 1000 and len(pattern_data['ips']) < 10:
            # This pattern is likely part of an attack
            for attack_ip in pattern_data['ips']:
                # Decrease reputation for all IPs involved
                port_funct.data['ip_reputation'][attack_ip] = max(0, port_funct.data['ip_reputation'].get(attack_ip, 500) - 100)
            
            if pattern_data['count'] > 2000:
                return SimulatedResponse(429, "Too Many Requests: Request pattern rate limit exceeded")
    else:
        port_funct.data['request_patterns'][request_signature] = {
            'count': 1,
            'ips': {client_ip},
            'first_seen': current_time
        }
    
    # Content-based protection
    # Check for suspiciously large payloads or query params
    query_size = len(str(params))
    if query_size > 1000:
        ip_data['suspicious_actions'] += 1
        return SimulatedResponse(413, "Payload Too Large")
    
    # Dynamic reputation adjustment
    # Legitimate request behavior gradually improves reputation
    if ip_data['count'] % 10 == 0 and ip_data['suspicious_actions'] == 0:
        port_funct.data['ip_reputation'][client_ip] = min(1000, port_funct.data['ip_reputation'][client_ip] + 10)
    
    # Long-term good behavior can earn trusted status
    if ip_data['count'] > 100 and ip_data['suspicious_actions'] == 0 and port_funct.data['ip_reputation'][client_ip] > 800:
        port_funct.data['trusted_ips'].add(client_ip)
    
    # Add jitter to response time to prevent timing attacks
    jitter = random.uniform(0.05, response_delay * 1.5)
    time.sleep(jitter)
    
    #  Update request counter after all checks passed
    request_count_tracker[0] += 1 
    
    #  Apply normal error simulation if needed
    if random.random() < error_rate:
        ip_data['response_errors'] += 1
        return SimulatedResponse(500, "Simulated server error")
    else:
        if method == "HEAD":
            return SimulatedResponse(200, "")
        else:
            # Response includes security information for educational purposes
            security_level = "Low"
            if client_ip in port_funct.data['trusted_ips']:
                security_level = "Trusted"
            elif port_funct.data['ip_reputation'].get(client_ip, 0) > 800:
                security_level = "High"
            elif port_funct.data['ip_reputation'].get(client_ip, 0) > 500:
                security_level = "Medium"
            
            response = f"""
<html>
    <head><title>Protected Simulated Server</title></head>
    <body>
        <h1>Enhanced Protected Web Server</h1>
        <p>Request #{request_count_tracker[0]}</p>
        <p>Path: {path}</p>
        <p>Security Status: {security_level}</p>
        <p>DDoS Protection Active with Advanced Threat Mitigation</p>
        <p>This is a simulated response for testing purposes.</p>
    </body>
</html>
    """
            return SimulatedResponse(200, response)



# Main execution to demonstrate DDoS attack and protection
def simulate_request(ip, user_agent, path="/", method="GET", params={}, delay=0):
    """Generate a single simulated request"""
    thread_name = threading.current_thread().name
    request_id = f"{ip}_{int(time.time()*1000)}"
    
    headers = {
        "X-Forwarded-For": ip,
        "User-Agent": user_agent,
        "Referer": "https://example.com",
        "CF-IPCountry": "US"
    }
    
    if delay > 0:
        time.sleep(delay)
    
    logger.debug(f"Request {request_id} from {ip} to {path} - Thread: {thread_name}")
    
    response = port_funct(
        method=method,
        path=path,
        params=params,
        headers=headers,
        response_delay=0.1,
        error_rate=0.05,
        request_count_tracker=request_counter
    )
    
    return response, request_id

def normal_traffic_generator(duration=30):
    """Generate normal background traffic"""
    thread_name = threading.current_thread().name
    logger.info(f"Starting normal background traffic for {duration} seconds - Thread: {thread_name}")
    
    legitimate_ips = [f"192.168.1.{i}" for i in range(1, 50)]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
    ]
    
    paths = ["/", "/about", "/contact", "/products", "/services"]
    
    end_time = time.time() + duration
    while time.time() < end_time:
        ip = random.choice(legitimate_ips)
        user_agent = random.choice(user_agents)
        path = random.choice(paths)
        
        # Normal traffic has randomized intervals between requests
        response, request_id = simulate_request(ip, user_agent, path)

        logger.info(f"Normal request {request_id} from {ip} to {path}: {response}")
        
        # Realistic delay between 1-5 seconds for normal users
        time.sleep(random.uniform(1, 5))


def ddos_attack(attack_type, duration=20):
    """Simulate different types of DDoS attacks"""
    thread_name = threading.current_thread().name
    logger.warning(f"Starting {attack_type} DDoS attack for {duration} seconds - Thread: {thread_name}")
    
    attack_ips = [f"10.0.0.{i}" for i in range(1, 10)]  # Small botnet of 9 IPs
    
    if attack_type == "flood":
        # Simple request flood attack from few IPs
        end_time = time.time() + duration
        while time.time() < end_time:
            ip = random.choice(attack_ips)
            user_agent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            
            # Very rapid requests with minimal delay
            response, request_id = simulate_request(ip, user_agent)
            logger.warning(f"Flood attack {request_id} from {ip}: {response}")
            
            # Almost no delay for flood attack (0.05-0.1 seconds)
            time.sleep(random.uniform(0.05, 0.1))
            
    elif attack_type == "distributed":
        # More sophisticated attack with rotating IPs and user agents
        bot_user_agents = [
            "BadBot/1.0",
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0",
            "python-requests/2.25.1",
            ""  # Empty user agent
        ]
        
        attack_paths = ["/", "/login", "/api/data", "/search"]
        
        end_time = time.time() + duration
        while time.time() < end_time:
            # Rotate between attack IPs
            ip = f"10.0.0.{random.randint(1, 25)}"
            user_agent = random.choice(bot_user_agents)
            path = random.choice(attack_paths)
            
            # Craft random params to evade pattern detection
            params = {"q": f"query{random.randint(1, 1000)}", "id": str(random.randint(1, 100))}
            
            response, request_id = simulate_request(ip, user_agent, path, params=params)
            logger.warning(f"Distributed attack {request_id} from {ip} to {path}: {response}")
            
            # Small random delay to make detection harder
            time.sleep(random.uniform(0.1, 0.3))
    
    elif attack_type == "advanced":
        # Advanced attack with some legitimate-looking characteristics
        # but consistent timing patterns and high volume
        sophisticated_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        ]
        
        # Create threads for parallel requests
        threads = []
        end_time = time.time() + duration
        
        def make_repeated_requests(thread_id):
            ip = f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
            user_agent = random.choice(sophisticated_user_agents)
            
            thread_logger = logger.getChild(f"AdvancedAttack-{thread_id}")
            thread_logger.info(f"Advanced attack thread {thread_id} started using IP {ip}")
            
            # Each thread makes requests at consistent intervals (suspicious behavior)
            local_end_time = time.time() + duration
            while time.time() < local_end_time:
                response, request_id = simulate_request(ip, user_agent)
                if response.status_code != 200:
                    thread_logger.warning(f"Advanced attack {request_id} from {ip} BLOCKED: {response}")
                else:
                    thread_logger.warning(f"Advanced attack {request_id} from {ip}: {response}")
                
                # Suspiciously consistent timing (easily detectable as bot)
                time.sleep(0.2)
            
            thread_logger.info(f"Advanced attack thread {thread_id} finished")
        
        # Start multiple attack threads
        for i in range(5):
            t = threading.Thread(target=make_repeated_requests, args=(i,), name=f"AdvancedAttack-{i}")
            threads.append(t)
            t.start()
            
        # Wait for all threads to complete
        for t in threads:
            t.join()

def check_protection_stats():
    """Print out the current state of DDoS protection"""
    if hasattr(port_funct, 'data'):
        data = port_funct.data
        logger.info("--- DDoS Protection Statistics ---")
        logger.info(f"Total tracked IPs: {len(data['ip_requests'])}")
        logger.info(f"Blacklisted IPs: {len(data['ip_blacklist'])}")
        logger.info(f"Greylisted IPs: {len(data['ip_greylist'])}")
        logger.info(f"IPs requiring CAPTCHA: {len(data['captcha_required'])}")
        logger.info(f"Trusted IPs: {len(data['trusted_ips'])}")
        logger.info(f"Request patterns tracked: {len(data['request_patterns'])}")
        
        # Sample of blacklisted IPs
        if data['ip_blacklist']:
            logger.info("Sample of blacklisted IPs:")
            for ip in list(data['ip_blacklist'])[:5]:
                logger.info(f"- {ip}")
        
        # Sample of reputation scores
        if data['ip_reputation']:
            logger.info("Sample of IP reputation scores:")
            sample_ips = list(data['ip_reputation'].items())
            if len(sample_ips) > 5:
                sample_ips = random.sample(sample_ips, 5)
            for ip, score in sample_ips:
                logger.info(f"- {ip}: {score}/1000")
    else:
        logger.info("No protection data available yet")

if __name__ == "__main__":
    # Initialize request counter
    request_counter = [0]
    
    # Flag to track if the simulation has already been run
    simulation_run = False
    
    try:
        logger.info("=== DDoS Attack Simulation and Protection Demo ===")
        logger.info("This demo will show how the system detects and blocks DDoS attacks.")
        logger.info(f"All output/logging saved to {log_filename}")
        
        # Start with some normal background traffic
        normal_traffic_thread = threading.Thread(
            target=normal_traffic_generator, 
            args=(60,), 
            name="NormalTraffic"
        )
        normal_traffic_thread.daemon = True
        normal_traffic_thread.start()
        
        # Give some time for normal traffic to establish baseline
        logger.info("Waiting 10 seconds for normal traffic to establish baseline...")
        time.sleep(10)
        
        # Show statistics after normal traffic
        check_protection_stats()
        
        # First attack: basic flood
        flood_thread = threading.Thread(
            target=ddos_attack, 
            args=("flood",), 
            name="FloodAttack"
        )
        flood_thread.start()
        flood_thread.join()
        
        # Show statistics after first attack
        check_protection_stats()
        
        # Wait a bit between attacks
        logger.info("Waiting between attacks...")
        time.sleep(5)
        
        # Second attack: distributed
        distributed_thread = threading.Thread(
            target=ddos_attack, 
            args=("distributed",), 
            name="DistributedAttack"
        )
        distributed_thread.start()
        distributed_thread.join()
        
        # Show statistics after second attack
        check_protection_stats()
        
        # Wait a bit between attacks
        logger.info("Waiting between attacks...")
        time.sleep(5)
        
        # Third attack: advanced multi-threaded
        advanced_thread = threading.Thread(
            target=ddos_attack, 
            args=("advanced",), 
            name="AdvancedAttack"
        )
        advanced_thread.start()
        advanced_thread.join()
        
        # Final statistics
        check_protection_stats()
        
        # Let the normal traffic finish
        logger.info("Waiting for remaining normal traffic to complete...")
        normal_traffic_thread.join(timeout=10)
        
        logger.info("=== Simulation Complete ===")
        logger.info(f"Total requests processed: {request_counter[0]}")
        logger.info(f"Complete log saved to: {log_filename}")
        simulation_run = True
        
    except KeyboardInterrupt:
        logger.warning("Simulation interrupted by user.")
    except Exception as e:
        logger.error(f"Error during simulation: {e}", exc_info=True)
    finally:
        if not simulation_run:
            logger.error("The program exited early - this indicates a problem in the setup.")
            logger.error("Please check the imports, class definitions, and ensure the main execution block is being run.")
            
            
           