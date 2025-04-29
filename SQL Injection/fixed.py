import sqlite3
from hashlib import sha256
import re
import time


class SecureSQLTester:
    def __init__(self):
        self.conn = None
        self.test_results = []
        
    def init_db(self):
        """Initialize an in-memory SQLite database with test users"""
        self.conn = sqlite3.connect(':memory:')
        cursor = self.conn.cursor()
        
        # Create users table with more fields for a realistic scenario
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
        
        # Add test users with different privilege levels
        test_users = [
            ('admin', 'StrongPassword123!', 'admin@example.com', 1, '2023-01-01'),
            ('alice', 'AliceSecret456', 'alice@example.com', 0, '2023-02-15'),
            ('bob', 'BobsPassword789', 'bob@example.com', 0, '2023-03-20')
        ]
        
        for username, password, email, is_admin, created_at in test_users:
            hashed_pw = sha256(password.encode()).hexdigest()
            cursor.execute(
                'INSERT INTO users (username, password, email, is_admin, created_at) VALUES (?, ?, ?, ?, ?)',
                (username, hashed_pw, email, is_admin, created_at)
            )
            
        self.conn.commit()
        return self.conn
    
    def secure_login(self, username, password):
        """SECURE LOGIN FUNCTION - uses parameterized queries"""
        cursor = self.conn.cursor()
        # SAFE: Parameterized query
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        hashed_pw = sha256(password.encode()).hexdigest()
        
        try:
            cursor.execute(query, (username, hashed_pw))
            user = cursor.fetchone()
            return user is not None, query
        except sqlite3.Error as e:
            return False, f"ERROR: {str(e)}\nQuery: {query}"
    
    def secure_user_search(self, search_term):
        """SECURE user search function - uses parameterized queries with LIKE
        and blocks inputs with special characters"""
        cursor = self.conn.cursor()
        
        # Check for special characters
        special_chars = ['"', '`', '<', '>', '?', '/', '&', '%', '*', ' ', '=', '+']
        
        # If any special character is found, reject the search
        if any(char in search_term for char in special_chars):
            return [], "BLOCKED (( Input contains special characters ))"
        
        # SAFE: Parameterized query with LIKE operator
        query = "SELECT id, username, email FROM users WHERE username LIKE ?"
        search_pattern = f"%{search_term}%"
        
        try:
            cursor.execute(query, (search_pattern,))
            return cursor.fetchall(), query
        except sqlite3.Error as e:
            return [], f"ERROR: {str(e)}\nQuery: {query}"
    
    def secure_user_data(self, user_id):
        """SECURE user data retrieval - uses parameterized queries for numeric fields"""
        cursor = self.conn.cursor()
        # SAFE: Parameterized query for numeric field
        query = "SELECT * FROM users WHERE id = ?"
        
        try:
            cursor.execute(query, (user_id,))
            return cursor.fetchone(), query
        except sqlite3.Error as e:
            return None, f"ERROR: {str(e)}\nQuery: {query}"
    
    def attempt_boolean_blind_extraction(self, use_secure_function=True):
        """
        Demonstrate how boolean blind SQL injection is prevented in secure functions
        
        Parameters:
            use_secure_function: If True, uses the secure login function.
                               
        """
        login_func = self.secure_login
        func_type = "SECURE"
        
        print(f"\n=== BOOLEAN BLIND ATTACK DEMONSTRATION ({func_type} FUNCTION) ===")
        print(f"Target: admin user's password hash")
        print(f"Function used: {login_func.__name__}")
        
        # Get start time to measure performance
        start_time = time.time()
        
        hash_chars = "0123456789abcdef"  # SHA-256 uses hexadecimal characters
        extracted_hash = ""
        
        # Try to extract first 8 characters only (for demonstration purposes)
        # A full extraction would try all 64 characters
        for position in range(1, 9):
            hash_char_found = False
            
            for char in hash_chars:
                # Craft the boolean blind injection
                injection = f"admin' AND SUBSTR((SELECT password FROM users WHERE username='admin'),{position},1)='{char}'--"
                result, query = login_func(injection, "anyText")
                
                if result:  # If login succeeded, found the correct character
                    extracted_hash += char
                    hash_char_found = True
                    print(f"Position {position}: Found character '{char}'")
                    print(f"Hash so far: {extracted_hash}")
                    break
            
            # If no character was found for this position with any attempts
            if not hash_char_found:
                print(f"Position {position}: No character could be found")
                if use_secure_function:
                    print("ATTACK PREVENTED: Secure function blocked the injection attempt")
                else:
                    print("ERROR: Unexpected failure in extraction")
                break
        
        # Calculate time taken
        time_taken = time.time() - start_time
        print(f"Extraction attempt took {time_taken:.2f} seconds")
        
        if use_secure_function and not extracted_hash:
            print("RESULT: Secure function successfully prevented the boolean blind attack")
            return None, False
        else:
            print("No use_secure_function");
                
        return None, False
    
    def run_test(self, test_name, function, *args):
        """Run a test and record results"""
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
    
    def display_results(self):
        """Display detailed test results"""
        print("\n" + "="*80)
        print("SQL FUNCTION TEST RESULTS")
        print("="*80)
        
        for i, result in enumerate(self.test_results):
            print(f"\n--- TEST #{i+1}: {result['name']} ---")
            print(f"Function: {result['function']}")
            print(f"Input: {result['args']}")
            print(f"Query Used: {result['query']}")
            print(f"Outcome: {result['result']}")
            if "exploitable" in result:
                print(f"Exploitable: {'YES' if result['exploitable'] else 'NO'}")
            print(f"\n")
    
    def test_blind_attack_prevention(self):
        """Run tests to demonstrate how secure functions prevent blind attacks"""
        # Initialize database
        self.init_db()
        
        # Now demonstrate the same attack against the secure function
        print("\n========== SECURE FUNCTION DEMONSTRATION ==========")
        print("This will show how parameterized queries prevent boolean blind attacks")
        secure_extracted, secure_login = self.attempt_boolean_blind_extraction(use_secure_function=True)
        
        # Compare results
        print("\n========== COMPARATIVE RESULTS ==========")
        print(f"Secure function extraction: {'SUCCESSFUL' if secure_extracted else 'FAILED (ATTACK PREVENTED)'}")
        
        # Close connection
        if self.conn:
            self.conn.close()
    
    def test_secure_functions(self):
        """Run tests on secure functions against various SQL injection attempts"""
        # Initialize database
        self.init_db()
        
        # Normal login tests as baseline
        self.run_test("Normal Login (Valid)", self.secure_login, "admin", "StrongPassword123!")
        self.run_test("Normal Login (Invalid)", self.secure_login, "admin", "wrongpassword")
        
        # Test against common SQL injection patterns
        self.run_test("Comment Injection - Secure", self.secure_login, "admin'--", "anyText")
        self.run_test("OR Condition Injection - Secure", self.secure_login, "admin' OR '1'='1'--", "anyText")
        self.run_test("UNION Injection - Secure", self.secure_login, "' UNION SELECT 1,2,'3','4',5,'6'--", "anyText")
        self.run_test("Multiple Statement Injection - Secure", self.secure_login, "'; DROP TABLE users; --", "anyText")
        
        # Test boolean blind injection patterns
        self.run_test("Boolean Blind Position 1 - Secure", self.secure_login, 
                      "admin' AND SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='a'--", "anyText")
        self.run_test("Boolean Blind Position 2 - Secure", self.secure_login, 
                      "admin' AND SUBSTR((SELECT password FROM users WHERE username='admin'),2,1)='b'--", "anyText")
        
        # Test search function against injections
        self.run_test("Search LIKE Injection - Secure", self.secure_user_search, "a%' UNION SELECT 1,2,3 FROM users--")
        
        # Additional tests for special character validation
        self.run_test("Search with % character - Should Block", self.secure_user_search, "admin%")
        self.run_test("Search with < character - Should Block", self.secure_user_search, "admin<script>")
        self.run_test("Search with & character - Should Block", self.secure_user_search, "admin&user")
        self.run_test("Search without special chars - Should Pass", self.secure_user_search, "admin")
        
        # Test user data function against numeric injections
        self.run_test("Numeric Field Injection - Secure", self.secure_user_data, "1 OR 1=1")
        
        # Display results
        self.display_results()
        
        # Close connection
        if self.conn:
            self.conn.close()
    
    def run_comparative_blind_attack_test(self):
        """Run a full demonstration of boolean blind attack prevention"""
        print("""
        =============================================================
        BOOLEAN BLIND SQL INJECTION PREVENTION DEMONSTRATION
        =============================================================
        This program demonstrates how boolean blind SQL injection attacks 
        are prevented by using parameterized queries.
        
        =============================================================
        """)
        
        # Run the blind attack prevention tests
        self.test_blind_attack_prevention()


if __name__ == "__main__":
    # First run comparative tests for blind attacks specifically
    print("RUNNING BLIND INJECTION COMPARATIVE TEST...")
    tester = SecureSQLTester()
    tester.run_comparative_blind_attack_test()
    
    # Then run the full suite of security tests
    print("\n\nRUNNING FULL SECURITY TEST SUITE...")
    tester = SecureSQLTester()
    tester.test_secure_functions()