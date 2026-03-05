"""
Test file containing various security vulnerabilities for pipeline testing.
This file is intentionally vulnerable to test the security scanning pipeline.
DO NOT USE IN PRODUCTION.
"""

import subprocess
import os
import pickle
import sys


def sql_injection_vulnerable(user_input):
    """Vulnerable SQL query construction - triggers SQL injection rule."""
    import sqlite3
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    
    # This will trigger the SQL injection rule
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    
    # Another vulnerable pattern
    query2 = "SELECT * FROM users WHERE id = " + user_input
    cursor.execute(query2)
    
    return cursor.fetchall()


def command_injection_vulnerable(user_input):
    """Vulnerable command execution - triggers command injection rule."""
    # This will trigger the command injection rule
    subprocess.run(f"ls -la {user_input}", shell=True)
    
    # Another vulnerable pattern
    subprocess.call("echo " + user_input, shell=True)
    
    # Using os.system with user input
    os.system(f"cat {user_input}")


def hardcoded_secrets():
    """Hardcoded secrets - triggers hardcoded secrets rule."""
    # These will trigger the hardcoded secrets rule
    API_KEY = "sk-1234567890abcdef"
    PASSWORD = "admin123"
    SECRET_TOKEN = "my-secret-token-here"
    CREDENTIAL = "username:password"
    
    return {
        "api_key": API_KEY,
        "password": PASSWORD,
        "token": SECRET_TOKEN
    }


def path_traversal_vulnerable(user_input):
    """Vulnerable file operations - triggers path traversal rule."""
    # This will trigger the path traversal rule
    file_path = "/data/" + user_input
    with open(file_path, 'r') as f:
        return f.read()
    
    # Another vulnerable pattern
    file_path2 = f"/tmp/{user_input}"
    with open(file_path2, 'w') as f:
        f.write("test")
    
    # Using format()
    file_path3 = "/uploads/{}".format(user_input)
    with open(file_path3, 'r') as f:
        return f.read()


def insecure_deserialization(data):
    """Insecure deserialization - triggers insecure deserialization rule."""
    # This will trigger the insecure deserialization rule
    obj = pickle.loads(data)
    return obj


def main():
    """Main function demonstrating all vulnerabilities."""
    user_input = input("Enter input: ")
    
    # Test SQL injection
    sql_injection_vulnerable(user_input)
    
    # Test command injection
    command_injection_vulnerable(user_input)
    
    # Test hardcoded secrets
    secrets = hardcoded_secrets()
    print(f"Using API key: {secrets['api_key']}")
    
    # Test path traversal
    path_traversal_vulnerable(user_input)
    
    # Test insecure deserialization
    serialized_data = pickle.dumps({"test": "data"})
    insecure_deserialization(serialized_data)


if __name__ == "__main__":
    main()
