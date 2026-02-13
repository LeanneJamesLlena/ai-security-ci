"""
Test task with 32 common vulnerabilities
Use this to verify the Semgrep pipeline works correctly
"""

import sqlite3
import subprocess

# VULNERABILITY 1: SQL Injection
def search_user(username):
    """Search for a user in the database"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

# VULNERABILITY 2: Command Injection
def backup_database(backup_name):
    """Create a database backup"""
    subprocess.call("cp database.db backups/" + backup_name, shell=True)

# VULNERABILITY 3: Hardcoded Secret
API_KEY = "sk-1234567890abcdefghijklmnop"