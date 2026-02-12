"""
Vulnerable code for testing CI pipeline
Contains 3 common security vulnerabilities
"""

import sqlite3
import subprocess


def search_user(username):
    """VULNERABILITY 1: SQL Injection"""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()


def ping_host(hostname):
    """VULNERABILITY 2: Command Injection"""
    result = subprocess.call("ping -c 1 " + hostname, shell=True)
    return result


# VULNERABILITY 3: Hardcoded Password
DATABASE_PASSWORD = "admin123"