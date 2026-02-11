import sqlite3
import os


def get_user(username: str):
    """Get user from database.
    
    VULNERABILITY 1: SQL Injection
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: String formatting in SQL queryr
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result


def backup_file(filename: str):
    """Backup a file.
    
    VULNERABILITY 2: Command Injection
    """
    # VULNERABLE: User input in shell command
    os.system(f"cp {filename} /backup/{filename}")


# VULNERABILITY 3: Hardcoded Secret
API_KEY = "sk-1234567890abcdefghijklmnop"


if __name__ == "__main__":
    user = get_user("admin")
    print(f"User: {user}")
