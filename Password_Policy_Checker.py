"""
Module for checking password policy compliance.

Provides functions for password strength validation, expiration checks,
and password history management.
"""

import re
from collections import deque
import time  # track timestamp of the password
import hashlib

# Constants for password expiration and password history
PASSWORD_EXPIRATION_DAYS = 90  # Example: 90 days expiration threshold
PASSWORD_HISTORY_LIMIT = 24  # Last 24 passwords should not be reused


# Hash function for password storage
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Store password data; last changed timestamp and history
user_password_data = {
    'last_password_changed': None,
    'password_history': deque(maxlen=PASSWORD_HISTORY_LIMIT)  # store the last 24 passwords
}


# Function to create a banner message
def create_banner(message):
    border = '*' * (len(message) + 4)
    print(border)
    print(f'* {message} *')
    print(border)


# Update password data when password is changed
def update_password_data(new_password):
    current_time = time.time()
    user_password_data['last_password_changed'] = current_time
    user_password_data['password_history'].append(hash_password(new_password))
    return True


# Check if password has been used before
def is_password_reused(new_password):
    hashed = hash_password(new_password)
    return hashed in user_password_data['password_history']


# Check if password is expired
def is_password_expired():
    if user_password_data['last_password_changed'] is None:
        return True  # Treat as expired if never set
    current_time = time.time()
    days_since_change = (current_time - user_password_data['last_password_changed']) / (24 * 3600)
    return days_since_change > PASSWORD_EXPIRATION_DAYS


# Check password strength
def check_password_strength(password):
    """Check the strength of 'password'
    Returns a tuple (is_strong, issues)
    is_strong: True if password meets all criteria, False otherwise
    issues: List of strings describing which criteria were not met
    """
    issues = []

    if len(password) < 14:
        issues.append("Password must be at least 14 characters long.")

    if not re.search(r'[A-Z]', password):
        issues.append("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        issues.append("Password must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        issues.append("Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        issues.append("Password must contain at least one special character.")

    is_strong = len(issues) == 0
    return is_strong, issues

if __name__ == "__main__":
    # Example usage
    test_password = "StrongPassw0rd!"
    is_strong, issues = check_password_strength(test_password)
    if is_strong:
        create_banner("Password is strong.")
    else:
        create_banner("Password is weak. Issues:")
        for issue in issues:
            print(f"- {issue}")

    if is_password_reused(test_password):
        create_banner("Password has been used before. Choose a different one.")
    else:
        update_password_data(test_password)
        create_banner("Password updated successfully.")

    if is_password_expired():
        create_banner("Password has expired. Please change your password.")
    else:
        create_banner("Password is still valid.")
