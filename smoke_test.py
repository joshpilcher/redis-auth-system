"""
Comprehensive smoke test for Flask/Redis authentication system.
Tests all major functionality including registration, login, password recovery,
rate limiting, and admin features.
"""

import uuid  # Create unique test identifiers
import re  # Regular expressions used to extract/parse flash messages from HTML
import html  # HTML entity unescaping when converting flashed HTML to plain text
from contextlib import suppress  # Silently ignore expected cleanup errors

# Imports the Flask app instance, Redis client, constants, and helper functions from app.py
from app import (
    app, REDIS, USER_INDEX_SET, user_key,
    MAX_LOGIN_ATTEMPTS, seed_security_questions_if_missing,
    create_admin_account
)

# Expected message patterns (lowercase)
MESSAGES = {
    'register_ok': [b"account created successfully"],
    'duplicate': [b"already exists"],
    'welcome': [b"welcome back"],
    'password_updated': [b"password updated successfully"],
    'locked_login': [b"too many failed attempts", b"too many failed login attempts"],
    'locked_sa': [b"too many failed security answer attempts"],
}

# HTML parsing patterns
PATTERNS = {
    'alert': re.compile(r'<div[^>]*class="[^"]*alert[^"]*"[^>]*>(.*?)</div>', re.DOTALL | re.IGNORECASE),
    'tags': re.compile(r"<[^>]+>"),
}

def extract_flash_messages(response):
    """Extract flash messages from response HTML."""
    if not response or not response.data:
        return []
    
    body = response.data.decode(errors="ignore")
    alerts = PATTERNS['alert'].findall(body)
    
    messages = []
    for alert in alerts:
        # Remove HTML tags and normalize whitespace
        text = html.unescape(PATTERNS['tags'].sub("", alert))
        text = " ".join(text.split()).strip()
        if text:
            messages.append(text)
    
    return messages

def check_response(response, expected_messages):
    """Check if response contains expected messages."""
    if not response or not response.data:
        return False
    
    response_lower = response.data.lower()
    return any(msg in response_lower for msg in expected_messages)

def print_result(test_name, passed, response=None, detail=""):
    """Print test result in consistent format."""
    status = "PASS" if passed else "FAIL"
    status_code = response.status_code if response else "-"
    
    # Get flash messages if available (show only the first to avoid duplicates/noise)
    messages = extract_flash_messages(response) if response else []
    message_str = messages[0] if messages else ""
    
    output = f"[{status}] {test_name} (status={status_code})"
    if message_str:
        output += f" - {message_str}"
    elif detail:
        # Only append [detail] if we didn't already print a flash message
        output += f" [{detail}]"
    
    print(output)
    return passed

def cleanup_user(email):
    """Remove all Redis data for a test user."""
    # Remove user data
    for field in ["firstname", "password", "sq", "sa", "is_admin"]:
        REDIS.delete(user_key(email, field))
    
    # Remove from user set
    REDIS.srem(USER_INDEX_SET, email)
    
    # Clear rate limits
    REDIS.delete(f"rate_limit:{email}")
    REDIS.delete(f"rate_limit_sa:{email}")

def test_registration(client, email):
    """Test user registration and duplicate prevention."""
    # Register new account
    response = client.post("/register", data={
        "email": email,
        "first_name": "Test User",
        "password": "OldPass123!",
        "confirm_password": "OldPass123!",
        "security_question": "3",
        "security_answer": "Brisbane",
    }, follow_redirects=True)
    
    passed = REDIS.sismember(USER_INDEX_SET, email) and \
            check_response(response, MESSAGES['register_ok'])
    print_result("Register new account", passed, response)
    
    # Test duplicate prevention
    response = client.post("/register", data={
        "email": email,
        "first_name": "Duplicate",
        "password": "AnyPass123!",
        "confirm_password": "AnyPass123!",
        "security_question": "1",
        "security_answer": "test",
    }, follow_redirects=True)
    
    passed = check_response(response, MESSAGES['duplicate'])
    print_result("Duplicate registration blocked", passed, response)
    
    return "OldPass123!"  # Return password for later use

def test_password_recovery(client, email):
    """Test password recovery flow."""
    # Step 1: Enter email
    response = client.post("/forgot-password", 
                        data={"step": "1", "email": email}, 
                        follow_redirects=True)
    print_result("Password recovery: Email accepted", 
                response.status_code == 200, response)
    
    # Step 2: Answer security question (test case insensitivity)
    response = client.post("/forgot-password", 
                        data={"step": "2", "answer": "  BRISBANE  "}, 
                        follow_redirects=True)
    print_result("Password recovery: Security answer accepted", 
                response.status_code == 200, response)
    
    # Step 3: Set new password
    response = client.post("/forgot-password", data={
        "step": "3",
        "password": "NewPass123!",
        "confirm_password": "NewPass123!"
    }, follow_redirects=True)
    
    passed = check_response(response, MESSAGES['password_updated'])
    print_result("Password recovery: Password updated", passed, response)
    
    return "NewPass123!"  # Return new password

def test_rate_limiting(client, email, password):
    """Test login rate limiting."""
    # Make MAX_LOGIN_ATTEMPTS failed attempts
    for i in range(MAX_LOGIN_ATTEMPTS):
        response = client.post("/login", 
                            data={"email": email, "password": f"wrong{i}"}, 
                            follow_redirects=True)
        messages = extract_flash_messages(response)
        detail = messages[0] if messages else ""
        print_result(f"Failed login attempt {i+1}/{MAX_LOGIN_ATTEMPTS}", 
                    True, response, detail)
    
    # Verify account is locked
    attempts = REDIS.get(f"rate_limit:{email}")
    locked = attempts and int(attempts) >= MAX_LOGIN_ATTEMPTS
    print_result("Rate limit counter reached", bool(locked), 
                detail=f"attempts={attempts}")
    
    # Verify correct password is also blocked
    response = client.post("/login", 
                        data={"email": email, "password": password}, 
                        follow_redirects=True)
    passed = check_response(response, MESSAGES['locked_login'])
    print_result("Correct password blocked during lockout", passed, response)

def test_security_answer_rate_limiting(client, email):
    """Test security answer rate limiting (same format as password rate limiting)."""
    # Start reset flow for this email (sets session + question)
    client.post("/forgot-password", data={"step": "1", "email": email}, follow_redirects=True)

    # Make MAX_LOGIN_ATTEMPTS wrong answers for step=2
    for i in range(MAX_LOGIN_ATTEMPTS):
        response = client.post("/forgot-password",
                            data={"step": "2", "answer": f"wrong{i}"},
                            follow_redirects=True)
        messages = extract_flash_messages(response)
        detail = messages[0] if messages else ""
        print_result(f"Failed security answer attempt {i+1}/{MAX_LOGIN_ATTEMPTS}",
                    True, response, detail)

    # Verify SA counter reached
    sa_attempts = REDIS.get(f"rate_limit_sa:{email}")
    sa_locked = sa_attempts and int(sa_attempts) >= MAX_LOGIN_ATTEMPTS
    print_result("Security-answer rate limit counter reached", bool(sa_locked),
                detail=f"attempts={sa_attempts}")

    # Verify even correct answer is blocked during lockout
    response = client.post("/forgot-password",
                        data={"step": "2", "answer": "Brisbane"},
                        follow_redirects=True)
    passed = check_response(response, MESSAGES['locked_sa'])
    print_result("Correct security answer blocked during lockout", passed, response)

    # Cleanup for repeatability
    REDIS.delete(f"rate_limit_sa:{email}")

def test_admin_features(client):
    """Test admin login and log export (prints last 5 entries, NEWEST first)."""
    response = client.post("/login", data={
        "email": "admin@outlook.com",
        "password": "Administrator1!"
    }, follow_redirects=True)
    
    if not check_response(response, MESSAGES['welcome']):
        print_result("Admin login", False, response)
        return
    
    print_result("Admin login", True, response)
    
    # Export logs
    response = client.get("/export-logs", follow_redirects=True)
    
    is_csv = response.status_code == 200 and response.mimetype == "text/csv"
    has_header = b"timestamp,email,status" in response.data.lower() if response.data else False
    
    print_result("Admin CSV export", is_csv and has_header, response,
                detail=f"mimetype={response.mimetype}")
    
    # Print first 5 log entries 
    if is_csv and response.data:
        print("\n--- First 5 Log Entries ---")
        lines = response.data.decode('utf-8', errors='ignore').splitlines()
        if len(lines) > 1:  # Has header and data
            header = lines[0]
            data_lines = lines[1:]

            # Show the first five rows
            first_entries = data_lines[:5]

            print(header)
            for entry in first_entries:
                print(entry)
        else:
            print("No log entries found")
        print("-" * 40)


def run_smoke_tests():
    """Run all smoke tests."""
    print("="*60)
    print("AUTHENTICATION SYSTEM SMOKE TEST")
    print("="*60)
    
    app.config["TESTING"] = True
    
    # Initialize Redis and seed data
    try:
        REDIS.ping()
        seed_security_questions_if_missing()
        create_admin_account()
        print_result("Redis connection & initialization", True)
    except Exception as e:
        print_result("Redis connection & initialization", False, detail=str(e))
        return 1
    
    # Generate unique test email
    test_email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    
    # Cleanup any existing test data
    with suppress(Exception):
        cleanup_user(test_email)
    
    with app.test_client() as client:
        print("\n--- Registration Tests ---")
        password = test_registration(client, test_email)
        
        print("\n--- Login Tests ---")
        response = client.post("/login", 
                            data={"email": test_email, "password": password},
                            follow_redirects=True)
        print_result("Login with original password", 
                    check_response(response, MESSAGES['welcome']), response)
        
        print("\n--- Password Recovery Tests ---")
        new_password = test_password_recovery(client, test_email)
        
        # Verify new password works
        response = client.post("/login",
                            data={"email": test_email, "password": new_password},
                            follow_redirects=True)
        print_result("Login with new password", 
                    check_response(response, MESSAGES['welcome']), response)
        
        print("\n--- Login Rate Limiting Tests ---")
        test_rate_limiting(client, test_email, new_password)

        print("\n--- Security Answer Rate Limiting Tests ---")
        test_security_answer_rate_limiting(client, test_email)
        
        print("\n--- Admin Tests ---")
        client.post("/logout", follow_redirects=True)
        test_admin_features(client)
    
    print("\n" + "="*60)
    print("SMOKE TEST COMPLETED")
    print("="*60)
    return 0

if __name__ == "__main__":
    exit(run_smoke_tests())
