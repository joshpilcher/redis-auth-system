"""
Redis-based Authentication System with Flask Web Interface

This module implements a secure user authentication and management system using Redis 
as the backend database and Flask for the web interface. It provides user registration,
login, password recovery, and administrative features including login auditing.

Features:
    - User registration with email validation and security questions
    - Secure password storage using salted bcrypt hashing
    - Password recovery via security questions
    - Rate limiting to prevent brute force attacks
    - Admin functionality for exporting login logs
    - CSV import for test data
    - Session management with Flask

Default Admin Account (for demonstration only, seeded at startup)
Email: admin@outlook.com
Password: Administrator1!

Author: Joshua Pilcher
Version: 3.4

"""

# =========================
# Imports
# =========================
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file  # Flask framework and utilities for web application
import bcrypt  # For secure password hashing
import redis  # Redis database client
import csv  # CSV file processing for bulk imports
import re  # Regular expressions for validation
import io  # In-memory file operations for CSV export
import secrets  # Cryptographically secure random generation
from datetime import datetime  # Timestamp generation
from functools import wraps  # Decorator utilities
from dotenv import load_dotenv
import os

load_dotenv()

# =========================
# Application Configuration
# =========================

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Flask app initialization with secure session key

# Redis connection configuration
REDIS = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    username=os.getenv("REDIS_USER", "default"),
    password=os.getenv("REDIS_PASSWORD", ""),
    decode_responses=True
)

# =========================
# Constants
# =========================

# Redis keys
LOG_LIST_KEY = "logs:login"            # Redis list for login attempts
SQ_HASH_KEY = "sq:text"                # Redis hash for security questions
USER_INDEX_SET = "user:emails"         # Redis set for all user emails

# System limits
MAX_LOG_ENTRIES = 100_000              # Maximum login log entries
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")  # Email validation pattern

# Rate limiting
MAX_LOGIN_ATTEMPTS = 5                 # Failed attempts before lockout
LOCKOUT_DURATION = 900                 # Lockout duration (15 minutes)


# =========================
# Utility Functions
# =========================
def now_str():
    """Generate current timestamp string for logging."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_login(login):
    """Normalize email address for consistent storage."""
    return login.strip().lower()


def validate_email(email):
    """Check if email format is valid."""
    return bool(EMAIL_RE.match(email))


def user_key(email, field):
    """Generate Redis key for user data fields."""
    return f"user:{email}:{field}"


def hash_secret(secret):
    """Hash a secret using bcrypt with automatic salting."""
    return bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt()).decode()


def check_secret(plain, hashed):
    """Verify a plain text secret against its bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def norm_answer(s):
    """Normalize security answer for case-insensitive comparison."""
    return " ".join(s.strip().casefold().split())


# =========================
# Validation Functions
# =========================

def password_ok(pw):
    """Validate password meets security requirements."""
    if len(pw) < 8:
        return False, "Password must be at least 8 characters long"
    if len(pw) > 16:
        return False, "Password cannot be longer than 16 characters"
    if re.search(r"\s", pw):
        return False, "Password cannot contain spaces"
    
    # Require at least one number or special character
    has_number = bool(re.search(r"\d", pw))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", pw))
    
    if not (has_number or has_special):
        return False, "Password must contain at least one number or special character"
    
    return True, ""


def validate_email_full(email):
    """Validate email format and length requirements."""
    if not validate_email(email):
        return False, "Invalid email format"
    if len(email) < 5 or len(email) > 320:
        return False, "Email must be between 5 and 320 characters"
    return True, ""


def validate_password_pair(password, confirm_password):
    """Validate password meets requirements and matches confirmation."""
    ok, reason = password_ok(password)
    if not ok:
        return False, reason
    if password != confirm_password:
        return False, "Passwords do not match"
    return True, ""


def validate_name(name, field_name="Name"):
    """Validate name field meets length requirements."""
    if not name:
        return False, f"{field_name} cannot be empty"
    if len(name) < 2 or len(name) > 25:
        return False, f"{field_name} must be between 2 and 25 characters"
    return True, ""


def validate_security_answer(answer):
    """Validate security answer meets length requirements."""
    if not answer:
        return False, "Security answer cannot be empty"
    if len(answer) < 2 or len(answer) > 50:
        return False, "Security answer must be between 2 and 50 characters"
    return True, ""


def validate_user_exists(email):
    """Check if user exists in Redis database."""
    return REDIS.sismember(USER_INDEX_SET, email)


# =========================
# Rate Limiting
# =========================

def check_limit(key_prefix, email, attempt_type="login"):
    """Check if user is rate limited for a given type."""
    key = f"{key_prefix}:{email}"
    attempts = REDIS.get(key)
    if attempts and int(attempts) >= MAX_LOGIN_ATTEMPTS:
        ttl = REDIS.ttl(key)  # how long until the key expires
        if ttl > 0:
            minutes = ttl // 60
            return False, f"Too many failed {attempt_type} attempts. Try again in {minutes} minutes."
    return True, ""


def increment_attempts(key_prefix, email):
    """Increment failed attempts counter for given type."""
    key = f"{key_prefix}:{email}"
    pipe = REDIS.pipeline()
    pipe.incr(key)  # Key is created on first failure, incremented each time after
    pipe.expire(key, LOCKOUT_DURATION)  # TTL set/reset to 15 minutes → counter auto-clears if no failures in that window
    result = pipe.execute()
    current_attempts = int(result[0])  # Once counter hits 5, user can no longer attempt until TTL expires
    return current_attempts


def clear_attempts(key_prefix, email):
    """Clear failed attempts on success."""
    REDIS.delete(f"{key_prefix}:{email}")


# =========================
# Logging Functions
# =========================
    
def log_login_attempt(email, success):
    """Record login attempt to Redis log list."""
    if not REDIS.sismember(USER_INDEX_SET, email):
        return
    
    status = "SUCCESS" if success else "FAILED"
    entry = f"{now_str()},{email},{status}"
    
    pipe = REDIS.pipeline()
    pipe.lpush(LOG_LIST_KEY, entry)  # Push entry to log list
    pipe.ltrim(LOG_LIST_KEY, 0, MAX_LOG_ENTRIES - 1)  # Limit max entries
    pipe.execute()


def _csv_safe(cell):
    """Prevent CSV injection by escaping formula characters."""
    if cell and cell[0] in ("=", "+", "-", "@"):
        return "'" + cell
    return cell


def get_logs_csv(max_rows=10000):
    """Generate CSV file content from login logs."""
    rows = REDIS.lrange(LOG_LIST_KEY, 0, max_rows - 1)
    if not rows:
        return None

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Email", "Status"])

    # Keep Redis order
    for row in rows:
        ts, email, status = row.split(",", 2)
        writer.writerow([_csv_safe(ts), _csv_safe(email), _csv_safe(status)])

    output.seek(0)
    return output.getvalue()


# =========================
# Security Questions Management
# =========================

def seed_security_questions_if_missing():
    """Seed default security questions if they don't exist in Redis."""
    if not REDIS.exists(SQ_HASH_KEY):
        # Create hash key for security questions (ID → text mapping)
        REDIS.hset(
            SQ_HASH_KEY,
            mapping={
                "1": "What is your first pet's name?",
                "2": "What was the name of your primary school?",
                "3": "In what city were you born?",
                "4": "What is your mother's maiden name?",
                "5": "What is your favourite teacher's surname?",
            },
        )
        return True
    return False


def fetch_security_questions():
    """Retrieve all security questions from Redis sorted by ID."""
    data = REDIS.hgetall(SQ_HASH_KEY)
    if not data:
        return []
    
    try:
        return sorted(data.items(), key=lambda kv: int(kv[0]))
    except ValueError:
        return sorted(data.items(), key=lambda kv: kv[0])


# =========================
# Admin Account Management
# =========================
    
def create_admin_account():
    """Create default admin account if it doesn't exist."""
    admin_email = "admin@outlook.com"
    
    if not REDIS.sismember(USER_INDEX_SET, admin_email):
        pipe = REDIS.pipeline()
        # Create string keys for admin account and add to pipeline
        pipe.set(user_key(admin_email, "firstname"), "Admin")
        pipe.set(user_key(admin_email, "password"), hash_secret("Administrator1!"))
        pipe.set(user_key(admin_email, "sq"), "5")
        pipe.set(user_key(admin_email, "sa"), hash_secret(norm_answer("Admin")))
        pipe.set(user_key(admin_email, "is_admin"), "1")
        pipe.sadd(USER_INDEX_SET, admin_email)
        pipe.execute()
        
        print("✅ Admin account created: admin@outlook.com / Administrator1!")
        return True
    return False


# =========================
# CSV Import Function
# =========================

def import_from_csv(csv_path, batch_size=50):
    """Import users from CSV file with batch processing."""
    def clean(s):
        """Safely strip whitespace from strings."""
        return s.strip() if isinstance(s, str) else ""

    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            # Clean headers (remove BOM and spaces)
            reader.fieldnames = [clean(h).lstrip("\ufeff") for h in reader.fieldnames]

            pipe = REDIS.pipeline()
            batch = imported = skipped = errors = 0

            for row in reader:
                # Extract and clean fields
                email = normalize_login(clean(row.get("email")))
                first_name = clean(row.get("first_name"))
                password = clean(row.get("password"))
                sq_id = clean(row.get("security_question_id"))
                answer_raw = clean(row.get("security_answer"))
                answer_norm = norm_answer(answer_raw)

                # Validate required fields
                if not (email and first_name and password and sq_id and answer_norm):
                    errors += 1
                    continue

                # Skip existing users
                if REDIS.sismember(USER_INDEX_SET, email):
                    skipped += 1
                    continue

                # Create user keys (strings for fields, add email to set)
                pipe.set(user_key(email, "firstname"), first_name)
                pipe.set(user_key(email, "password"), hash_secret(password))
                pipe.set(user_key(email, "sq"), sq_id)
                pipe.set(user_key(email, "sa"), hash_secret(answer_norm))
                pipe.set(user_key(email, "is_admin"), "0", nx=True)
                pipe.sadd(USER_INDEX_SET, email)

                batch += 1
                imported += 1
                
                # Execute batch when size reached
                if batch >= batch_size:
                    pipe.execute()
                    batch = 0

            # Execute remaining operations
            if batch:
                pipe.execute()

            print(f"✅ Imported {imported} new, skipped {skipped}, errors {errors}")
            
    except FileNotFoundError:
        print(f"⚠️ CSV not found: {csv_path} (skipping)")

    except Exception as e:
        print(f"❌ CSV import failed: {e}")


# =========================
# Decorators
# =========================
        
def login_required(f):
    """Decorator to require user authentication for protected routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "email" not in session:
            flash("Please login first", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to require admin privileges for administrative routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "email" not in session or not session.get("is_admin"):
            flash("Admin access required", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# =========================
# Initialization
# =========================

@app.before_request
def initialize():
    """Run before each request to ensure Redis connection and seed data."""
    try:
        REDIS.ping()
        seed_security_questions_if_missing()
    except Exception as e:
        print(f"❌ Could not connect to Redis: {e}")


# =========================
# Routes
# =========================
        
@app.route("/")
def index():
    """Display homepage."""
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Handle user registration."""
    if request.method == "POST":
        # Extract form data
        email = normalize_login(request.form.get("email", ""))
        first_name = request.form.get("first_name", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        sq_id = request.form.get("security_question", "")
        sec_answer = request.form.get("security_answer", "").strip()

        # Validate email
        valid, msg = validate_email_full(email)
        if not valid:
            flash(msg, "danger")
            return redirect(url_for("register"))

        # Check if account exists
        if REDIS.exists(user_key(email, "password")):
            flash(f"An account already exists for {email}. Please login.", "warning")
            return redirect(url_for("login"))

        # Validate first name
        valid, msg = validate_name(first_name, "First name")
        if not valid:
            flash(msg, "danger")
            return redirect(url_for("register"))

        # Validate password
        valid, msg = validate_password_pair(password, confirm_password)
        if not valid:
            flash(msg, "danger")
            return redirect(url_for("register"))

        # Validate security question
        if not sq_id or not REDIS.hget(SQ_HASH_KEY, sq_id):
            flash("Please select a valid security question", "danger")
            return redirect(url_for("register"))

        # Validate security answer
        valid, msg = validate_security_answer(sec_answer)
        if not valid:
            flash(msg, "danger")
            return redirect(url_for("register"))

        # Create account
        try:
            pipe = REDIS.pipeline()
            # Create user keys (strings for fields, add email to set)
            pipe.set(user_key(email, "firstname"), first_name)
            pipe.set(user_key(email, "password"), hash_secret(password))
            pipe.set(user_key(email, "sq"), sq_id)
            pipe.set(user_key(email, "sa"), hash_secret(norm_answer(sec_answer)))
            pipe.set(user_key(email, "is_admin"), "0")
            pipe.sadd(USER_INDEX_SET, email)
            pipe.execute()

            flash(f"Account created successfully for {email}!", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"Database error: {e}", "danger")
            return redirect(url_for("register"))

    # GET request - display form
    questions = fetch_security_questions()
    return render_template("register.html", questions=questions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Handle user authentication with rate limiting."""
    if request.method == "POST":
        email = normalize_login(request.form.get("email", ""))
        password = request.form.get("password", "")

        # Validate email
        valid, msg = validate_email_full(email)
        if not valid:
            flash("Invalid email or password", "danger")
            return redirect(url_for("login"))

        # Check rate limiting (login attempts)
        allowed, msg = check_limit("rate_limit", email, "login")
        if not allowed:
            flash(msg, "danger")
            return redirect(url_for("login"))

        # Check if user exists
        if not validate_user_exists(email):
            log_login_attempt(email, False)
            current = increment_attempts("rate_limit", email)
            if current >= MAX_LOGIN_ATTEMPTS:
                flash(f"Too many failed attempts. Account locked for {LOCKOUT_DURATION // 60} minutes.", "danger")
            else:
                remaining = MAX_LOGIN_ATTEMPTS - current
                flash(f"Invalid email or password. {remaining} attempts remaining.", "danger")
            return redirect(url_for("login"))

        # Verify password
        stored_hash = REDIS.get(user_key(email, "password"))
        if not stored_hash:
            log_login_attempt(email, False)
            current = increment_attempts("rate_limit", email)
            if current >= MAX_LOGIN_ATTEMPTS:
                flash(f"Too many failed attempts. Account locked for {LOCKOUT_DURATION // 60} minutes.", "danger")
            else:
                remaining = MAX_LOGIN_ATTEMPTS - current
                # Keep message generic to avoid leaking account state, but include remaining attempts
                flash(f"Invalid email or password. {remaining} attempts remaining.", "danger")
            return redirect(url_for("login"))

        if check_secret(password, stored_hash):
            # Successful login
            clear_attempts("rate_limit", email)
            log_login_attempt(email, True)
            first_name = REDIS.get(user_key(email, "firstname")) or "User"
            
            # Create session
            session["email"] = email
            session["first_name"] = first_name
            session["is_admin"] = REDIS.get(user_key(email, "is_admin")) == "1"
            
            flash(f"Welcome back, {first_name}!", "success")
            return redirect(url_for("dashboard"))
        else:
            # Failed login
            log_login_attempt(email, False)
            current = increment_attempts("rate_limit", email)
            if current >= MAX_LOGIN_ATTEMPTS:
                flash(f"Too many failed attempts. Account locked for {LOCKOUT_DURATION // 60} minutes.", "danger")
            else:
                remaining = MAX_LOGIN_ATTEMPTS - current
                flash(f"Invalid email or password. {remaining} attempts remaining.", "danger")
            return redirect(url_for("login"))

    # GET request - display form
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    """Display user dashboard."""
    return render_template("dashboard.html", first_name=session.get("first_name"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Handle password reset via security questions."""
    if request.method == "POST":
        step = request.form.get("step", "1")

        if step == "1":
            # Step 1: Verify email
            email = normalize_login(request.form.get("email", ""))

            valid, msg = validate_email_full(email)
            if not valid or not validate_user_exists(email):
                flash("No account found with this email", "danger")
                return redirect(url_for("forgot_password"))

            # Retrieve security question
            sq_id = REDIS.get(user_key(email, "sq"))
            q_text = REDIS.hget(SQ_HASH_KEY, sq_id)
            if not q_text:
                flash("Security question not found for this account", "danger")
                return redirect(url_for("forgot_password"))

            session["reset_email"] = email
            session["reset_question"] = q_text
            return render_template("forgot_password.html", step=2, question=q_text)

        elif step == "2":
            # Step 2: Verify security answer
            if "reset_email" not in session:
                return redirect(url_for("forgot_password"))

            email = session["reset_email"]

            # Check rate limiting (security answers)
            allowed, msg = check_limit("rate_limit_sa", email, "security answer")
            if not allowed:
                flash(msg, "danger")
                return render_template(
                    "forgot_password.html", step=2, question=session.get("reset_question")
                )

            answer = request.form.get("answer", "").strip()
            stored_hash = REDIS.get(user_key(email, "sa"))

            if not stored_hash or not check_secret(norm_answer(answer), stored_hash):
                current = increment_attempts("rate_limit_sa", email)

                if current >= MAX_LOGIN_ATTEMPTS:
                    ttl = REDIS.ttl(f"rate_limit_sa:{email}")
                    minutes = ttl // 60 if ttl > 0 else LOCKOUT_DURATION // 60
                    flash(f"Too many failed security answer attempts. Try again in {minutes} minutes.", "danger")
                else:
                    remaining = MAX_LOGIN_ATTEMPTS - current
                    flash(f"Incorrect security answer. {remaining} attempts remaining.", "danger")

                return render_template(
                    "forgot_password.html", step=2, question=session.get("reset_question")
                )

            # Success → clear attempts
            clear_attempts("rate_limit_sa", email)

            session["reset_verified"] = True
            return render_template("forgot_password.html", step=3)

        elif step == "3":
            # Step 3: Set new password
            if "reset_email" not in session or not session.get("reset_verified"):
                return redirect(url_for("forgot_password"))

            email = session["reset_email"]
            new_password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            valid, msg = validate_password_pair(new_password, confirm_password)
            if not valid:
                flash(msg, "danger")
                return render_template("forgot_password.html", step=3)

            # Update password
            REDIS.set(user_key(email, "password"), hash_secret(new_password))

            # Clear session
            session.pop("reset_email", None)
            session.pop("reset_question", None)
            session.pop("reset_verified", None)

            flash("Password updated successfully! Please login with your new password.", "success")
            return redirect(url_for("login"))

    # GET request - display form
    return render_template("forgot_password.html", step=1)


@app.route("/logout")
def logout():
    """Clear user session and logout."""
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for("index"))


@app.route("/export-logs")
@admin_required
def export_logs():
    """Export login history as CSV (admin only)."""
    csv_data = get_logs_csv()
    if not csv_data:
        flash("No logs to export", "warning")
        return redirect(url_for("dashboard"))

    # Create in-memory file
    output = io.BytesIO()
    output.write(csv_data.encode("utf-8"))
    output.seek(0)

    # Send file download
    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"login_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
    )


# =========================
# Main Application Entry Point
# =========================

if __name__ == "__main__":
    print("🔄 Initialising application...")
    
    # Seed security questions
    if seed_security_questions_if_missing():
        print("✅ Security questions seeded")
    else:
        try:
            existing = REDIS.hlen(SQ_HASH_KEY)
            print(f"ℹ️ Security questions already exist (count: {existing})")
        except Exception:
            print("ℹ️ Security questions already exist")
    
    # Create admin account
    if create_admin_account():
        print("ℹ️ Admin account created for testing")
    
    # Import initial data
    import_from_csv("sample_data.csv")
    
    # Start application
    app.run(port=5000)
