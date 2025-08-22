# 1. Import necessary libraries

# Standard library imports
import os
from functools import wraps
from datetime import datetime
import re

# Third-party library imports
from flask import Flask, render_template, request, redirect, session, url_for, g, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras  # Needed to access columns by name
from dotenv import load_dotenv
import pytz
import requests
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# Added imports for admin functionality
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# It's good practice to ensure the key was actually loaded
if not app.secret_key:
    raise ValueError("No SECRET_KEY set for Flask application. Did you create a .env file?")

# 2. Get the database connection URL from environment variables
# DATABASE_URL = os.environ.get('DATABASE_URL')
DATABASE_URL = os.getenv('DATABASE_URL')

if not DATABASE_URL:
    raise ValueError("No DATABASE_URL set for Flask application")


# ---------- Database Setup for Neon (PostgreSQL) ----------

def get_db():
    """
    Opens a new database connection if there is none yet for the
    current application context.
    """
    if 'db' not in g:
        g.db = psycopg2.connect(DATABASE_URL)
        g.cursor = g.db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    return g.cursor


@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
    db = g.pop('db', None)
    cursor = g.pop('cursor', None)
    if cursor is not None:
        cursor.close()
    if db is not None:
        db.close()


def init_db():
    """
    Initializes the database and creates the 'users' and 'purchases' tables.
    """
    with app.app_context():
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()

        # Create users table
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        fullname TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                    )''')

        # 3. Create a new 'purchases' table to track courses
        # It links a user_id to a purchased course_name.
        cur.execute('''CREATE TABLE IF NOT EXISTS purchases (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        course_name TEXT NOT NULL,
                        purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id),
                        UNIQUE (user_id, course_name)
                    )''')

        conn.commit()
        cur.close()
        conn.close()
        print("Database initialized with users and purchases tables.")


# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
# Use environment variables for sensitive data in production
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER') # Your email address
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS') # Your App Password
# ADD THIS LINE for the admin's email
app.config['ADMIN_EMAIL'] = os.environ.get('ADMIN_EMAIL')
app.config['SUPERVISOR_EMAIL'] = os.environ.get('SUPERVISOR_EMAIL')
# --- Add your Google Client ID to the app's config ---
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID') # Get client ID from .env file

# Initialize the Mail instance
mail = Mail(app)

# --- NEW: Custom Jinja filter to format UTC datetime to IST ---
def format_to_ist(utc_dt):
    """Takes a naive UTC datetime and converts it to a formatted IST string."""
    if not utc_dt:
        return "" # Return empty string if datetime is None
    
    utc_tz = pytz.timezone('UTC')
    ist_tz = pytz.timezone('Asia/Kolkata')
    
    # Make the naive datetime object from the database timezone-aware (as UTC)
    aware_utc_dt = utc_tz.localize(utc_dt)
    
    # Convert it to the IST timezone
    ist_dt = aware_utc_dt.astimezone(ist_tz)
    
    # Return the formatted string
    return ist_dt.strftime('%d %b %Y, %I:%M %p')

# Register the custom filter with the Jinja environment
app.jinja_env.filters['format_ist'] = format_to_ist

# ---------- Decorators ----------
def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to be logged in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """
    CORRECTED: Decorator to require 'admin' role for actions like editing or deleting.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # This check is the crucial part. It must be exactly 'admin'.
        if session.get('role') != 'admin':
            flash("You do not have permission to perform this action.", "error")
            # Redirect to the dashboard, as you might be a supervisor.
            return redirect(url_for('admin_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# --- NEW DECORATOR: To grant dashboard access to both Admin and Supervisor ---
def dashboard_access_required(f):
    """Decorator to grant dashboard access to both 'admin' and 'supervisor' roles."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') not in ['admin', 'supervisor']:
            flash("You do not have permission to view this page.", "error")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function


# ---------- Routes ----------

@app.route('/')
def home():
    """
    Displays the home page.
    Fetches purchased courses ONLY if the user is logged in.
    """
    purchased_courses = [] # Default to an empty list for guests
    
    # Check if a user is logged in
    if 'user_id' in session:
        cur = get_db()
        # Fetch the list of courses the user has purchased
        cur.execute("SELECT course_name FROM purchases WHERE user_id = %s", (session['user_id'],))
        purchased_courses_rows = cur.fetchall()
        # Convert list of row objects to a simple list of strings
        purchased_courses = [row['course_name'] for row in purchased_courses_rows]

    # Pass the list (either empty or populated) to the template
    return render_template('index.html', purchased_courses=purchased_courses)


def is_strong_password(password):
    """
    Checks if a password meets the strength requirements.
    Returns None if the password is strong, otherwise an error message string.
    """
    # Minimum 8 characters
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    # Must contain at least one lowercase letter
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    # Must contain at least one uppercase letter
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    # Must contain at least one number
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."
    # Must contain at least one special character
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character (e.g., !@#$%)."
    
    # If all checks pass
    return None


# --- Signup Logic ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        # --- START: Password Validation Logic ---
        
        # 1. Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('signup'))
            
        # 2. Check for password strength
        strength_error = is_strong_password(password)
        if strength_error:
            flash(strength_error, "error") # Flash the specific reason
            return redirect(url_for('signup'))
            
        # --- END: Password Validation Logic ---

        hashed_password = generate_password_hash(password)

        try:
            cur = get_db()
            cur.execute("INSERT INTO users (fullname, email, password) VALUES (%s, %s, %s)",
                        (fullname, email, hashed_password))
            cur.connection.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('login'))
        except psycopg2.errors.UniqueViolation:
            flash("An account with this email already exists.", "error")
            get_db().connection.rollback()
            return redirect(url_for('signup'))

    return render_template('signup.html', google_client_id=app.config['GOOGLE_CLIENT_ID'])


# --- ADD THIS NEW ROUTE FOR GOOGLE LOGIN ---

@app.route('/google-login', methods=['POST'])
def google_login():
    try:
        # Retrieve the Google credential token sent from frontend
        token = request.form.get('credential')
        
        # Verify the token with Google, ensuring authenticity
        idinfo = id_token.verify_oauth2_token(
            token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID']
        )
        
        # Extract user information from validated token
        user_email = idinfo['email']
        user_fullname = idinfo['name']
        
        cur = get_db()
        # Check if user already exists in database
        cur.execute("SELECT * FROM users WHERE email = %s", (user_email,))
        user = cur.fetchone()
        if user:
            # User exists: log them in by setting session variables
            session['user_id'] = user['id']
            session['user_name'] = user['fullname']
        else:
            # User does not exist: create new user with placeholder password for SSO
            cur.execute(
                "INSERT INTO users (fullname, email, password) VALUES (%s, %s, %s) RETURNING id",
                (user_fullname, user_email, 'GOOGLE_SSO')
            )
            new_user_id = cur.fetchone()['id']
            cur.connection.commit()
            
            # Log the new user in by setting session variables
            session['user_id'] = new_user_id
            session['user_name'] = user_fullname
        
        flash("Successfully logged in with Google!", "success")
        return redirect(url_for('home'))
    except ValueError:
        # Token was invalid or verification failed
        flash("There was an error logging in with Google.", "error")
        return redirect(url_for('login'))
    except Exception as e:
        # Catch-all for unexpected errors, rollback if needed
        flash(f"An unexpected error occurred: {e}", "error")
        get_db().connection.rollback()
        return redirect(url_for('login'))

# --- MODIFY YOUR EXISTING /login ROUTE ---

# --- 4. MODIFY THE LOGIN ROUTE FOR GOOGLE USERS ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        cur = get_db()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        # CORRECTED LOGIC FLOW STARTS HERE
        if user:
            # First, check if the user signed up with Google.
            if user['password'] == 'GOOGLE_SSO':
                flash("This account was created with Google. Please use the 'Sign in with Google' button.", "warning")
                return redirect(url_for('login'))
            
            # If not a Google user, then check the password.
            if check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['user_name'] = user['fullname']
                
                # --- ROLE ASSIGNMENT LOGIC ---

                # --- MODIFICATION: Make email check case-insensitive ---
                admin_email = app.config.get('ADMIN_EMAIL', '').lower()
                supervisor_email = app.config.get('SUPERVISOR_EMAIL', '').lower()
                
                if email.lower() == admin_email:
                    session['role'] = 'admin'
                    flash("Admin login successful!", "success")
                    return redirect(url_for('admin_dashboard'))
                elif email.lower() == supervisor_email:
                    session['role'] = 'supervisor'
                    flash("Supervisor login successful!", "success")
                    return redirect(url_for('admin_dashboard'))
                else:
                    session['role'] = 'user'
                    flash("Login successful!", "success")
                    return redirect(url_for('home'))

        # This message now correctly shows if the user doesn't exist OR the password is wrong.
        flash("Invalid email or password.", "error")
        return redirect(url_for('login'))
    
    return render_template('login.html', google_client_id=app.config['GOOGLE_CLIENT_ID'])

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    # Redirect to the public home page instead of the login page
    return redirect(url_for('home')) 


# --- 5. ADD THE NEW GOOGLE AUTH CALLBACK ROUTE ---
@app.route('/auth/google', methods=['POST'])
def auth_google():
    try:
        # Get the ID token sent by the client
        token = request.json.get('token')
        if not token:
            return {"success": False, "message": "No token provided."}, 400

        # Verify the token against Google's public keys
        id_info = id_token.verify_oauth2_token(
            token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID']
        )

        # Extract user information
        user_email = id_info['email']
        user_name = id_info.get('name', 'N/A')
        
        cur = get_db()
        
        # Check if user already exists
        cur.execute("SELECT * FROM users WHERE email = %s", (user_email,))
        user = cur.fetchone()

        if user:
            # User exists, log them in
            session['user_id'] = user['id']
            session['user_name'] = user['fullname']
        else:
            # User is new, create an account
            # We insert 'GOOGLE_SSO' to satisfy the 'NOT NULL' constraint on the password column.
            cur.execute(
                "INSERT INTO users (fullname, email, password) VALUES (%s, %s, %s) RETURNING id",
                (user_name, user_email, 'GOOGLE_SSO')
            )
            new_user_id = cur.fetchone()['id']
            cur.connection.commit()
            
            # Log the new user in
            session['user_id'] = new_user_id
            session['user_name'] = user_name

        flash("Successfully logged in with Google!", "success")
        return {"success": True}

    except ValueError:
        # This error is raised by verify_oauth2_token if the token is invalid
        return {"success": False, "message": "Invalid Google token."}, 401
    except Exception as e:
        # Log the error for debugging
        app.logger.error(f"Error during Google authentication: {e}")
        return {"success": False, "message": "An internal error occurred."}, 500

# 5. New route to handle course purchases


@app.route('/purchase/<string:course_name>', methods=['POST'])
@login_required
def purchase(course_name):
    """
    Handles the logic for purchasing a course and sends confirmation emails
    to both the user and the admin.
    """
    try:
        cur = get_db()
        cur.execute("INSERT INTO purchases (user_id, course_name) VALUES (%s, %s)",
                    (session['user_id'], course_name))
        cur.connection.commit()
        flash(f"Successfully purchased the '{course_name}' course!", "success")

        # --- Email Sending Logic ---
        try:
            cur.execute("SELECT fullname, email FROM users WHERE id = %s", (session['user_id'],))
            user = cur.fetchone()

            if user:
                # --- Part A: Send Confirmation Email to the USER ---
                user_subject = f"Purchase Confirmation: {course_name}"
                msg_user = Message(user_subject, sender=app.config['MAIL_USERNAME'], recipients=[user['email']])
                msg_user.html = f"""
                <html>
                    <body>
                        <h2>Thank You for Your Purchase!</h2>
                        <p>Hi {user['fullname']},</p>
                        <p>You have successfully purchased the <strong>{course_name}</strong> course. You can now access all course materials from your dashboard.</p>
                        <p>Happy learning!</p>
                        <p><em>The Trade with Plan Team</em></p>
                    </body>
                </html>
                """
                mail.send(msg_user)

                # --- Part B: Send Notification Email to the ADMIN/MENTOR ---
                admin_subject = f"New Course Sale: '{course_name}' by {user['fullname']}"

                # --- CORRECTED TIMEZONE LOGIC ---
                # 1. Get the standard UTC time
                utc_now = datetime.utcnow().replace(tzinfo=pytz.utc)
                # 2. Define the IST timezone
                ist_tz = pytz.timezone('Asia/Kolkata')
                # 3. Convert UTC time to IST
                ist_now = utc_now.astimezone(ist_tz)
                # 4. Format the IST time string (using %Z to get the timezone name automatically)
                purchase_time = ist_now.strftime('%d %b %Y, %I:%M %p %Z')
                
                msg_admin = Message(admin_subject, sender=app.config['MAIL_USERNAME'], recipients=[app.config['ADMIN_EMAIL']])
                msg_admin.html = f"""
                <html>
                    <body>
                        <h2>New Course Purchase Alert!</h2>
                        <p>A course was just purchased on Trade with Plan. Here are the details:</p>
                        <ul>
                            <li><strong>User Name:</strong> {user['fullname']}</li>
                            <li><strong>User Email:</strong> {user['email']}</li>
                            <li><strong>Course Purchased:</strong> {course_name}</li>
                            <li><strong>Time of Purchase:</strong> {purchase_time}</li>
                            <li><strong>User ID:</strong> {session['user_id']}</li>
                        </ul>
                    </body>
                </html>
                """
                mail.send(msg_admin)

        except Exception as e:
            app.logger.error(f"Email sending failed for user {session['user_id']}: {e}")
            flash("Purchase successful, but we failed to send confirmation emails. Please contact support.", "warning")
            
    except psycopg2.errors.UniqueViolation:
        get_db().connection.rollback()
        flash("You have already purchased this course.", "info")
        
    except Exception as e:
        get_db().connection.rollback()
        flash(f"An error occurred during purchase: {e}", "error")

    return redirect(url_for('home'))


def user_has_purchased_course(course_name):
    """
    Returns True if the currently logged-in user has purchased the given course.
    """
    if 'user_id' not in session:
        return False

    cur = get_db()
    cur.execute(
        "SELECT 1 FROM purchases WHERE user_id = %s AND course_name = %s",
        (session['user_id'], course_name)
    )
    return cur.fetchone() is not None


from flask import abort

def login_and_purchase_required(course_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("You need to be logged in to access this course.", "warning")
                return redirect(url_for('login'))
            if not user_has_purchased_course(course_name):
                flash(f"You need to purchase the '{course_name}' course to access this page.", "warning")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# 1. Add this import at the top of your app.py file
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

# ... (rest of your app setup)

# 2. Add these helper functions and new routes anywhere in app.py, 
#     for example, after the logout() route.

# --- START: FORGOT PASSWORD LOGIC ---

def get_reset_token_serializer():
    """Returns a serializer for generating and verifying password reset tokens."""
    return URLSafeTimedSerializer(app.secret_key)

def send_reset_email(user_email, token):
    """Sends the password reset email."""
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = Message(
        'Password Reset Request - Trade with Plan',
        sender=app.config['MAIL_USERNAME'],
        recipients=[user_email]
    )
    msg.html = f"""
    <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>You requested a password reset for your 'Trade with Plan' account.</p>
            <p>Click the link below to set a new password. This link will expire in 1 hour.</p>
            <p><a href="{reset_url}" style="padding: 10px 15px; background-color: #8b5cf6; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
            <p>If you did not make this request, please ignore this email.</p>
            <p><em>The Trade with Plan Team</em></p>
        </body>
    </html>
    """
    mail.send(msg)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        cur = get_db()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            # Generate a token that includes the user's ID
            serializer = get_reset_token_serializer()
            token = serializer.dumps(user['id'], salt='password-reset-salt')
            
            # Send the email
            send_reset_email(user['email'], token)

        # Flash message regardless of whether user exists to prevent email enumeration
        flash("If an account with that email exists, a password reset link has been sent.", "info")
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    serializer = get_reset_token_serializer()
    try:
        # Verify the token and get the user ID. Max age is 3600 seconds (1 hour).
        user_id = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        flash("The password reset link is invalid or has expired.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template('reset_password.html', token=token)

        strength_error = is_strong_password(password)
        if strength_error:
            flash(strength_error, "error")
            return render_template('reset_password.html', token=token)

        # Hash the new password and update the database
        hashed_password = generate_password_hash(password)
        cur = get_db()
        cur.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, user_id))
        cur.connection.commit()

        flash("Your password has been updated successfully. You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# --- END: FORGOT PASSWORD LOGIC ---


# -------------------------------------
# -------- NEW ADMIN ROUTES -----------
# -------------------------------------

# --- Admin Dashboard with Filtering AND Sorting ---
@app.route('/admin')
@dashboard_access_required
def admin_dashboard():
    """Renders the admin dashboard with lists of users and purchases, including filtering and sorting."""
    cur = get_db()
    
    # --- Get filter and sort parameters from the URL ---
    user_filter = request.args.get('user_filter', '').strip()
    purchase_filter = request.args.get('purchase_filter', '').strip()
    sort_by = request.args.get('sort_by', 'id') # Default sort column
    order = request.args.get('order', 'asc') # Default sort order
    
    # --- Security: Validate sort parameters to prevent SQL injection ---
    # Whitelist of columns that are allowed to be sorted
    user_sortable_columns = ['id', 'fullname', 'email']
    purchase_sortable_columns = ['id', 'fullname', 'email', 'course_name', 'purchase_date']
    
    # Check if the requested sort column is in the appropriate whitelist
    is_user_sort = sort_by in user_sortable_columns
    is_purchase_sort = sort_by in purchase_sortable_columns
    
    # Default to a safe column if an invalid one is provided
    if not (is_user_sort or is_purchase_sort):
        sort_by = 'id'
        
    # Ensure order is either 'asc' or 'desc'
    if order not in ['asc', 'desc']:
        order = 'asc'

    # --- Fetch users with filtering and sorting ---
    users_query = "SELECT * FROM users"
    params = []
    if user_filter:
        users_query += " WHERE fullname ILIKE %s OR email ILIKE %s"
        params.extend([f"%{user_filter}%", f"%{user_filter}%"])
    
    if is_user_sort:
        # Safely add the validated sort parameters to the query
        users_query += f" ORDER BY {sort_by} {order.upper()}"
        
    cur.execute(users_query, tuple(params))
    users = cur.fetchall()
    
    # --- Fetch purchases with filtering and sorting ---
    purchases_query = """
        SELECT 
            p.id, p.course_name, p.purchase_date,
            u.id AS user_id, u.fullname, u.email
        FROM purchases p
        JOIN users u ON p.user_id = u.id
    """
    params = []
    if purchase_filter:
        purchases_query += " WHERE u.fullname ILIKE %s OR u.email ILIKE %s OR p.course_name ILIKE %s"
        params.extend([f"%{purchase_filter}%", f"%{purchase_filter}%", f"%{purchase_filter}%"])
    
    if is_purchase_sort:
        # Safely add the validated sort parameters to the query
        purchases_query += f" ORDER BY {sort_by} {order.upper()}"
    else:
        # Default sort for purchases if no valid sort is specified
        purchases_query += " ORDER BY purchase_date DESC"

    cur.execute(purchases_query, tuple(params))
    purchases = cur.fetchall()
    
    return render_template('admin.html', 
                           users=users, 
                           purchases=purchases, 
                           user_filter=user_filter, 
                           purchase_filter=purchase_filter,
                           sort_by=sort_by,
                           order=order)


# --- NEW: Route to handle editing a user (both GET and POST) ---
@app.route('/admin/edit-user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    cur = get_db()

    # Fetch the user to edit
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        new_fullname = request.form['fullname']
        new_email = request.form['email']

        # Check if the new email is already taken by another user
        cur.execute("SELECT id FROM users WHERE email = %s AND id != %s", (new_email, user_id))
        if cur.fetchone():
            flash("That email address is already in use by another user.", "error")
            return render_template('edit_user.html', user=user)

        # Update the user's information
        try:
            cur.execute("UPDATE users SET fullname = %s, email = %s WHERE id = %s",
                        (new_fullname, new_email, user_id))
            cur.connection.commit()
            flash(f"User {user_id} has been updated successfully.", "success")
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            get_db().connection.rollback()
            flash(f"An error occurred while updating user: {e}", "error")

    return render_template('edit_user.html', user=user)



@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Deletes a user and all their purchases."""
    cur = get_db()
    try:
        # First, delete all purchases associated with the user
        cur.execute("DELETE FROM purchases WHERE user_id = %s", (user_id,))
        # Then, delete the user
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        cur.connection.commit()
        flash(f"User ID {user_id} and all their purchases have been deleted.", "success")
    except Exception as e:
        get_db().connection.rollback()
        flash(f"An error occurred while deleting user: {e}", "error")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/add-purchase', methods=['POST'])
@admin_required
def add_purchase():
    """Manually adds a purchase for a user via their email."""
    user_email = request.form.get('user_email')
    course_name = request.form.get('course_name')
    
    cur = get_db()
    try:
        cur.execute("SELECT id FROM users WHERE email = %s", (user_email,))
        user_id_row = cur.fetchone()
        
        if not user_id_row:
            flash(f"User with email '{user_email}' not found.", "error")
            return redirect(url_for('admin_dashboard'))

        user_id = user_id_row['id']
        
        cur.execute("INSERT INTO purchases (user_id, course_name) VALUES (%s, %s)",
                    (user_id, course_name))
        cur.connection.commit()
        flash(f"Manually added '{course_name}' purchase for user '{user_email}'.", "success")
    except psycopg2.errors.UniqueViolation:
        get_db().connection.rollback()
        flash(f"User '{user_email}' already owns the '{course_name}' course.", "warning")
    except Exception as e:
        get_db().connection.rollback()
        flash(f"An error occurred while adding purchase: {e}", "error")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete-purchase/<int:purchase_id>', methods=['POST'])
@admin_required
def delete_purchase(purchase_id):
    """Deletes a specific purchase record."""
    cur = get_db()
    try:
        cur.execute("DELETE FROM purchases WHERE id = %s", (purchase_id,))
        cur.connection.commit()
        flash(f"Purchase ID {purchase_id} has been deleted.", "success")
    except Exception as e:
        get_db().connection.rollback()
        flash(f"An error occurred while deleting purchase: {e}", "error")
    return redirect(url_for('admin_dashboard'))


@app.route('/course1')
@login_and_purchase_required('ICT "Forever Model"')
def course1():
    return render_template('course1.html')


@app.route('/course2')
@login_and_purchase_required('Basic to Advanced')
def course2():
    return render_template('course2.html')


@app.route('/course3')
@login_and_purchase_required('1-1 Personal Mentorship')
def course3():
    return render_template('course3.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)