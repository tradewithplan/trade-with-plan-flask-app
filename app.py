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


app = Flask(__name__)
app.secret_key = os.urandom(24)

load_dotenv()

# 2. Get the database connection URL from environment variables
# DATABASE_URL = os.environ.get('DATABASE_URL')
DATABASE_URL = os.getenv('DATABASE_URL')

print(DATABASE_URL)

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


# ---------- Decorators ----------
def login_required(f):
    """
    Decorate routes to require login.
    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to be logged in to access this page.", "warning")
            return redirect(url_for('login'))
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

    return render_template('signup.html')


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

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['fullname']
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid email or password.", "error")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    # Redirect to the public home page instead of the login page
    return redirect(url_for('home')) 


# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
# Use environment variables for sensitive data in production
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER') # Your email address
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS') # Your App Password
# ADD THIS LINE for the admin's email
app.config['ADMIN_EMAIL'] = os.environ.get('ADMIN_EMAIL')

# Initialize the Mail instance
mail = Mail(app)

# 5. New route to handle course purchases
# Add pytz to your imports at the top of the file
from datetime import datetime
import pytz


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

@app.route('/course1')
def course1():
    return render_template('course1.html')


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
