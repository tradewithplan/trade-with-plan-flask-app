# 1. Import necessary libraries
import os
import psycopg2
import psycopg2.extras  # Needed to access columns by name
from flask import Flask, render_template, request, redirect, session, url_for, g, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv

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
@login_required
def home():
    """
    Displays the home page and fetches the user's purchased courses.
    """
    cur = get_db()
    # 4. Fetch the list of courses the user has purchased
    cur.execute("SELECT course_name FROM purchases WHERE user_id = %s", (session['user_id'],))
    purchased_courses_rows = cur.fetchall()
    # Convert list of row objects to a simple list of strings
    purchased_courses = [row['course_name'] for row in purchased_courses_rows]

    # Pass the list of purchased courses to the template
    return render_template('index.html', purchased_courses=purchased_courses)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('signup'))

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
    return redirect(url_for('login'))


# 5. New route to handle course purchases
@app.route('/purchase/<string:course_name>', methods=['POST'])
@login_required
def purchase(course_name):
    """
    Handles the logic for purchasing a course.
    """
    try:
        cur = get_db()
        # Insert the purchase record into the database
        cur.execute("INSERT INTO purchases (user_id, course_name) VALUES (%s, %s)",
                    (session['user_id'], course_name))
        cur.connection.commit()
        flash(f"Successfully purchased the '{course_name}' course!", "success")
    except psycopg2.errors.UniqueViolation:
        # This prevents a user from buying the same course twice
        flash("You have already purchased this course.", "info")
        get_db().connection.rollback()
    except Exception as e:
        flash(f"An error occurred: {e}", "error")
        get_db().connection.rollback()

    return redirect(url_for('home'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
