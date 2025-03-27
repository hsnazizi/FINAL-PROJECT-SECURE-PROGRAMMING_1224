from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
import bcrypt  
from time import time
from datetime import timedelta

app = Flask(__name__)
app.secret_key = "supersecretkey"
DATABASE = 'members.db'

# Configure session security settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # Prevent client-side JS from accessing the cookie
    SESSION_COOKIE_SECURE=True,        # Only send cookie over HTTPS (in production)
    SESSION_COOKIE_SAMESITE='Lax',     # Prevent CSRF attacks
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=10)
)

USERS = {
    "staff": {"password": "", "role": "staff"},
    "member": {"password": "", "role": "member"},
    "pakkarim": {"password": "", "role": "staff"}
}

def generate_hashes():
    """Run this ONCE to create password hashes"""
    hashes = {
        "staff": bcrypt.hashpw("staffpass".encode(), bcrypt.gensalt()).decode(),
        "member": bcrypt.hashpw("memberpass".encode(), bcrypt.gensalt()).decode(),
        "pakkarim": bcrypt.hashpw("karim".encode(), bcrypt.gensalt()).decode()
    }
    print("COPY THESE HASHES INTO YOUR USERS DICTIONARY:")
    print(hashes)
    return hashes

# Uncomment the next line, run the app ONCE, then re-comment it:
generated_hashes = generate_hashes()


USERS = {
    "staff": {
        "password": "$2b$12$Tt2b.CGfZruH.P2LmOQ3F.DYV37y68H/JMlxLOFMFsdztBYqpH8dS",  
        "role": "staff"
    },
    "member": {
        "password": "2b$12$QKbaANjQMRhlMaQSX9CVeur9a4SEayx9L5.9PuZFGZdyLTTgsRPO6",  
        "role": "member"
    },
    "pakkarim": {
        "password": "$2b$12$CkQAzIwzDQeyIG/4xyLfveTw8ms09pddWbNcZzfYg94w.lZj5YaMe",  
        "role": "staff"
    }
}

# Track failed login attempts and lock accounts after multiple failures
FAILED_ATTEMPTS = {}
LOCKED_ACCOUNTS = {}
MAX_ATTEMPTS = 5  # Lock the account after 5 failed attempts
LOCKOUT_TIME = 300  # Lockout period in seconds (5 minutes)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.before_request
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                membership_status TEXT NOT NULL
                )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                id INTEGER PRIMARY KEY,
                class_name TEXT NOT NULL,
                class_time TEXT NOT NULL
                )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                member_id INTEGER,
                class_id INTEGER,
                FOREIGN KEY (member_id) REFERENCES members (id),
                FOREIGN KEY (class_id) REFERENCES classes (id)
                )''')
    db.commit()

# Home Route (Login)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        try:
            password = request.form['password'].encode('utf-8')

            # Check if the account is locked
            if username in LOCKED_ACCOUNTS:
                if time() - LOCKED_ACCOUNTS[username] < LOCKOUT_TIME:
                    return "Account temporarily locked. Try again later.", 403
                else:
                    del LOCKED_ACCOUNTS[username]  # Unlock after timeout

            user = USERS.get(username)
            if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
                session_data = {
                    'user': username,
                    'role': user['role'],
                    'last_activity': time()
                }
                
                # Clear the existing session completely
                session.clear()
                
                session['_fresh'] = True 
        
                
                # Now set up the new session
                session.update(session_data)
                session.permanent = True

                # Reset failed attempts on successful login
                FAILED_ATTEMPTS.pop(username, None)  
                return redirect(url_for('dashboard'))

            # Track failed attempts
            FAILED_ATTEMPTS[username] = FAILED_ATTEMPTS.get(username, 0) + 1

            if FAILED_ATTEMPTS[username] >= MAX_ATTEMPTS:
                LOCKED_ACCOUNTS[username] = time()
                return "Too many failed attempts. Account locked.", 403

        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")

        return "Invalid username or password", 401

    return render_template('login.html')

# Dashboard (for both staff and members)
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    username = session['user']
    return render_template('dashboard.html', username=username)

# Member Management Routes
@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))

    return render_template('add_member.html')

# View specific member classes
@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get member classes
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                       "JOIN member_classes mc ON c.id = mc.class_id "
                       "WHERE mc.member_id = ?", [member_id])
    return render_template('member_classes.html', member=member, classes=classes)

# Register class
@app.route('/register_classes/<int:member_id>', methods=['GET', 'POST'])
def register_classes(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    classes = query_db("SELECT * FROM classes")  # Get all available classes

    if request.method == 'POST':
        class_id = request.form['class_id']
        db = get_db()
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES(?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('member_classes', member_id=member_id))

    return render_template('register_classes.html', member_id=member_id, classes=classes)

# View members
@app.route('/view_members')
def view_members():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)

# Registering a Member
@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))

    return render_template('register_member.html')

# Class Scheduling Routes
@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        db = get_db()
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)", (class_name, class_time))
        db.commit()
        return redirect(url_for('view_classes'))

    return render_template('add_class.html')

@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))

    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)

# Deleting member
@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    db = get_db()
    db.execute("DELETE FROM members WHERE id = ?", [member_id])
    db.execute("DELETE FROM member_classes WHERE member_id = ?", [member_id])
    db.commit()

    return redirect(url_for('view_members'))

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)