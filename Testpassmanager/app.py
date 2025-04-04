from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import secrets
import os
import requests

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)



# Initialize database
def init_db():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, salt TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (id INTEGER PRIMARY KEY, user_id INTEGER, website TEXT, 
                 username TEXT, password_hash TEXT, salt TEXT)''')
    conn.commit()
    conn.close()


init_db()


# Password hashing
def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()


# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')
    return redirect('/home')


# Add this new route to app.py
@app.route('/send_entry/<int:entry_id>', methods=['POST'])
def send_entry(entry_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''SELECT website, username, password_hash, salt 
                 FROM passwords WHERE id=? AND user_id=?''',
              (entry_id, session['user_id']))
    entry = c.fetchone()
    conn.close()

    if entry:
        # Prepare data to send
        data = {
            'website': entry[0],
            'username': entry[1],
            'password_hash': entry[2],
            'salt': entry[3]
        }

        # Send to backend server (replace with your actual backend URL)
        backend_url = "http://your-backend-server.com/api/store_password"
        try:
            response = requests.post(backend_url, json=data)
            if response.status_code == 200:
                flash(f"Successfully sent {entry[0]} credentials to backend")
            else:
                flash("Failed to send to backend")
        except requests.RequestException:
            flash("Error connecting to backend server")

    return redirect('/home')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute('SELECT id, password_hash, salt FROM users WHERE username=?', (username,))
        user = c.fetchone()
        conn.close()

        if user and hash_password(password, user[2]) == user[1]:
            session['user_id'] = user[0]
            return redirect('/home')
        flash('Invalid credentials')
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        salt = secrets.token_hex(16)
        password_hash = hash_password(password, salt)

        try:
            conn = sqlite3.connect('passwords.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password_hash, salt) VALUES (?,?,?)',
                      (username, password_hash, salt))
            conn.commit()
            conn.close()
            flash('Account created! Please login')
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash('Username exists')
    return render_template('signup.html')


@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute('''SELECT website, username, password_hash, id 
                 FROM passwords WHERE user_id=?''',
              (session['user_id'],))
    passwords = c.fetchall()
    conn.close()

    return render_template('home.html', passwords=passwords)


@app.route('/add', methods=['GET', 'POST'])
def add_password():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        salt = secrets.token_hex(16)
        password_hash = hash_password(password, salt)

        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute('INSERT INTO passwords (user_id, website, username, password_hash, salt) VALUES (?,?,?,?,?)',
                  (session['user_id'], website, username, password_hash, salt))
        conn.commit()
        conn.close()
        return redirect('/home')

    return render_template('add_password.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)