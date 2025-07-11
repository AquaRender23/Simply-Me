import os
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import random

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

#links the database
def get_db_connection():
    conn = sqlite3.connect('journal.db')
    conn.row_factory = sqlite3.Row
    return conn

#creates table if it doesn't exist
def initialize_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            hash TEXT NOT NULL
        )
    """)

    conn.execute("""
                     CREATE TABLE IF NOT EXISTS entries(
                     id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                     user_id INTEGER NOT NULL,
                     title TEXT NOT NULL,
                     content TEXT NOT NULL,
                     timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                     FOREIGN KEY(user_id) REFERENCES users(id)
                     )
                 """)

    conn.execute("""
                 CREATE TABLE IF NOT EXISTS reminders(
                 id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                 user_id INTEGER NOT NULL,
                 title TEXT NOT NULL,
                 due_date TEXT,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY(user_id) REFERENCES users(id)
                 )
            """)

    conn.commit()
    conn.close()
initialize_db()


#Responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = "0"
    response.headers["Pragma"] = "no-cache"
    return response


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


@app.route("/")
@login_required
def index():
    return render_template("index.html")


def apology(message, code=400):
    #Render message as an apology to user.

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


#Registers user
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("Username required")

        elif not password:
            return apology("Password required")

        elif not confirmation:
            return apology("Confirmation of password  required")


        if confirmation != password:
            return apology("Password doesn't match")

        hash_pw = generate_password_hash(password)

        try:
            conn = get_db_connection()
            conn.execute("INSERT INTO users (username, hash) VALUES (?, ?)", (username, hash_pw))
            conn.commit()
            conn.close()

        except sqlite3.IntegrityError:
            return apology("Username already exists")

        return redirect("/login")
    return render_template("register.html")


#Logs user in
@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            return apology("Username required", 403)
        elif not password:
            return apology("Password required", 403)

        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()
        conn.commit()
        conn.close()

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("Invalid username or password", 403)

        session["user_id"] = rows[0]["id"]
        return redirect("/")

    return render_template("login.html")

#Logs user out
@app.route("/logout")
def logout():
    session.clear()

    return redirect(url_for("login"))


#Creates a new entry
@app.route("/new-entry", methods=["GET","POST"])
@login_required
def new_entry():
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")

        if not title:
            return apology("Cannot save entry without title")
        if not content:
            return apology("Cannot save entry without content")

        conn = get_db_connection()
        conn.execute("INSERT INTO entries (user_id , title , content) VALUES (?, ?, ?)", (session["user_id"], title, content,))
        conn.commit()
        conn.close()

        return redirect("/")
    return render_template("new-entry.html")


#Shows all the saved entries
@app.route("/entries")
@login_required
def entries():

    conn = get_db_connection()
    rows = conn.execute("SELECT title, content, timestamp FROM entries WHERE user_id = ?", (session["user_id"],)).fetchall()
    conn.close()

    print(f"[DEBUG] Entries for user {session['user_id']}:", rows)
    return render_template("entries.html", entries=rows)


#Shows the quotes list
@app.route("/quotes")
@login_required
def quotes():

    quote = [
                "Start where you are. Use what you have. Do what you can.",
                "If you can dream it, you can do it.",
                "Feel it. Heal it. Let it go.",
                "Believe you can and you're halfway there.",
                "The only way to do great work is to love what you do.",
                "Doubt kills more dreams than failure ever will.",
                "Success is not final, failure is not fatal: It is the courage to continue that counts.",
                "What lies behind us and what lies before us are tiny matters compared to what lies within us.",
                "If you want something you’ve never had, you must be willing to do something you’ve never done.",
                "The best way to get started is to quit talking and begin doing.",
                "Your mountain may be harder to climb, but oh, the view will be worth it.",
                "Magic happens when you do not give up, even though you want to.",
                "You are not behind in life. There’s no race — you're on your own journey.",
                "Trust the timing of your life.",
                "Your story matters. Every version of it.",
    ]

    return render_template("quotes.html", quotes = quote)


#To add a reminder
@app.route("/add_reminder",  methods=["POST"])
@login_required
def add_reminder():

        title = request.form.get("title")
        due = request.form.get("due_date")

        if not title:
            return apology("Cannot save without a title")

        conn = get_db_connection()
        conn.execute("INSERT INTO reminders (user_id, title, due_date) VALUES (?, ?, ?)", (session["user_id"], title, due))
        conn.commit()
        conn.close()

        return redirect("/reminders")


#To view all reminders
@app.route("/reminders")
@login_required
def reminders():

    conn = get_db_connection()
    reminders = conn.execute("SELECT * FROM reminders WHERE user_id = ?", (session["user_id"],)).fetchall()
    conn.close()

    return render_template("reminders.html", reminders = reminders)


#To delete a reminder
@app.route("/delete_reminder/<int:reminder_id>", methods=["POST"])
@login_required
def delete_reminder(reminder_id):

    conn = get_db_connection()
    conn.execute("DELETE FROM reminders WHERE id = ? AND user_id = ?", (reminder_id, session["user_id"]))
    conn.commit()
    conn.close()

    return redirect("/reminders")
