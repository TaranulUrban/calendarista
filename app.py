from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps


app = Flask(__name__)


app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


db = SQL("sqlite:///clienti.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response



def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code



def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function



@app.route("/")
@login_required
def index():
    user_id = session["user_id"]
    return render_template("/index.html",)



@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("login.html")



@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username")
        if not request.form.get("password"):
            return apology("must provide a password")
        if not request.form.get("confirmation"):
            return apology("must confirm the password")

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("the password does not match the confirmation")

        hash = generate_password_hash(request.form.get("password"))

        try:
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", request.form.get("username"), hash)
            return redirect("/")
        except:
            return apology("username alredy exists")

    else:
        return render_template("/register.html")




@app.route("/catalog", methods=["GET", "POST"])
@login_required

def catalog():
    user_id = session["user_id"]
    catalog = db.execute("SELECT categorie, serviciu, durata, pret FROM servicii WHERE user_id = ?", user_id)

    if request.method == "GET":
        return render_template("catalog.html", catalog=catalog)

    if request.method == "POST":
        return render_template("catalog.html", catalog=catalog)


@app.route("/servicii", methods=["GET", "POST"])
@login_required
def servicii():
    user_id = session["user_id"]
    categorii = db.execute("SELECT nume_categorie FROM categorii GROUP BY nume_categorie")

    if request.method == "GET":
        return render_template("servicii.html", categorii=categorii)

    if request.method == "POST":
        categorie = request.form.get("categorie")
        serviciu = request.form.get("serviciu")
        durata = int(request.form.get("durata"))
        pret = int(request.form.get("pret"))

        if not categorie:
            return render_template("categoria?")
        if not serviciu:
            return render_template("serviciu?")
        if pret < 1:
            return apology("pune macar 1 LEU :) ")

        db.execute("INSERT INTO servicii (user_id, categorie, serviciu, durata, pret) VALUES (?, ?, ?, ?, ?)", user_id, categorie, serviciu, durata, pret)

        return redirect("/catalog")





@app.route("/categorie", methods=["GET", "POST"])
@login_required
def categorie():
    if request.method == "GET":
        return render_template("categorie.html")

    if request.method == "POST":
        categorie = request.form.get("categorie")

        if not categorie:
            return apology("va rog inserati o categorie")

        db.execute("INSERT INTO categorii(nume_categorie) VALUES (?)", categorie)

        return redirect("/catalog")
