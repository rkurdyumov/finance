import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL(os.getenv("DATABASE_URL"))

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        if request.form.get("buy"):
            return redirect(url_for("buy", symbol=request.form["buy"]))
        else:
            return redirect(url_for("sell", symbol=request.form["sell"]))

    cash = db.execute(
        "SELECT * FROM users WHERE id = :id", id=session["user_id"])[0]["cash"]
    total = cash
    rows = db.execute(
        ("SELECT symbol, sum(shares) as shares FROM transactions "
         "WHERE user_id=:id GROUP BY symbol"),
        id=session["user_id"])
    stocks = []
    for row in rows:
        if row["shares"] == 0:
            continue
        quote = lookup(row["symbol"])
        share_total = row["shares"] * quote["price"]
        stocks.append({"symbol": row["symbol"],
                       "shares": row["shares"],
                       "price": usd(quote["price"]),
                       "total": usd(share_total)})
        total += share_total
    return render_template(
        "index.html", stocks=stocks, cash=usd(cash), total=usd(total))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Modify account settings"""
    if request.method == "GET":
        username = db.execute("SELECT * FROM users WHERE id = :id",
                              id=session["user_id"])[0]["username"]
        return render_template("account.html", username=username)

    # Process username change.
    if "submit_username" in request.form:
        if not request.form.get("username"):
            return apology("missing new username")
        elif not request.form.get("password"):
            return apology("missing password")

        # Query database for new username
        rows = db.execute("SELECT * FROM users WHERE username = :u",
                          u=request.form.get("username"))
        if len(rows) != 0:
            return apology("username already exists")

        hash = db.execute("SELECT * FROM users WHERE id = :id",
                          id=session["user_id"])[0]["hash"]
        if not check_password_hash(hash, request.form.get("password")):
            return apology("invalid password", 403)

        db.execute("UPDATE users SET username=:u WHERE id=:id",
                   u=request.form.get("username"),
                   id=session["user_id"])
        flash("Updated username!")
    # Process password change.
    else:
        if not request.form.get("password"):
            return apology("missing current password")
        elif not request.form.get("new_password"):
            return apology("missing new password")
        elif request.form.get("new_password") != request.form.get("confirmation"):
            return apology("password confirmation must match", 403)
        elif request.form.get("password") == request.form.get("new_password"):
            return apology("new password same as old", 403)

        hash = db.execute("SELECT * FROM users WHERE id = :id",
                          id=session["user_id"])[0]["hash"]
        if not check_password_hash(hash, request.form.get("password")):
            return apology("invalid password", 403)

        db.execute(
            "UPDATE users SET hash=:h WHERE id=:id",
            h=generate_password_hash(request.form.get("new_password")),
            id=session["user_id"])
        flash("Updated password!")
    return redirect("/account")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html", symbol=request.args.get("symbol"))

    if not request.form.get("symbol"):
        return apology("missing symbol", 400)
    elif not request.form.get("shares"):
        return apology("missing shares", 400)
    quote = lookup(request.form.get("symbol"))
    if not quote:
        return apology("invalid symbol", 400)

    cash = db.execute("SELECT * FROM users WHERE id = :id",
                      id=session["user_id"])[0]["cash"]
    purchase_price = int(request.form.get("shares")) * quote["price"]
    if purchase_price > cash:
        return apology("can't afford", 400)

    db.execute(
        ("INSERT INTO transactions (user_id, symbol, shares, price) "
         "VALUES (:u, :sy, :sh, :p)"),
        u=session["user_id"],
        sy=request.form.get("symbol"),
        sh=request.form.get("shares"),
        p=quote["price"])
    db.execute("UPDATE users SET cash=cash-:c WHERE id=:id",
               c=purchase_price,
               id=session["user_id"])
    flash("Bought!")
    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        ("SELECT symbol, shares, price, time FROM transactions "
         "WHERE user_id=:id"),
        id=session["user_id"])
    for transaction in transactions:
        transaction["price"] = usd(transaction["price"])
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("login.html")

    # User reached route via POST (as by submitting a form via POST)
    # Ensure username was submitted
    if not request.form.get("username"):
        return apology("must provide username", 403)

    # Ensure password was submitted
    elif not request.form.get("password"):
        return apology("must provide password", 403)

    # Query database for username
    rows = db.execute("SELECT * FROM users WHERE username = :username",
                      username=request.form.get("username"))

    # Ensure username exists and password is correct
    if len(rows) != 1 or not check_password_hash(
        rows[0]["hash"], request.form.get("password")):
        return apology("invalid username and/or password", 403)

    # Remember which user has logged in
    session["user_id"] = rows[0]["id"]

    # Redirect user to home page
    return redirect("/")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to homepage
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")

    if not request.form.get("symbol"):
        return apology("missing symbol", 400)

    quote = lookup(request.form.get("symbol"))
    if not quote:
        return apology("invalid symbol", 400)

    return render_template("quoted.html",
                           name=quote["name"],
                           symbol=quote["symbol"],
                           price=usd(quote["price"]))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    # Ensure username was submitted
    if not request.form.get("username"):
        return apology("must provide username", 403)
    # Ensure username is not already taken
    rows = db.execute("SELECT * FROM users WHERE username = :username",
                      username=request.form.get("username"))
    if len(rows) == 1:
        return apology("username already exists", 403)
    # Ensure password was submitted
    elif not request.form.get("password"):
        return apology("must provide password", 403)
    # Ensure password confirmation matches
    elif request.form.get("password") != request.form.get("confirmation"):
        return apology("password confirmation must match", 403)

    # Add user and automatically log in.
    id = db.execute("INSERT INTO users (username, hash) VALUES (:u, :h)",
                    u=request.form.get("username"),
                    h=generate_password_hash(request.form.get("password")))
    session["user_id"] = id
    flash("Registered!")
    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        shares = db.execute(
            ("SELECT symbol, sum(shares) as shares FROM transactions "
             "WHERE user_id=:id GROUP BY symbol"),
            id=session["user_id"])
        symbols = [share["symbol"] for share in shares if share["shares"]]
        return render_template("sell.html", symbols=symbols,
                               symbol=request.args.get("symbol"))

    if not request.form.get("symbol"):
        return apology("missing symbol", 400)
    elif not request.form.get("shares"):
        return apology("missing shares", 400)
    elif int(request.form.get("shares")) < 1:
        return apology("must sell at least one share", 400)

    rows = db.execute(("SELECT sum(shares) as shares FROM transactions "
                       "WHERE user_id=:id AND symbol=:symbol"),
                      id=session["user_id"],
                      symbol=request.form.get("symbol"))
    requested_shares = int(request.form.get("shares"))
    if requested_shares > rows[0]["shares"]:
        return apology("too many shares", 400)

    quote = lookup(request.form.get("symbol"))
    db.execute(("INSERT INTO transactions (user_id, symbol, shares, price) "
                "VALUES (:u, :sy, :sh, :p)"),
               u=session["user_id"],
               sy=request.form.get("symbol"),
               sh=-requested_shares,
               p=quote["price"])
    sell_price = int(request.form.get("shares")) * quote["price"]
    db.execute("UPDATE users SET cash=cash+:c WHERE id=:id",
               c=sell_price,
               id=session["user_id"])
    flash("Sold!")
    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
