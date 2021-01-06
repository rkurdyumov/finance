import os

from sqlalchemy import create_engine
from sqlalchemy.sql import text
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or b'_5#y2L"F4Q8z\n\xec]/'

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

# Configure CS50 Library to use Heroku Postgres database
if not os.environ.get("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL not set")
db = create_engine(os.environ.get("DATABASE_URL"))

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

    cash = db.execute(text("SELECT * FROM users WHERE id = :id"),
                      id=session["user_id"]).fetchone()["cash"]
    # Coerce decimal.Decimal into float (Postgres numeric is decimal.Decimal)
    # https://groups.google.com/d/msg/sqlalchemy/0qXMYJvq8SA/oqtvMD9Uw-kJ
    total = float(cash)
    rows = db.execute(text(
        "SELECT symbol, sum(shares) as shares FROM transactions "
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
        username = db.execute(text("SELECT * FROM users WHERE id = :id"),
                              id=session["user_id"]).fetchone()["username"]
        return render_template("account.html", username=username)

    # Process username change.
    if "submit_username" in request.form:
        if not request.form.get("username"):
            return apology("missing new username")
        elif not request.form.get("password"):
            return apology("missing password")

        # Query database for new username
        rows = db.execute(text("SELECT * FROM users WHERE username = :u"),
                          u=request.form.get("username")).fetchall()
        if len(rows) != 0:
            return apology("username already exists")

        hash = db.execute(text("SELECT * FROM users WHERE id = :id"),
                          id=session["user_id"]).fetchone()["hash"]
        if not check_password_hash(hash, request.form.get("password")):
            return apology("invalid password", 403)

        db.execute(text("UPDATE users SET username=:u WHERE id=:id"),
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

        hash = db.execute(text("SELECT * FROM users WHERE id = :id"),
                          id=session["user_id"]).fetchone()["hash"]
        if not check_password_hash(hash, request.form.get("password")):
            return apology("invalid password", 403)

        db.execute(text(
            "UPDATE users SET hash=:h WHERE id=:id"),
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

    cash = db.execute(text("SELECT * FROM users WHERE id = :id"),
                      id=session["user_id"]).fetchone()["cash"]
    purchase_price = int(request.form.get("shares")) * quote["price"]
    if purchase_price > float(cash):
        return apology("can't afford", 400)

    db.execute(text(
        "INSERT INTO transactions (user_id, symbol, shares, price) "
         "VALUES (:u, :sy, :sh, :p)"),
        u=session["user_id"],
        sy=request.form.get("symbol"),
        sh=request.form.get("shares"),
        p=quote["price"])
    db.execute(text("UPDATE users SET cash=cash-:c WHERE id=:id"),
               c=purchase_price,
               id=session["user_id"])
    flash("Bought!")
    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute(text(
        "SELECT symbol, shares, price, time FROM transactions "
        "WHERE user_id=:id"),
        id=session["user_id"])
    transactions = []
    for row in rows:
        transaction = dict(row)
        transaction["price"] = usd(transaction["price"])
        transactions.append(transaction)
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
    row = db.execute(text("SELECT * FROM users WHERE username = :username"),
                     username=request.form.get("username")).fetchone()
    # Ensure username exists
    if row is None:
        return apology("invalid username")
    # Ensure password is correct
    if not check_password_hash(row["hash"], request.form.get("password")):
        return apology("invalid password", 403)

    # Remember which user has logged in
    session["user_id"] = row["id"]

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
    rows = db.execute(text("SELECT * FROM users WHERE username = :username"),
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
    result = db.execute(text("INSERT INTO users (username, hash) VALUES (:u, :h)"),
                        u=request.form.get("username"),
                        h=generate_password_hash(request.form.get("password")))
    # TODO: Use result.inserted_primary_key after converting to SQLAlchemy ORM.
    if db.url.get_backend_name() in ["postgres", "postgresql"]:
        id = session.execute("SELECT LASTVAL()").first()[0]
    else:
        id = result.lastrowid if result.rowcount == 1 else None
    session["user_id"] = id
    flash("Registered!")
    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        rows = db.execute(text(
            "SELECT symbol, sum(shares) as shares FROM transactions "
            "WHERE user_id=:id GROUP BY symbol"),
            id=session["user_id"])
        symbols = [row["symbol"] for row in rows if row["shares"]]
        return render_template("sell.html", symbols=symbols,
                               symbol=request.args.get("symbol"))

    if not request.form.get("symbol"):
        return apology("missing symbol", 400)
    elif not request.form.get("shares"):
        return apology("missing shares", 400)
    elif int(request.form.get("shares")) < 1:
        return apology("must sell at least one share", 400)

    rows = db.execute(text(
        "SELECT sum(shares) as shares FROM transactions "
        "WHERE user_id=:id AND symbol=:symbol"),
        id=session["user_id"],
        symbol=request.form.get("symbol"))
    requested_shares = int(request.form.get("shares"))
    if requested_shares > rows.fetchone()["shares"]:
        return apology("too many shares", 400)

    quote = lookup(request.form.get("symbol"))
    db.execute(text(
        "INSERT INTO transactions (user_id, symbol, shares, price) "
        "VALUES (:u, :sy, :sh, :p)"),
        u=session["user_id"],
        sy=request.form.get("symbol"),
        sh=-requested_shares,
        p=quote["price"])
    sell_price = int(request.form.get("shares")) * quote["price"]
    db.execute(text("UPDATE users SET cash=cash+:c WHERE id=:id"),
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
