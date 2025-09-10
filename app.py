from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///workshop.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)


class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String(100), nullable=False)
    client_phone = db.Column(db.String(50), nullable=False)
    client_address = db.Column(db.String(200), nullable=False)
    device_type = db.Column(db.String(100), nullable=False)
    device_brand = db.Column(db.String(100), nullable=False)
    problem = db.Column(db.String(200), nullable=False)
    comment = db.Column(db.Text)
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"))


def login_required(role=None):
    def wrapper(func):
        def decorated_view(*args, **kwargs):
            if "user_id" not in session:
                flash("Сначала войдите в систему")
                return redirect(url_for("login"))
            if role and session.get("role") not in role:
                flash("Нет доступа")
                return redirect(url_for("index"))
            return func(*args, **kwargs)
        decorated_view.__name__ = func.__name__
        return decorated_view
    return wrapper


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))

    role = session.get("role")
    if role == "master":
        requests = Request.query.filter_by(assigned_to=session["user_id"]).all()
    else:
        requests = Request.query.all()
    return render_template("index.html", requests=requests, role=role)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and check_password_hash(user.password, request.form["password"]):
            session["user_id"] = user.id
            session["role"] = user.role
            return redirect(url_for("index"))
        flash("Неверный логин или пароль")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/add_request", methods=["GET", "POST"])
@login_required(role=["manager", "director", "creator"])
def add_request():
    if request.method == "POST":
        req = Request(
            client_name=request.form["client_name"],
            client_phone=request.form["client_phone"],
            client_address=request.form["client_address"],
            device_type=request.form["device_type"],
            device_brand=request.form["device_brand"],
            problem=request.form["problem"],
            comment=request.form.get("comment"),
            assigned_to=request.form.get("assigned_to")
        )
        db.session.add(req)
        db.session.commit()
        return redirect(url_for("index"))

    masters = User.query.filter_by(role="master").all()
    return render_template("add_request.html", masters=masters)


@app.route("/register", methods=["GET", "POST"])
@login_required(role=["director", "creator"])
def register():
    if request.method == "POST":
        hashed_password = generate_password_hash(request.form["password"])
        user = User(
            username=request.form["username"],
            password=hashed_password,
            role=request.form["role"]
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("index"))
    return render_template("register.html")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
