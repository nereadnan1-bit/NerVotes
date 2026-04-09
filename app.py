from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Election, Candidate, Vote, AuditLog
import datetime
import random
import os

app = Flask(__name__)

app.config["SECRET_KEY"] = "super_secret_key"

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///database.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


# ---------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------

def log_action(user_id, custom_id, action):

    log = AuditLog(
        user_id=user_id,
        user_custom_id=custom_id,
        action=action,
        timestamp=datetime.datetime.utcnow()
    )

    db.session.add(log)
    db.session.commit()


@login_manager.user_loader
def load_user(user_id):

    return db.session.get(User, int(user_id))


def generate_custom_id(role):

    year_suffix = datetime.datetime.now().strftime("%y")

    role_map = {
        "voter": "V",
        "candidate": "C",
        "auditor": "AUD",
        "admin": "ADM"
    }

    role_char = role_map.get(role, "U")

    count = User.query.filter(User.role == role).count() + 1

    return f"UID{role_char}{count:04d}{year_suffix}"


with app.app_context():
    db.create_all()

# ---------------------------------------------------
# HOME
# ---------------------------------------------------

@app.route("/")
def home():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    return render_template("index.html")


# ---------------------------------------------------
# REGISTER
# ---------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]
        national_id = request.form.get("national_id")

        if User.query.filter_by(username=username).first():

            flash("Username already exists.", "danger")
            return redirect(url_for("register"))

        if national_id and User.query.filter_by(national_id=national_id).first():

            flash("This National ID is already registered.", "danger")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        otp = random.randint(100000, 999999)

        session["reg_otp"] = otp

        session["pending_user"] = {
            "username": username,
            "password_hash": password_hash,
            "role": role,
            "national_id": national_id
        }

        print("REGISTRATION OTP:", otp)

        return redirect(url_for("verify_registration"))

    return render_template("register.html")


# ---------------------------------------------------
# VERIFY REGISTRATION
# ---------------------------------------------------

@app.route("/verify_registration", methods=["GET", "POST"])
def verify_registration():

    if "pending_user" not in session:
        return redirect(url_for("register"))

    if request.method == "POST":

        if str(session.get("reg_otp")) == request.form.get("otp"):

            data = session["pending_user"]

            new_user = User(
                username=data["username"],
                password_hash=data["password_hash"],
                role=data["role"],
                national_id=data["national_id"],
                custom_id=generate_custom_id(data["role"]),
                is_approved=True
            )

            db.session.add(new_user)
            db.session.commit()

            log_action(new_user.id, new_user.custom_id, "Account Registered")

            session.clear()

            flash("Registration complete!", "success")

            return redirect(url_for("login"))

        flash("Invalid OTP.", "danger")

    return render_template("otp.html")


# ---------------------------------------------------
# LOGIN
# ---------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        user = User.query.filter_by(username=request.form["username"]).first()

        if user and check_password_hash(user.password_hash, request.form["password"]):

            otp = random.randint(100000, 999999)

            session["otp"] = otp
            session["otp_user"] = user.id

            print("LOGIN OTP:", otp)

            return redirect(url_for("verify_otp"))

        flash("Invalid credentials.", "danger")

    return render_template("login.html")


# ---------------------------------------------------
# VERIFY LOGIN OTP
# ---------------------------------------------------

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():

    if request.method == "POST":

        if str(session.get("otp")) == request.form.get("otp"):

            user = User.query.get(session["otp_user"])

            login_user(user)

            log_action(user.id, user.custom_id, "Logged In")

            session.pop("otp")
            session.pop("otp_user")

            return redirect(url_for("dashboard"))

        flash("Invalid OTP.", "danger")

    return render_template("otp.html")


# ---------------------------------------------------
# DASHBOARD ROUTER
# ---------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    role_redirects = {
        "admin": "admin_dashboard",
        "voter": "voter_dashboard",
        "candidate": "candidate_dashboard",
        "auditor": "auditor_dashboard"
    }

    return redirect(url_for(role_redirects.get(current_user.role, "logout")))


# ---------------------------------------------------
# LOGOUT
# ---------------------------------------------------

@app.route("/logout")
@login_required
def logout():

    log_action(current_user.id, current_user.custom_id, "Logged Out")

    logout_user()

    return redirect(url_for("login"))


# ---------------------------------------------------
# RUN APP
# ---------------------------------------------------

if __name__ == "__main__":

    app.run(debug=True)