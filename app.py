from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Election, Candidate, Vote, AuditLog
import datetime, random, os, re
from itsdangerous import URLSafeTimedSerializer

# -----------------------
# APP INIT
# -----------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "super_secret_key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///database.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Flask-Mail Config
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# Init extensions
mail = Mail(app)
db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)
csrf = CSRFProtect(app)

# Serializer for password reset tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# -----------------------
# UTILITY FUNCTIONS
# -----------------------
def log_action(user_id, custom_id, action):
    log = AuditLog(user_id=user_id, user_custom_id=custom_id, action=action, timestamp=datetime.datetime.utcnow())
    db.session.add(log)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def generate_custom_id(role):
    year_suffix = datetime.datetime.now().strftime("%y")
    role_map = {"voter":"V", "candidate":"C", "auditor":"AUD", "admin":"ADM"}
    role_char = role_map.get(role, "U")
    count = User.query.filter(User.role == role).count() + 1
    return f"UID{role_char}{count:04d}{year_suffix}"

def send_email(subject, recipients, html_body):
    msg = Message(subject, recipients=recipients, html=html_body)
    mail.send(msg)

def validate_password_strength(password):
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one digit."
    if not re.search(r"[@$!%*?&]", password):
        return "Password must contain at least one special character (@$!%*?&)."
    return None

# -----------------------
# CREATE TABLES
# -----------------------
with app.app_context():
    db.create_all()

# -----------------------
# FORMS
# -----------------------
class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    role = StringField("Role", validators=[DataRequired()])
    national_id = StringField("National ID")
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class OTPForm(FlaskForm):
    otp = StringField("OTP", validators=[DataRequired(), Length(6,6)])
    submit = SubmitField("Verify OTP")

class ForgotPasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Send Reset Link")

class ResetPasswordForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Reset Password")

# -----------------------
# ROUTES
# -----------------------
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

# -----------------------
# REGISTER
# -----------------------
@app.route("/register", methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        role = form.role.data
        national_id = form.national_id.data

        # Validate password strength
        err = validate_password_strength(password)
        if err:
            flash(err, "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))

        if national_id and User.query.filter_by(national_id=national_id).first():
            flash("This National ID is already registered.", "danger")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        otp = random.randint(100000,999999)
        session["reg_otp"] = {"otp": otp, "expires": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)}
        session["pending_user"] = {"username": username, "email": email, "password_hash": password_hash, "role": role, "national_id": national_id}

        html_body = f"<p>Your registration OTP is <strong>{otp}</strong>. It expires in 5 minutes.</p>"
        send_email("Registration OTP", [email], html_body)

        flash("OTP sent to your email.", "success")
        return redirect(url_for("verify_registration"))
    return render_template("register.html", form=form)

# -----------------------
# VERIFY REGISTRATION
# -----------------------
@app.route("/verify_registration", methods=["GET","POST"])
def verify_registration():
    form = OTPForm()
    if "pending_user" not in session or "reg_otp" not in session:
        return redirect(url_for("register"))

    otp_data = session["reg_otp"]
    if datetime.datetime.utcnow() > otp_data["expires"]:
        session.pop("reg_otp")
        session.pop("pending_user")
        flash("OTP expired. Please register again.", "danger")
        return redirect(url_for("register"))

    if form.validate_on_submit():
        if str(otp_data["otp"]) == form.otp.data:
            data = session["pending_user"]
            new_user = User(username=data["username"], email=data["email"], password_hash=data["password_hash"],
                            role=data["role"], national_id=data["national_id"], custom_id=generate_custom_id(data["role"]), is_approved=True)
            db.session.add(new_user)
            db.session.commit()
            log_action(new_user.id, new_user.custom_id, "Account Registered")
            session.clear()
            flash("Registration complete!", "success")
            return redirect(url_for("login"))
        flash("Invalid OTP.", "danger")
    return render_template("otp.html", form=form)

# -----------------------
# LOGIN
# -----------------------
@app.route("/login", methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            otp = random.randint(100000,999999)
            session["otp"] = {"otp": otp, "expires": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)}
            session["otp_user"] = user.id
            html_body = f"<p>Your login OTP is <strong>{otp}</strong>. Expires in 5 minutes.</p>"
            send_email("Login OTP", [email], html_body)
            flash("OTP sent to your email.", "info")
            return redirect(url_for("verify_otp"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html", form=form)

# -----------------------
# VERIFY LOGIN OTP
# -----------------------
@app.route("/verify_otp", methods=["GET","POST"])
def verify_otp():
    form = OTPForm()
    if "otp" not in session or "otp_user" not in session:
        flash("No OTP session found.", "danger")
        return redirect(url_for("login"))

    otp_data = session["otp"]
    if datetime.datetime.utcnow() > otp_data["expires"]:
        session.pop("otp")
        session.pop("otp_user")
        flash("OTP expired. Please login again.", "danger")
        return redirect(url_for("login"))

    if form.validate_on_submit():
        if str(otp_data["otp"]) == form.otp.data:
            user = User.query.get(session["otp_user"])
            login_user(user)
            log_action(user.id, user.custom_id, "Logged In")
            session.pop("otp")
            session.pop("otp_user")
            return redirect(url_for("dashboard"))
        flash("Invalid OTP.", "danger")
    return render_template("otp.html", form=form)

# -----------------------
# DASHBOARD
# -----------------------
@app.route("/dashboard")
@login_required
def dashboard():
    role_redirects = {"admin":"admin_dashboard","voter":"voter_dashboard","candidate":"candidate_dashboard","auditor":"auditor_dashboard"}
    return redirect(url_for(role_redirects.get(current_user.role, "logout")))

# -----------------------
# FORGOT PASSWORD
# -----------------------
@app.route("/forgot_password", methods=["GET","POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(user.email, salt="password-reset-salt")
            user.reset_token = token
            user.reset_token_expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            db.session.commit()
            reset_url = url_for("reset_password", token=token, _external=True)
            html_body = f"<p>Hello {user.username},</p><p>Click <a href='{reset_url}'>here</a> to reset your password (valid 30 min).</p>"
            send_email("Password Reset", [user.email], html_body)
            flash("Password reset link sent to your email.", "info")
        else:
            flash("Email not found.", "danger")
        return redirect(url_for("forgot_password"))
    return render_template("forgot_password.html", form=form)

# -----------------------
# RESET PASSWORD
# -----------------------
@app.route("/reset_password/<token>", methods=["GET","POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=1800)
    except:
        flash("Reset link invalid or expired.", "danger")
        return redirect(url_for("forgot_password"))

    user = User.query.filter_by(email=email).first()
    if not user or user.reset_token != token:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for("forgot_password"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        err = validate_password_strength(form.password.data)
        if err:
            flash(err, "danger")
            return render_template("reset_password.html", form=form)
        user.password_hash = generate_password_hash(form.password.data)
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()
        flash("Password reset successful! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", form=form)

# -----------------------
# LOGOUT
# -----------------------
@app.route("/logout")
@login_required
def logout():
    log_action(current_user.id, current_user.custom_id,"Logged Out")
    logout_user()
    return redirect(url_for("login"))

# -----------------------
# RUN
# -----------------------
if __name__ == "__main__":
    app.run(debug=True)