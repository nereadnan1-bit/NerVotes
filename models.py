from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    custom_id = db.Column(db.String(20), unique=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    national_id = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    is_approved = db.Column(db.Boolean, default=True)
    failed_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100), nullable=True)

class Election(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='active')


class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Changed from voter_id to user_id to match your app.py logic
    user_id = db.Column(db.Integer, db.ForeignKey('user.id')) 
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'))
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user_custom_id = db.Column(db.String(20)) # <--- This MUST be here
    action = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'))

    full_name = db.Column(db.String(150))
    manifesto = db.Column(db.Text)
    photo = db.Column(db.String(200))

    is_approved = db.Column(db.Boolean, default=False)

    user = db.relationship("User")
    election = db.relationship("Election")