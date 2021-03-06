from datetime import datetime
from app import db, login, app, oembed
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from time import time
import jwt
from flask import Markup
from markdown import markdown
from micawber import parse_html


@login.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    notes = db.relationship('Note', backref='author', lazy='dynamic')
    
    def __repr__(self):
        return '<Note {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def followed_posts(self):
    	own = Note.query.filter_by(user_id=self.id)
    	return own.order_by(Note.timestamp.desc()).filter(Note.archived == False)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')
    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(1400))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    archived = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return '<Note {}>'.format(self.body)

##New code to get markdown integration into the app.

    def html(self):
        html = parse_html(
            markdown(self.body),
            oembed,
            maxwidth=300,
            urlize_all=True)
        return Markup(html)