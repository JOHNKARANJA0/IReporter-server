#!/usr/bin/env python3

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from sqlalchemy import MetaData
from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

metadata = MetaData(
    naming_convention={
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    }
)

db = SQLAlchemy(metadata=metadata)

# Creating the users
class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    image = db.Column(db.String, nullable=True)
    role = db.Column(db.String, nullable=False)
    _password_hash = db.Column('password_hash', db.String(128), nullable=False)
    token = db.Column(db.String(32), nullable=True)
    token_verified = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=False)
    requesting_admin = db.Column(db.Boolean, default=False)
    
    
    redflags = db.relationship('Redflags', backref='user', lazy=True, cascade='all, delete-orphan')
    interventions = db.relationship('Intervention', backref='user', lazy=True, cascade='all, delete-orphan')
    
    serialize_rules = ('-redflags.user', '-interventions.user')
    
    @validates('email')
    def validate_email(self, key, value):
        assert '@' in value, "Invalid Email provided"
        return value
    
    @hybrid_property    
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')
    
    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password.encode('utf-8')).decode('utf-8')
    
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))


class Redflags(db.Model, SerializerMixin):
    __tablename__ = 'redflags'
    
    id = db.Column(db.Integer, primary_key=True)
    redflag = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    geolocation = db.Column(db.String, nullable=False)
    image = db.Column(db.String, nullable=True)
    video = db.Column(db.String, nullable=True)
    date_added = db.Column(db.DateTime, default=lambda: datetime.now())
    status = db.Column(db.String, default='draft')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    serialize_rules = ('-user',)

    def __repr__(self):
        return f"<Redflags {self.id}>"
    
class Intervention(db.Model, SerializerMixin):
    __tablename__ = 'intervention'
    
    id = db.Column(db.Integer, primary_key=True)
    intervention = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    geolocation = db.Column(db.String, nullable=False)
    image = db.Column(db.String, nullable=True)
    video = db.Column(db.String, nullable=True)
    date_added = db.Column(db.DateTime, default=lambda: datetime.now())
    status = db.Column(db.String, default='draft')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    serialize_rules = ('-user',)

    def __repr__(self):
        return f"<Intervention {self.id}>"