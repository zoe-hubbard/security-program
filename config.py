from datetime import timedelta
import os
from cryptography.fernet import Fernet


class Config:
    DEBUG = True
    SECRET_KEY = os.environ.get("SECRET_KEY") or "o1r3B9U0R5i6hQk5S0v9Zr3mXj2x8KfM4Yl5sD6d7f8="
    SESSION_COOKIE_SECURE = False # change in prod
    SESSION_COOKIE_HTTPONLY = False  # change inm prod
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    SESSION_REFRESH_EACH_REQUEST = True
    FERNET_KEY = os.environ.get('FERNET_KEY') or Fernet.generate_key().decode()