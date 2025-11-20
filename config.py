from datetime import timedelta
import os


class Config:
    DEBUG = True
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-placeholder-only"
    SESSION_COOKIE_SECURE = True  # only send cookie over HTTPS
    SESSION_COOKIE_HTTPONLY = True  # JS cannot read cookie
    SESSION_COOKIE_SAMESITE = 'Lax'  # or 'Strict' if no cross-site need
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    SESSION_REFRESH_EACH_REQUEST = True