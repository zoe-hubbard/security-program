from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_talisman import Talisman
from app.utils import sanitize_html
import os
import logging
from logging.handlers import RotatingFileHandler
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from config import Config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


db = SQLAlchemy() # initialises
csrf = CSRFProtect()
bcrypt = Bcrypt()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address, default_limits=["7 per minute"]) # limit set for per ip address per minute

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    csrf.init_app(app)  # initialises csrf protection
    db.init_app(app)
    bcrypt.init_app(app)  # initialises bcyypt
    login_manager.init_app(app)
    limiter.init_app(app) # initialises limit

    csp = {
        'default-src': ["'self'"],
        'script-src': ["'self'", "https://cdn.jsdelivr.net"],  # allow SweetAlert, app.js from static is 'self'
        'style-src': ["'self'", "https://cdn.jsdelivr.net"],
        'img-src': ["'self'", "data:"],
        'connect-src': ["'self'"]
    }

    Talisman(app, content_security_policy=csp, force_https=True,
             strict_transport_security=True, strict_transport_security_max_age=31536000)

    @app.errorhandler(400) # error mpage for a
    def bad_request(e):
        return render_template('error.html', code=400, message="Bad Request"), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('error.html', code=403, message="Access Denied"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('error.html', code=404, message="Not Found"), 404

    @app.errorhandler(500)
    def internal_error(e):
        return render_template('error.html', code=500, message="Internal Server Error"), 500

    from app.models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    login_manager.login_view = 'main.login'

    if not os.path.exists('logs'):
        os.mkdir('logs')  # creates log file
    log_file = os.path.join('logs', 'login.log')  # joins log file

    handler = RotatingFileHandler(log_file, maxBytes=1000000, backupCount=5)  # handler for log
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # creates format for log
        datefmt='%d/%m/%Y %H:%M:%S')
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)

    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('login start')

    from .routes import main
    app.register_blueprint(main)

    with app.app_context():
        from .models import User
        db.drop_all()
        db.create_all()

        users = [
            {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
            {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
            {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
        ]

        for u in users:
            PEPPER = os.environ.get('PASSWORD_PEPPER', '')
            new_user = User(
                username=u["username"],
                password=u["password"],
                role=u["role"],
                bio=sanitize_html(u["bio"])
            )

            db.session.add(new_user)
            db.session.commit()

    return app
