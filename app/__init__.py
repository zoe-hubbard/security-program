from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from config import Config
import os
import logging
from logging.handlers import RotatingFileHandler
#from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from config import Config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


db = SQLAlchemy() # initialises
csrf = CSRFProtect()
#bcrypt = Bcrypt()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address, default_limits=["7 per minute"]) # limit set for per ip address per minute

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    csrf.init_app(app)  # initialises crsf protection
    db.init_app(app)
    #bcrypt.init_app(app)  # initialises bcyypt
    login_manager.init_app(app)
    limiter.init_app(app)

    from app.models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    login_manager.login_view = 'main.login'

    if not os.path.exists('logs'):
        os.mkdir('logs')  # creates log file
    log_file = os.path.join('logs', 'login.log')  # joins log file

    handler = RotatingFileHandler(log_file, maxBytes=1000000, backupCount=3)  # handler for log
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

        for user in users:
            user = User(username=user["username"], password=user["password"], role=user["role"], bio=user["bio"])
            db.session.add(user)
            db.session.commit()

    return app
