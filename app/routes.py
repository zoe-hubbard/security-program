import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort, current_app
from sqlalchemy import text
from app import db
from app.models import User
from app.utils import sanitize_html
from app.loginform import LoginForm, RegisterForm

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':

        if form.validate_on_submit():
            raw_username = form.username.data  # gets raw username
            username = sanitize_html(raw_username)  # sanitizes using utils.py
            raw_password = form.password.data  # gets raw password
            password = sanitize_html(raw_password)  # sanitises using utils.py
            user = User.query.filter_by(username=username).first()  # filters details by given username
            client_ip = request.remote_addr or "Unknown IP"  # gets client ip


            row = db.session.execute(text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")).mappings().first()
            if row:
                user = db.session.get(User, row['id'])  # creates a User object
                session['user'] = user.username
                session['role'] = user.role
                session['bio'] = user.bio
                current_app.logger.info("user logged in", extra={'ip': client_ip})
                return redirect(url_for('main.dashboard'))
        else:
            flash('Login credentials are invalid, please try again')
            client_ip = request.remote_addr or "Unknown IP"  # gets client ip
            current_app.logger.warning("invalid login credentials", extra={'ip': client_ip})

    elif request.method == 'POST':
        client_ip = request.remote_addr or "Unknown IP"  # gets ip
        if form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{getattr(form, field).label.text}: {error}", 'danger')  # flashes erros
                    current_app.logger.warning(  # logs errors
                        f"Validation failed | field='{field}' | "
                        f"error='{error}' | ip={client_ip} | user='{form.username.data}'"
                        # logs errors w appropriate fields
                    )
    return render_template('login.html', form=form,)

@main.route('/dashboard')
def dashboard():
    if 'user' in session:
        username = session['user']
        bio = session['bio']
        return render_template('dashboard.html', username=username, bio=bio)
    return redirect(url_for('main.login'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        form = RegisterForm()
        if form.validate_on_submit():
            raw_username = form.username.data  # gets raw username
            username = sanitize_html(raw_username)  # sanitizes using utils.py
            raw_password = form.password.data  # gets raw password
            password = sanitize_html(raw_password)  # sanitises using utils.py
            raw_bio = form.bio.data
            bio = sanitize_html(raw_bio)
            client_ip = request.remote_addr or "Unknown IP"  # gets client ip
            role = request.form.get('role', 'user')
            db.session.execute(text(f"INSERT INTO user (username, password, role, bio) VALUES ('{username}', '{password}', '{role}', '{bio}')"))
            db.session.commit()
            current_app.logger.info("account registered", extra={'ip': client_ip})
            return redirect(url_for('main.login'))
    return render_template('register.html')

@main.route('/admin-panel')
def admin():
    if session.get('role') != 'admin':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('admin.html')

@main.route('/moderator')
def moderator():
    if session.get('role') != 'moderator':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('moderator.html')

@main.route('/user-dashboard')
def user_dashboard():
    if session.get('role') != 'user':
        stack = ''.join(traceback.format_stack(limit=25))
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")
    return render_template('user_dashboard.html', username=session.get('user'))


@main.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Require basic "login" state
    if 'user' not in session:
        client_ip = request.remote_addr or "Unknown IP"
        stack = ''.join(traceback.format_stack(limit=25))
        current_app.logger.warning("user not in session access denied", extra={'ip': client_ip})
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")


    username = session['user']

    if request.method == 'POST':

        raw_current_password = request.form.get('current_password', '')
        current_password = sanitize_html(raw_current_password)
        raw_new_password = request.form.get('new_password', '')
        new_password = sanitize_html(raw_new_password)

        user = db.session.execute(
            text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{current_password}' LIMIT 1")
        ).mappings().first()

        client_ip = request.remote_addr or "Unknown IP"

        # Enforce: current password must be valid for user
        if not user:
            flash('Current password is incorrect', 'error')
            current_app.logger.error("Incorrect password - attempting to change password", extra={'ip': client_ip})
            return render_template('change_password.html')

        # Enforce: new password must be different from current password
        if new_password == current_password:
            flash('New password must be different from the current password', 'error')
            current_app.logger.error("New password same as current password", extra={'ip': client_ip})
            return render_template('change_password.html')

        db.session.execute(
            text(f"UPDATE user SET password = '{new_password}' WHERE username = '{username}'")
        )
        db.session.commit()

        flash('Password changed successfully', 'success')
        current_app.logger.info("Password succesfully changed", extra={'ip': client_ip})
        return redirect(url_for('main.dashboard'))

    return render_template('change_password.html')

