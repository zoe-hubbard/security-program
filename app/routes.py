import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort, current_app
from flask_login import login_user, fresh_login_required, logout_user, login_required
from app import db
from app.models import User
from app.utils import sanitize_html
from app.loginform import LoginForm, RegisterForm, CheckPassword
from app import loginform
from flask_bcrypt import bcrypt, Bcrypt, check_password_hash, generate_password_hash
from flask_login import fresh_login_required, current_user
from app.utils import requires_roles, encrypt_text, decrypt_text

main = Blueprint('main', __name__)


@main.route('/admin')
@login_required
@requires_roles('admin')
def admin_dashboard():
    return render_template('admin/dashboard.html')

@main.route('/moderator')
@login_required
@requires_roles('moderator')
def moderator_dashboard():
    return render_template('moderator/dashboard.html')

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()


    if form.validate_on_submit():
        raw_username = form.username.data  # gets raw username
        username = sanitize_html(raw_username)  # sanitizes using utils.py
        password = form.password.data  # gets raw password
        user = User.query.filter_by(username=username).first()  # filters details by given username
        client_ip = request.remote_addr or "Unknown IP"  # gets client ip

        if user and check_password_hash(user.password_hash, password):
            session.clear()
            login_user(user, remember=False, fresh=True)
            current_app.logger.info("user logged in", extra={'ip': client_ip})
            return redirect(url_for('main.dashboard'))


        flash('Login credentials are invalid, please try again', 'danger')
        current_app.logger.warning("invalid login credentials", extra={'ip': client_ip})


    elif form.errors:
        client_ip = request.remote_addr or "Unknown IP"
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
        bio = decrypt_text(session['bio'])
        return render_template('dashboard.html', username=username, bio=bio)
    return redirect(url_for('main.login'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            raw_username = form.username.data  # gets raw username
            username = sanitize_html(raw_username)# sanitizes using utils.py

            password = form.password.data  # gets raw password
            hashed_pw = generate_password_hash(password)

            raw_bio = form.bio.data
            bio = encrypt_text((raw_bio))

            client_ip = request.remote_addr or "Unknown IP"  # gets client ip
            role = 'user'
            user = User(username=username, password=password, role=role, bio=bio)

            try:
                db.session.add(user)
                db.session.commit()
                current_app.logger.info("Account registered", extra={'ip': client_ip})
                return redirect(url_for('main.login'))
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Error registering account: {str(e)}", extra={'ip': client_ip})
                form.username.errors.append("Registration failed, try a different username.")

    return render_template('register.html', form=form)

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
@fresh_login_required
def change_password():
    # Require basic "login" state
    form = CheckPassword()

    if not current_user.is_authenticated:
        client_ip = request.remote_addr or "Unknown IP"
        stack = ''.join(traceback.format_stack(limit=25))
        current_app.logger.warning("user not authenticated access denied", extra={'ip': client_ip})
        abort(403, description=f"Access denied.\n\n--- STACK (demo) ---\n{stack}")

    if form.validate_on_submit():
        if not check_password_hash(current_user.password_hash, form.current_password.data):
            flash("Current password incorrect", "danger")
            return redirect(url_for('main.change_password'))
        current_user.password_hash = generate_password_hash(form.new_password.data).decode()
        db.session.commit()

        logout_user()  # force re-login to create a fresh session
        session.clear()
        flash("Password changed. Please log in again.", "success")
        return redirect(url_for('auth.login'))

    return render_template('change_password.html', form=form)

