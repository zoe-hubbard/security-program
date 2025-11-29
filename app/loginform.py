from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length, Regexp, ValidationError, Email
from wtforms import StringField, PasswordField, SubmitField
from flask import request, current_app
import re

RESERVED_PASSWORDS = [p.lower() for p in ['password123$', 'Adminadmin1@', 'weLcome123!', 'qwerty123$']]
SPECIAL_CHARACTERS = "!@#$%^&*()_+{}[]:;<>,.?/~-"

def password_validator(form, field): # validates password
    value = (field.data or "").strip()
    errors = [] # starts errors list
    client_ip = request.remote_addr or "unknown IP" # ip for logging

    if len(value) < 10: # checks min length
        errors.append("Password must be at least 10 characters long.")
    value = field.data.strip() # strips
    username = getattr(form, "username", None) # gets username

    if value.lower() in RESERVED_PASSWORDS:
        errors.append("This password is too easy to guess.")

    if not any(c.isupper() for c in value): #checks in capital letter
        errors.append("This password must contain at least one capital letter.")
    if not any(c.islower() for c in value): # checks if lowercase letter
        errors.append("This password must contain at least one lowercase letter.")
    if not any(c.isdigit() for c in value): # checks if number
        errors.append("This password must contain at least one digit.")
    if not any(c in SPECIAL_CHARACTERS for c in value): # checks if special char present
        errors.append(f"Password must include at least one special character")
    if username and username.data.lower() in value.lower(): # checks if contains username
        errors.append("password cannot contain username")
        #avoid repeated chars
    if re.search(r'(.)\1\1', value.lower()):
        errors.append("Invalid: contains 3+ repeated chars")

    if errors:
        joined_errs = ("\n".join(errors)) # join errors
        current_app.logger.warning(
            f"Validation failure | client_ip={client_ip}, errors = {joined_errs}" #logs errrors w ip
        )
        raise ValidationError(joined_errs) #raises errors

    else:
        return True


class LoginForm(FlaskForm): # creates form for login
    username = StringField('Username', validators=[ # username
        DataRequired(message='Username is required'),
        Email(), Length(max=254)# requires to be email
    ])
    password = PasswordField("Password", validators=[ # psswd
        DataRequired(message='password is required'),
        Length(min=10, max=128)
                             ])
    submit = SubmitField("Login")

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[  # username
        DataRequired(message='Username is required'),
        Email(message='must be a valid email address'),
        Length(max=254)# requires to be email
    ])
    password = PasswordField("Password", validators=[  # psswd
        DataRequired(message='password is required'),
        Length(min=10, max=128),
        password_validator# requires data
    ])
    bio = StringField("Bio", validators=[  # psswd
        DataRequired(message='Bio is required'), Length(max=500)  # requires data
    ])
    submit = SubmitField("Register")

class CheckPassword(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField("new password", validators=[  # psswd
        DataRequired(message='password is required'),
        password_validator ])
    submit = SubmitField("Submit")






