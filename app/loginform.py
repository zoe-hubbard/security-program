from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length, Regexp, ValidationError, Email
from wtforms import StringField, PasswordField, SubmitField
from flask import request, current_app

RESERVED_PASSWORDS = ['password123$', 'Adminadmin1@', 'weLcome123!', 'qwerty123$']
SPECIAL_CHARACTERS = "!@#$%^&*()_+{}[]:;<>,.?/~-"


class LoginForm(FlaskForm): # creates form for login
    username = StringField('Username', validators=[ # username
        DataRequired(message='Username is required'),
        Email(), # requires to be email
    ])
    password = PasswordField("Password", validators=[ # psswd
        DataRequired(message='password is required') # requires data
                             ])
    submit = SubmitField("Login")

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[  # username
        DataRequired(message='Username is required'),
        Email(),  # requires to be email
    ])
    password = PasswordField("Password", validators=[  # psswd
        DataRequired(message='password is required')  # requires data
    ])
    bio = PasswordField("Bio", validators=[  # psswd
        DataRequired(message='Bio is required')  # requires data
    ])
    submit = SubmitField("Register")

    def validate_password(self, field): # validates password
        value = (field.data or "").strip()
        errors = [] # starts errors list
        client_ip = request.remote_addr or "unknown IP" # ip for logging

        if len(value) < 10: # checks min length
            errors.append("Password must be at least 10 characters long.")
        value = field.data.strip() # strips
        username = getattr(self, "name", None) # gets username
        email = getattr(self, "email", None) # gets email
        # Disallow reserved passwords
        if value.lower() in RESERVED_PASSWORDS:
            errors.append("This password is too easy to guess.")

        if not any(c.isupper() for c in value): #checks in capital letter
            errors.append("This password must contain at least one capital letter.")
        if not any(c.islower() for c in value): # checks if lowercase letter
            errors.append("This password must contain at least one lowercase letter.")
        if not any(c.isdigit() for c in value): # checks if number
            errors.append("This password must contain at least one digit.")
        if any (c.isspace() for c in value): # checks for spaces - not allowed
            errors.append("This password cannot contain spaces.")
        if not any(c in SPECIAL_CHARACTERS for c in value): # checks if special char present
            errors.append(f"Password must include at least one special character")
        if username and username.data.lower() in value.lower(): # checks if contains username
            errors.append("password cannot contain username")
        if email and email.data.lower() in value.lower(): # checks if contains email
            errors.append("password cannot contain email")

        if errors:
            joined_errs = ("\n".join(errors)) # join errors
            current_app.logger.warning(
                f"Validation failure | client_ip={client_ip}, errors = {joined_errs}" #logs errrors w ip
            )
            raise ValidationError(joined_errs) #raises errors