import bleach
from functools import wraps
from flask_login import current_user
from flask import abort
from cryptography.fernet import Fernet
from flask import current_app

ALLOWED_TAGS = [ # allowed html tags specified
    'b', 'i', 'u', 'em', 'strong',
    'a', 'p', 'ul', 'ol', 'li', 'br'
]
 # sanitises input from username and password
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title']
}

ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']

def sanitize_html(text): # callable on raw data
    return bleach.clean( # bleaches
        text,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True
    )

def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return wrapper

def get_fernet():
    key = current_app.config.get('FERNET_KEY')
    if not key:
        raise RuntimeError('FERNET_KEY not set')
    return Fernet(key.encode())

def encrypt_text(plaintext):
    return get_fernet().encrypt(plaintext.encode()).decode()

def decrypt_text(token):
    return get_fernet().decrypt(token.encode()).decode()