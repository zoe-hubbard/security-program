from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)
    bio = db.Column(db.String(500), nullable=False)

    def set_password(self, plaintext):
        from app import bcrypt
        self.password_hash = bcrypt.generate_password_hash(plaintext).decode('utf-8')

    def check_password(self, plaintext):
        from app import bcrypt
        return bcrypt.check_password_hash(self.password_hash, plaintext)

    def __init__(self, username, password, role, bio):
        self.username = username
        self.password = password
        self.role = role
        self.bio = bio



