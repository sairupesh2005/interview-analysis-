from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Using SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Signup Route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    phone_number = data.get('phone_number')
    password = data.get('password')

    if not all([name, email, phone_number, password]):
        return jsonify({"error": "All fields are required."}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "Email already registered."}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=name, email=email, phone_number=phone_number, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully."}), 201

# Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({"error": "Email and password are required."}), 400

    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        return jsonify({"message": "Login successful.", "user": {"name": user.name, "email": user.email}}), 200

    return jsonify({"error": "Invalid credentials."}), 401

# Logout Route
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout successful."}), 200

# Run the app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
