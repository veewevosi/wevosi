from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import db
from models import User
import os
from PIL import Image
from datetime import datetime, timedelta
import uuid
from sqlalchemy.exc import SQLAlchemyError, OperationalError
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_picture(file):
    random_hex = uuid.uuid4().hex
    _, f_ext = os.path.splitext(file.filename)
    picture_filename = random_hex + f_ext
    picture_path = os.path.join(app.config['UPLOAD_FOLDER'], picture_filename)
    
    output_size = (400, 400)
    i = Image.open(file)
    i.thumbnail(output_size)
    i.save(picture_path)
    
    return os.path.join('uploads', picture_filename)

@login_manager.user_loader
def load_user(user_id):
    try:
        user = User.query.get(int(user_id))
        logger.debug(f"Loading user with ID {user_id}: {'Found' if user else 'Not found'}")
        return user
    except SQLAlchemyError as e:
        logger.error(f"Database error loading user {user_id}: {str(e)}")
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        try:
            logger.debug(f"Attempting to create new user with email: {email}")
            
            user = User.query.filter_by(username=username).first()
            if user:
                logger.debug(f"Username {username} already exists")
                flash('Username already exists')
                return redirect(url_for('signup'))
            
            user = User.query.filter_by(email=email).first()
            if user:
                logger.debug(f"Email {email} already registered")
                flash('Email already registered')
                return redirect(url_for('signup'))
            
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password)
            )
            
            db.session.add(new_user)
            db.session.commit()
            logger.info(f"Successfully created new user with email: {email}")
            
            flash('Account created successfully')
            return redirect(url_for('login'))
        except OperationalError as e:
            logger.error(f"Database connection error during signup: {str(e)}")
            flash('Database connection error. Please try again later.')
            return redirect(url_for('signup'))
        except SQLAlchemyError as e:
            logger.error(f"Database error in signup: {str(e)}")
            flash('An error occurred while creating your account. Please try again.')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            logger.debug(f"Attempting login for email: {email}")
            user = User.query.filter_by(email=email).first()
            
            if user:
                logger.debug(f"User found: {user.username}")
                if check_password_hash(user.password_hash, password):
                    login_user(user)
                    logger.info(f"Successful login for user: {user.username}")
                    return redirect(url_for('account'))
                else:
                    logger.debug("Invalid password provided")
            else:
                logger.debug("No user found with provided email")
            
            flash('Invalid email or password')
        except OperationalError as e:
            logger.error(f"Database connection error during login: {str(e)}")
            flash('Database connection error. Please try again later.')
        except SQLAlchemyError as e:
            logger.error(f"Database error in login: {str(e)}")
            flash('An error occurred. Please try again later.')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/account')
@login_required
def account():
    return render_template('account.html')

@app.route('/upload_profile_picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        flash('No file selected')
        return redirect(url_for('account'))
    
    file = request.files['profile_picture']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('account'))
    
    if file and allowed_file(file.filename):
        try:
            # Delete old profile picture if it exists
            if current_user.profile_picture:
                old_picture_path = os.path.join(app.root_path, 'static', current_user.profile_picture)
                if os.path.exists(old_picture_path):
                    os.remove(old_picture_path)
            
            # Save new profile picture
            picture_path = save_picture(file)
            current_user.profile_picture = picture_path
            db.session.commit()
            logger.info(f"Successfully updated profile picture for user: {current_user.username}")
            flash('Profile picture updated successfully')
        except OperationalError as e:
            logger.error(f"Database connection error during profile picture upload: {str(e)}")
            flash('Database connection error. Please try again later.')
            return redirect(url_for('account'))
        except SQLAlchemyError as e:
            logger.error(f"Database error in profile picture upload: {str(e)}")
            flash('Error updating profile picture. Please try again.')
            return redirect(url_for('account'))
        except Exception as e:
            logger.error(f"Error in profile picture upload: {str(e)}")
            flash('Error uploading profile picture')
    else:
        flash('Invalid file type. Please upload a valid image file (PNG, JPG, JPEG, GIF)')
    
    return redirect(url_for('account'))

@app.route('/debug/users')
def debug_users():
    try:
        users = User.query.all()
        logger.info(f"Found {len(users)} users in database")
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'email_verified': user.email_verified,
                'has_profile_picture': bool(user.profile_picture)
            })
        return {'users': user_list}
    except SQLAlchemyError as e:
        logger.error(f"Database error in debug_users: {str(e)}")
        return {'error': 'Database error'}, 500

if __name__ == '__main__':
    with app.app_context():
        try:
            logger.info("Attempting to create database tables...")
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Verify table structure
            inspector = db.inspect(db.engine)
            for table_name in inspector.get_table_names():
                logger.info(f"Table: {table_name}")
                for column in inspector.get_columns(table_name):
                    logger.info(f"  Column: {column['name']} ({column['type']})")
        except Exception as e:
            logger.error(f"Error creating database tables: {str(e)}")
            
    app.run(host='0.0.0.0', port=5000)
