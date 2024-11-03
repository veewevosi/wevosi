from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import db
from models import User
from email_utils import send_verification_email, send_password_reset_email
import os
from PIL import Image
from datetime import datetime, timedelta
import uuid
from sqlalchemy.exc import SQLAlchemyError, OperationalError
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

with app.app_context():
    try:
        db.connect_with_retry(app)
        logger.info("Database connection established")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

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
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/properties')
@login_required
def properties():
    return render_template('properties.html')

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
            
            token = new_user.get_verification_token()
            verification_url = url_for('verify_email', token=token, _external=True)
            
            if send_verification_email(email, verification_url):
                logger.info(f"Successfully created new user and sent verification email to: {email}")
                flash('Account created successfully! Please check your email to verify your account.')
            else:
                logger.error(f"Failed to send verification email to: {email}")
                flash('Account created, but failed to send verification email. Please request a new verification email.')
            
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
                    return redirect(url_for('dashboard'))
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

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    try:
        username = request.form['username']
        email = request.form['email']
        
        user_check = User.query.filter(User.username == username, User.id != current_user.id).first()
        if user_check:
            flash('Username already taken')
            return redirect(url_for('settings'))
        
        email_check = User.query.filter(User.email == email, User.id != current_user.id).first()
        if email_check:
            flash('Email already registered')
            return redirect(url_for('settings'))
        
        current_user.username = username
        current_user.email = email
        db.session.commit()
        
        flash('Profile updated successfully')
        return redirect(url_for('settings'))
    except Exception as e:
        logger.error(f"Error updating profile: {str(e)}")
        flash('An error occurred while updating your profile')
        return redirect(url_for('settings'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    try:
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect')
            return redirect(url_for('settings'))
        
        if new_password != confirm_password:
            flash('New passwords do not match')
            return redirect(url_for('settings'))
        
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Password updated successfully')
        return redirect(url_for('settings'))
    except Exception as e:
        logger.error(f"Error changing password: {str(e)}")
        flash('An error occurred while changing your password')
        return redirect(url_for('settings'))

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
            if current_user.profile_picture:
                old_picture_path = os.path.join(app.root_path, 'static', current_user.profile_picture)
                if os.path.exists(old_picture_path):
                    os.remove(old_picture_path)
            
            picture_path = save_picture(file)
            current_user.profile_picture = picture_path
            db.session.commit()
            logger.info(f"Successfully updated profile picture for user: {current_user.username}")
            flash('Profile picture updated successfully')
        except OperationalError as e:
            logger.error(f"Database connection error during profile picture upload: {str(e)}")
            flash('Database connection error. Please try again later.')
        except SQLAlchemyError as e:
            logger.error(f"Database error in profile picture upload: {str(e)}")
            flash('Error updating profile picture. Please try again.')
        except Exception as e:
            logger.error(f"Error in profile picture upload: {str(e)}")
            flash('Error uploading profile picture')
    else:
        flash('Invalid file type. Please upload a valid image file (PNG, JPG, JPEG, GIF)')
    
    return redirect(url_for('account'))

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            email = request.form['email']
            user = User.query.filter_by(email=email).first()
            
            if user:
                token = user.get_reset_token()
                reset_url = url_for('reset_password', token=token, _external=True)
                
                if send_password_reset_email(email, reset_url):
                    logger.info(f"Password reset email sent to: {user.email}")
                    flash('Password reset instructions have been sent to your email.')
                else:
                    logger.error(f"Failed to send password reset email to: {email}")
                    flash('Failed to send reset email. Please try again later.')
            else:
                logger.debug(f"Password reset requested for non-existent email: {email}")
                flash('If an account exists with that email, you will receive reset instructions.')
            
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error in reset_request: {str(e)}")
            flash('An error occurred. Please try again later.')
    
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    user = User.verify_reset_token(token)
    if user is None:
        flash('Invalid or expired reset token')
        return redirect(url_for('reset_request'))
    
    if request.method == 'POST':
        try:
            password = request.form['password']
            user.password_hash = generate_password_hash(password)
            db.session.commit()
            logger.info(f"Password reset successful for user: {user.email}")
            flash('Your password has been updated! You can now log in.')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error in reset_password: {str(e)}")
            flash('An error occurred. Please try again.')
    
    return render_template('reset_password.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        user = User.verify_email_token(token)
        if user is None:
            flash('Invalid or expired verification link.')
            return render_template('verify_email.html', verified=False)
        
        if not user.email_verified:
            user.email_verified = True
            db.session.commit()
            logger.info(f"Email verified for user: {user.email}")
        
        return render_template('verify_email.html', verified=True)
    except Exception as e:
        logger.error(f"Error in verify_email: {str(e)}")
        return render_template('verify_email.html', verified=False, error_message='An error occurred during verification.')

@app.route('/resend_verification', methods=['GET', 'POST'])
def resend_verification():
    if current_user.is_authenticated and current_user.email_verified:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            email = request.form['email']
            user = User.query.filter_by(email=email).first()
            
            if user and not user.email_verified:
                token = user.get_verification_token()
                verification_url = url_for('verify_email', token=token, _external=True)
                
                if send_verification_email(email, verification_url):
                    logger.info(f"Verification email resent to: {user.email}")
                    flash('A new verification email has been sent.')
                else:
                    logger.error(f"Failed to send verification email to: {email}")
                    flash('Failed to send verification email. Please try again later.')
            else:
                logger.debug(f"Verification resend requested for invalid email: {email}")
                flash('If an account exists with that email, you will receive a verification link.')
            
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error in resend_verification: {str(e)}")
            flash('An error occurred. Please try again later.')
    
    return render_template('resend_verification.html')

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
            
            inspector = db.inspect(db.engine)
            for table_name in inspector.get_table_names():
                logger.info(f"Table: {table_name}")
                for column in inspector.get_columns(table_name):
                    logger.info(f"  Column: {column['name']} ({column['type']})")
        except Exception as e:
            logger.error(f"Error creating database tables: {str(e)}")
    
    app.run(host='0.0.0.0', port=5000)