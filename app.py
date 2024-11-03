import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from database import db
from models import User
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from python_http_client.exceptions import HTTPError as SendGridException

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "a secret key"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
VERIFIED_SENDER_EMAIL = os.environ.get('SENDGRID_VERIFIED_SENDER', 'noreply@yourdomain.com')
DEBUG_EMAIL = os.environ.get('DEBUG_EMAIL', False)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_verification_email(user, token):
    if not SENDGRID_API_KEY:
        logger.error("SendGrid API key is not configured")
        if DEBUG_EMAIL:
            logger.info(f"DEBUG MODE: Verification URL would be: {url_for('verify_email', token=token, _external=True)}")
            flash('Debug mode: Check logs for verification URL', 'info')
            return True
        flash('Email service is not properly configured. Please contact support.', 'error')
        return False
    
    if not VERIFIED_SENDER_EMAIL or VERIFIED_SENDER_EMAIL == 'noreply@yourdomain.com':
        logger.error("SendGrid verified sender email is not configured")
        flash('Email sender is not properly configured. Please contact support.', 'error')
        return False
    
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        verification_url = url_for('verify_email', token=token, _external=True)
        
        message = Mail(
            from_email=VERIFIED_SENDER_EMAIL,
            to_emails=user.email,
            subject='Verify Your Email Address',
            html_content=f'''Please verify your email address by clicking the link below:
            <a href="{verification_url}">Verify Email</a>
            
            If you did not create this account, please ignore this email.
            
            This link will expire in 24 hours.
            ''')
        
        response = sg.send(message)
        logger.info(f"Verification email sent successfully to {user.email}. Status code: {response.status_code}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending verification email: {str(e)}")
        flash('Failed to send verification email. Please try again later.', 'error')
        return False

def send_reset_email(user, token):
    if not SENDGRID_API_KEY:
        logger.error("SendGrid API key is not configured")
        if DEBUG_EMAIL:
            logger.info(f"DEBUG MODE: Reset URL would be: {url_for('reset_token', token=token, _external=True)}")
            flash('Debug mode: Check logs for reset URL', 'info')
            return True
        flash('Email service is not properly configured. Please contact support.', 'error')
        return False
    
    if not VERIFIED_SENDER_EMAIL or VERIFIED_SENDER_EMAIL == 'noreply@yourdomain.com':
        logger.error("SendGrid verified sender email is not configured")
        flash('Email sender is not properly configured. Please contact support.', 'error')
        return False
    
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        reset_url = url_for('reset_token', token=token, _external=True)
        
        message = Mail(
            from_email=VERIFIED_SENDER_EMAIL,
            to_emails=user.email,
            subject='Password Reset Request',
            html_content=f'''To reset your password, visit the following link:
            <a href="{reset_url}">Reset Password</a>
            
            If you did not make this request, please ignore this email.
            
            This link will expire in 1 hour.
            ''')
        
        response = sg.send(message)
        logger.info(f"Reset email sent successfully to {user.email}. Status code: {response.status_code}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending reset email: {str(e)}")
        flash('Failed to send reset email. Please try again later.', 'error')
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/debug/users')
def debug_users():
    users = User.query.all()
    user_list = [{'id': user.id, 'username': user.username, 'email': user.email} for user in users]
    return str(user_list)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            if not user.email_verified:
                flash('Please verify your email address before logging in.', 'error')
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('account'))
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('signup'))
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            email_verified=False
        )
        db.session.add(user)
        db.session.commit()
        
        token = user.get_verification_token()
        if send_verification_email(user, token):
            flash('A verification email has been sent to your email address.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    user = User.verify_email_token(token)
    if user is None:
        return render_template('verify_email.html', verified=False)
    
    if user.email_verified:
        return render_template('verify_email.html', verified=True, 
                             error_message='Email already verified.')
    
    user.email_verified = True
    user.email_verification_token = None
    db.session.commit()
    flash('Your email has been verified! You can now login.', 'success')
    return render_template('verify_email.html', verified=True)

@app.route('/resend_verification', methods=['GET', 'POST'])
def resend_verification():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user and not user.email_verified:
            token = user.get_verification_token()
            if send_verification_email(user, token):
                flash('A new verification email has been sent.', 'success')
            return redirect(url_for('login'))
        flash('Invalid email or account already verified.')
        return redirect(url_for('login'))
    
    return render_template('resend_verification.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = user.get_reset_token()
            if send_reset_email(user, token):
                flash('An email has been sent with instructions to reset your password.', 'success')
                logger.info(f"Password reset requested for user: {email}")
            else:
                logger.error(f"Failed to send reset email to: {email}")
        else:
            logger.info(f"Password reset attempted for non-existent email: {email}")
            flash('If an account exists with that email address, you will receive password reset instructions.', 'info')
        return redirect(url_for('login'))
    
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    
    user = User.verify_reset_token(token)
    if user is None:
        flash('Invalid or expired reset token', 'error')
        logger.warning(f"Invalid reset token attempt: {token[:10]}...")
        return redirect(url_for('reset_request'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('reset_token', token=token))
        
        user.password_hash = generate_password_hash(password)
        db.session.commit()
        logger.info(f"Password successfully reset for user: {user.email}")
        flash('Your password has been updated! You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/account')
@login_required
def account():
    return render_template('account.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)