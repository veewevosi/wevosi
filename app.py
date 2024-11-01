import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from database import db
from models import User
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "a secret key"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_reset_email(user, token):
    sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
    reset_url = url_for('reset_token', token=token, _external=True)
    
    message = Mail(
        from_email='noreply@yourdomain.com',
        to_emails=user.email,
        subject='Password Reset Request',
        html_content=f'''To reset your password, visit the following link:
        <a href="{reset_url}">Reset Password</a>
        
        If you did not make this request, please ignore this email.
        ''')
    
    try:
        sg.send(message)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
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
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('account'))
    return render_template('signup.html')

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
                flash('An email has been sent with instructions to reset your password.')
            else:
                flash('An error occurred. Please try again later.')
        else:
            flash('No account found with that email address.')
        return redirect(url_for('login'))
    
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    
    user = User.verify_reset_token(token)
    if user is None:
        flash('Invalid or expired reset token')
        return redirect(url_for('reset_request'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('reset_token', token=token))
        
        user.password_hash = generate_password_hash(password)
        db.session.commit()
        flash('Your password has been updated!')
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
        db.drop_all()  # Drop all tables to recreate them with new columns
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
