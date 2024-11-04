from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from models import User, Company, Property, Notification
from database import db
from email_utils import send_verification_email, send_password_reset_email
import os
import logging
from sqlalchemy import text
import qrcode
from io import BytesIO
import base64

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db.init_app(app)

# Create notification table
with app.app_context():
    try:
        db.session.execute(text('''
            CREATE TABLE IF NOT EXISTS notification (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES "user" (id),
                title VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        '''))
        db.session.commit()
        print("Notification table created successfully")
    except Exception as e:
        db.session.rollback()
        print(f"Error creating notification table: {e}")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_qr_code(url):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="white", back_color="#121212")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            if not user.email_verified:
                flash('Please verify your email before logging in')
                return redirect(url_for('login'))
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('dashboard'))
            
        flash('Invalid email or password')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('signup'))
            
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        
        try:
            db.session.add(user)
            db.session.flush()
            
            token = user.get_verification_token()
            verification_url = url_for('verify_email', token=token, _external=True)
            
            if send_verification_email(email, verification_url):
                db.session.commit()
                flash('Account created successfully. Please check your email to verify your account.')
                return redirect(url_for('login'))
            else:
                db.session.rollback()
                flash('Error sending verification email. Please try again.')
                return redirect(url_for('signup'))
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error in signup: {str(e)}")
            flash('An error occurred during signup. Please try again.')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = user.get_reset_token()
            reset_url = url_for('reset_password', token=token, _external=True)
            
            if send_password_reset_email(email, reset_url):
                flash('Password reset instructions have been sent to your email.')
                return redirect(url_for('login'))
            else:
                flash('Error sending password reset email. Please try again.')
                return redirect(url_for('reset_request'))
        else:
            flash('No account found with that email address.')
            return redirect(url_for('reset_request'))
            
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    user = User.verify_reset_token(token)
    if user is None:
        flash('Invalid or expired reset token')
        return redirect(url_for('reset_request'))
        
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('reset_password', token=token))
            
        user.password_hash = generate_password_hash(password)
        db.session.commit()
        flash('Your password has been updated! You can now log in.')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    users = User.query.all() if current_user.role == 'admin' else None
    return render_template('dashboard.html', users=users)

@app.route('/notifications')
@login_required
def notifications():
    user_notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc())\
        .all()
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/notifications/mark_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != current_user.id:
        abort(403)
    notification.read = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/notifications/mark_all_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(user_id=current_user.id).update({'read': True})
    db.session.commit()
    return jsonify({'success': True})

@app.route('/properties')
@login_required
def properties():
    user_properties = Property.query.filter_by(user_id=current_user.id).all()
    return render_template('properties.html', properties=user_properties)

@app.route('/all_properties')
@login_required
def all_properties():
    properties = Property.query.all()
    properties_json = [{
        'name': p.property_name,
        'address': f"{p.street_address}, {p.city}, {p.state} {p.zipcode}",
        'type': p.type,
        'acres': p.acres,
        'latitude': p.latitude,
        'longitude': p.longitude
    } for p in properties]
    return render_template('all_properties.html', 
                         properties=properties,
                         properties_json=properties_json,
                         here_api_key=os.environ.get('HERE_API_KEY'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    user_companies = Company.query.all()
    return render_template('account.html', companies=user_companies)

@app.route('/update_phone', methods=['POST'])
@login_required
def update_phone():
    phone_number = request.form.get('phone_number')
    current_user.phone_number = phone_number
    db.session.commit()
    flash('Phone number updated successfully')
    return redirect(url_for('account'))

@app.route('/update_company_membership', methods=['POST'])
@login_required
def update_company_membership():
    company_id = request.form.get('company_id')
    action = request.form.get('action')
    
    if not company_id:
        flash('No company selected')
        return redirect(url_for('account'))
        
    company = Company.query.get_or_404(company_id)
    
    if action == 'join':
        if company not in current_user.member_of_companies:
            current_user.member_of_companies.append(company)
            db.session.commit()
            flash(f'Successfully joined {company.name}')
    elif action == 'leave':
        if company in current_user.member_of_companies:
            current_user.member_of_companies.remove(company)
            db.session.commit()
            flash(f'Successfully left {company.name}')
            
    return redirect(url_for('account'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    return render_template('settings.html')

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    username = request.form.get('username')
    email = request.form.get('email')
    
    if User.query.filter_by(username=username).first() and username != current_user.username:
        flash('Username already exists')
        return redirect(url_for('settings'))
        
    if User.query.filter_by(email=email).first() and email != current_user.email:
        flash('Email already registered')
        return redirect(url_for('settings'))
    
    current_user.username = username
    current_user.email = email
    db.session.commit()
    flash('Profile updated successfully')
    return redirect(url_for('settings'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not check_password_hash(current_user.password_hash, current_password):
        flash('Current password is incorrect')
        return redirect(url_for('settings'))
        
    if new_password != confirm_password:
        flash('New passwords do not match')
        return redirect(url_for('settings'))
        
    current_user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    flash('Password changed successfully')
    return redirect(url_for('settings'))

@app.route('/user/<username>')
def public_profile(username):
    profile_user = User.query.filter_by(username=username).first_or_404()
    
    owned_companies = Company.query.filter_by(owner_id=profile_user.id).all()
    member_companies = profile_user.member_of_companies
    
    companies = list(set(owned_companies + list(member_companies)))
    
    # Generate QR code for the profile URL
    profile_url = url_for('public_profile', username=username, _external=True)
    qr_code = generate_qr_code(profile_url)
    
    return render_template('public_profile.html',
                         profile_user=profile_user,
                         companies=companies,
                         qr_code=qr_code)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
