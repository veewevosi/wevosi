from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from models import User, Company, Property
from database import db
from email_utils import send_password_reset_email
import os
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File Upload Configuration
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize database
db.init_app(app)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
            send_password_reset_email(user.email, reset_url)
            flash('Password reset instructions sent to your email')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email address')
    
    return render_template('reset_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    user = User.verify_reset_token(token)
    if not user:
        flash('Invalid or expired reset token')
        return redirect(url_for('reset_request'))
        
    if request.method == 'POST':
        password = request.form.get('password')
        user.password_hash = generate_password_hash(password)
        db.session.commit()
        flash('Password has been updated! You can now log in')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            
            if not email or not password:
                flash('Please provide both email and password')
                return render_template('login.html')
            
            user = User.query.filter_by(email=email).first()
            
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password')
                return render_template('login.html')
                
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login. Please try again.')
            return render_template('login.html')
    
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
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    users = User.query.all() if current_user.role == 'admin' else None
    return render_template('dashboard.html', users=users)

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/account')
@login_required
def account():
    companies = Company.query.all()
    return render_template('account.html', companies=companies)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        
        if username != current_user.username and User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('settings'))
            
        if email != current_user.email and User.query.filter_by(email=email).first():
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
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect')
        elif new_password != confirm_password:
            flash('New passwords do not match')
        else:
            current_user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash('Password changed successfully')
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
            # Secure the filename and save the file
            filename = secure_filename(file.filename)
            # Add timestamp or random string to filename to avoid conflicts
            filename = f"{os.urandom(16).hex()}.{filename.rsplit('.', 1)[1].lower()}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Save the file
            file.save(filepath)
            
            # Update user's profile picture path in database
            current_user.profile_picture = f"uploads/{filename}"
            db.session.commit()
            
            flash('Profile picture updated successfully')
        except Exception as e:
            logger.error(f"Error uploading profile picture: {str(e)}")
            flash('Error uploading profile picture')
    else:
        flash('Invalid file type. Please use PNG, JPG, JPEG, or GIF')
        
    return redirect(url_for('account'))

@app.route('/update_company_membership', methods=['POST'])
@login_required
def update_company_membership():
    company_id = request.form.get('company_id')
    action = request.form.get('action')
    
    company = Company.query.get(company_id)
    if not company:
        flash('Company not found')
        return redirect(url_for('account'))
        
    if action == 'join':
        if company not in current_user.member_of_companies:
            current_user.member_of_companies.append(company)
            flash(f'Successfully joined {company.name}')
    elif action == 'leave':
        if company in current_user.member_of_companies:
            current_user.member_of_companies.remove(company)
            flash(f'Successfully left {company.name}')
            
    db.session.commit()
    return redirect(url_for('account'))

@app.route('/create_company', methods=['POST'])
@login_required
def create_company():
    if current_user.role != 'admin':
        flash('Permission denied')
        return redirect(url_for('account'))
        
    name = request.form.get('name')
    description = request.form.get('description')
    
    if Company.query.filter_by(name=name).first():
        flash('Company name already exists')
        return redirect(url_for('account'))
        
    company = Company(
        name=name,
        description=description,
        owner_id=current_user.id
    )
    db.session.add(company)
    db.session.commit()
    flash('Company created successfully')
    return redirect(url_for('account'))

@app.route('/properties')
@login_required
def properties():
    properties = Property.query.filter_by(user_id=current_user.id).all()
    return render_template('properties.html', properties=properties)

@app.route('/add_property', methods=['POST'])
@login_required
def add_property():
    try:
        property_name = request.form.get('property_name')
        street_address = request.form.get('street_address')
        city = request.form.get('city')
        state = request.form.get('state')
        zipcode = request.form.get('zipcode')
        longitude = float(request.form.get('longitude'))
        latitude = float(request.form.get('latitude'))
        acres = float(request.form.get('acres'))
        square_feet = float(request.form.get('square_feet'))
        property_type = request.form.get('type')

        new_property = Property(
            property_name=property_name,
            street_address=street_address,
            city=city,
            state=state,
            zipcode=zipcode,
            longitude=longitude,
            latitude=latitude,
            acres=acres,
            square_feet=square_feet,
            type=property_type,
            user_id=current_user.id
        )
        
        db.session.add(new_property)
        db.session.commit()
        flash('Property added successfully')
        
    except Exception as e:
        flash('Error adding property')
        logger.error(f"Error adding property: {str(e)}")
        
    return redirect(url_for('properties'))

@app.route('/all_properties')
@login_required
def all_properties():
    properties = Property.query.all()
    properties_json = [{
        'name': p.property_name,
        'address': f"{p.street_address}, {p.city}, {p.state}",
        'type': p.type,
        'acres': p.acres,
        'latitude': p.latitude,
        'longitude': p.longitude
    } for p in properties]
    
    return render_template('all_properties.html', 
                         properties=properties,
                         properties_json=properties_json,
                         here_api_key=os.environ.get('HERE_API_KEY'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
