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
    # Generate a unique filename
    random_hex = uuid.uuid4().hex
    _, f_ext = os.path.splitext(file.filename)
    picture_filename = random_hex + f_ext
    picture_path = os.path.join(app.config['UPLOAD_FOLDER'], picture_filename)
    
    # Resize and save the image
    output_size = (400, 400)
    i = Image.open(file)
    i.thumbnail(output_size)
    i.save(picture_path)
    
    return os.path.join('uploads', picture_filename)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists')
            return redirect(url_for('signup'))
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered')
            return redirect(url_for('signup'))
        
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('account'))
        
        flash('Invalid email or password')
    
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
            flash('Profile picture updated successfully')
        except Exception as e:
            flash('Error uploading profile picture')
    else:
        flash('Invalid file type. Please upload a valid image file (PNG, JPG, JPEG, GIF)')
    
    return redirect(url_for('account'))

@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('reset_request.html')

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()  # This line will be removed after successful table creation
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
