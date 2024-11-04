from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, current_user, login_required
from models import User, Company, Property
from database import db
import os
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/account')
@login_required
def account():
    # Get all available companies and the ones user is a member of
    all_companies = Company.query.all()
    return render_template('account.html', companies=all_companies)

@app.route('/update_company_membership', methods=['POST'])
@login_required
def update_company_membership():
    try:
        company_id = request.form.get('company_id')
        action = request.form.get('action')  # 'join' or 'leave'
        
        if not company_id or not action:
            flash('Invalid request')
            return redirect(url_for('account'))
        
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
    except Exception as e:
        logger.error(f"Error updating company membership: {str(e)}")
        flash('An error occurred while updating company membership')
        
    return redirect(url_for('account'))

@app.route('/create_company', methods=['POST'])
@login_required
def create_company():
    if current_user.role != 'admin':
        flash('Only administrators can create companies')
        return redirect(url_for('account'))
        
    try:
        name = request.form.get('name')
        description = request.form.get('description')
        
        if not name or not description:
            flash('Company name and description are required')
            return redirect(url_for('account'))
            
        company = Company(
            name=name,
            description=description,
            owner_id=current_user.id
        )
        
        db.session.add(company)
        db.session.commit()
        
        flash(f'Successfully created company: {name}')
    except Exception as e:
        logger.error(f"Error creating company: {str(e)}")
        flash('An error occurred while creating the company')
        
    return redirect(url_for('account'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
