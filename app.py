from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_mail import Mail, Message
import os
import locale
import re
import random
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///finance.db'

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'anuragyadav2641@gmail.com'  # Your Gmail address
app.config['MAIL_PASSWORD'] = 'swkfxxcojkvxtylt'  # Your Gmail App Password
app.config['MAIL_DEFAULT_SENDER'] = 'anuragyadav2641@gmail.com'  # Your Gmail address

# Configure session lifetime to 30 days
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Set locale to Indian English
try:
    locale.setlocale(locale.LC_ALL, 'en_IN')
except locale.Error:
    try:
        locale.setlocale(locale.LC_ALL, 'en_IN.UTF-8')
    except locale.Error:
        locale.setlocale(locale.LC_ALL, '')

def format_currency(amount):
    """Format amount in Indian Rupees"""
    try:
        return locale.currency(amount, grouping=True, symbol=True)
    except:
        # Fallback formatting if locale currency fails
        return f"₹{amount:,.2f}"

def validate_password(password):
    """
    Validate password meets the following criteria:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    - Contains at least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"

def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    """Send OTP to user's email"""
    msg = Message(
        'Verify Your Email - Finance Manager',
        recipients=[email]
    )
    msg.body = f'''Your verification code is: {otp}

This code will expire in 10 minutes.

If you didn't request this verification, please ignore this email.

Best regards,
Finance Manager Team'''
    mail.send(msg)

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    transactions = db.relationship('Transaction', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Transaction Model
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    category = db.Column(db.String(50))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    type = db.Column(db.String(10))  # 'income' or 'expense'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def calculate_totals(transactions):
    total_income = sum(t.amount for t in transactions if t.type == 'income')
    total_expense = sum(t.amount for t in transactions if t.type == 'expense')
    balance = total_income - total_expense
    return {
        'total_income': total_income,
        'total_expense': total_expense,
        'balance': balance
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        # Validate password
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('register'))

        # Generate OTP
        otp = generate_otp()
        
        # Store registration data and OTP in session
        session['pending_registration'] = {
            'username': username,
            'email': email,
            'password': password,
            'otp': otp,
            'timestamp': datetime.utcnow().timestamp()
        }

        # Send OTP email
        try:
            send_otp_email(email, otp)
            return redirect(url_for('verify_otp'))
        except Exception as e:
            flash('Error sending verification email. Please try again.', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'pending_registration' not in session:
        flash('Invalid verification session. Please register again.', 'error')
        return redirect(url_for('register'))

    if request.method == 'POST':
        user_otp = request.form.get('otp')
        stored_data = session['pending_registration']
        
        # Check if OTP is expired (10 minutes)
        if datetime.utcnow().timestamp() - stored_data['timestamp'] > 600:
            flash('Verification code has expired. Please register again.', 'error')
            session.pop('pending_registration', None)
            return redirect(url_for('register'))

        if user_otp == stored_data['otp']:
            # Create new user
            user = User(
                username=stored_data['username'],
                email=stored_data['email']
            )
            user.set_password(stored_data['password'])
            
            try:
                db.session.add(user)
                db.session.commit()
                session.pop('pending_registration', None)
                flash('Registration successful! Please login to continue.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('Error creating account. Please try again.', 'error')
                return redirect(url_for('register'))
        else:
            flash('Invalid verification code. Please try again.', 'error')
            return redirect(url_for('verify_otp'))

    return render_template('verify_otp.html')

@app.route('/resend_otp')
def resend_otp():
    if 'pending_registration' not in session:
        flash('Invalid verification session. Please register again.', 'error')
        return redirect(url_for('register'))

    stored_data = session['pending_registration']
    
    # Generate new OTP
    new_otp = generate_otp()
    stored_data['otp'] = new_otp
    stored_data['timestamp'] = datetime.utcnow().timestamp()
    session['pending_registration'] = stored_data

    try:
        send_otp_email(stored_data['email'], new_otp)
        flash('New verification code has been sent to your email.', 'success')
    except Exception as e:
        flash('Error sending verification email. Please try again.', 'error')

    return redirect(url_for('verify_otp'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', 'false') == 'true'
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('Username does not exist. Please register.', 'error')
            return redirect(url_for('login'))
        
        if not user.check_password(password):
            flash('The password is not valid for the username.', 'error')
            return redirect(url_for('login'))
        
        login_user(user, remember=remember)
        # Set session as permanent if remember me is checked
        if remember:
            session.permanent = True
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).all()
    totals = calculate_totals(transactions)
    return render_template('dashboard.html', transactions=transactions, totals=totals)

@app.route('/add_transaction', methods=['POST'])
@login_required
def add_transaction():
    try:
        amount = float(request.form.get('amount'))
        description = request.form.get('description')
        category = request.form.get('category')
        type = request.form.get('type')
        
        if not all([amount, description, category, type]):
            return jsonify({
                'success': False,
                'message': 'All fields are required'
            }), 400
        
        transaction = Transaction(
            amount=amount,
            description=description,
            category=category,
            type=type,
            user_id=current_user.id
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Transaction added successfully!',
            'transaction': {
                'id': transaction.id,
                'date': transaction.date.strftime('%Y-%m-%d %H:%M'),
                'description': transaction.description,
                'category': transaction.category,
                'amount': float(transaction.amount),
                'type': transaction.type
            }
        }), 200
    except ValueError:
        return jsonify({
            'success': False,
            'message': 'Invalid amount value'
        }), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': 'Error adding transaction. Please try again.'
        }), 500

@app.route('/edit_transaction/<int:transaction_id>', methods=['GET', 'POST'])
@login_required
def edit_transaction(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    
    # Ensure user owns this transaction
    if transaction.user_id != current_user.id:
        return jsonify({
            'success': False,
            'message': 'Unauthorized access'
        }), 403
    
    if request.method == 'GET':
        return jsonify({
            'success': True,
            'transaction': {
                'id': transaction.id,
                'amount': float(transaction.amount),
                'description': transaction.description,
                'category': transaction.category,
                'type': transaction.type
            }
        })
    
    if request.method == 'POST':
        try:
            transaction.amount = float(request.form.get('amount'))
            transaction.description = request.form.get('description')
            transaction.category = request.form.get('category')
            transaction.type = request.form.get('type')
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Transaction updated successfully!',
                'transaction': {
                    'id': transaction.id,
                    'date': transaction.date.strftime('%Y-%m-%d %H:%M'),
                    'description': transaction.description,
                    'category': transaction.category,
                    'amount': float(transaction.amount),
                    'type': transaction.type
                }
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'message': 'Error updating transaction. Please try again.'
            }), 500

@app.route('/delete_transaction/<int:transaction_id>', methods=['POST'])
@login_required
def delete_transaction(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    
    # Ensure user owns this transaction
    if transaction.user_id != current_user.id:
        return jsonify({
            'success': False,
            'message': 'Unauthorized access'
        }), 403
    
    try:
        db.session.delete(transaction)
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Transaction deleted successfully!'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': 'Error deleting transaction. Please try again.'
        }), 500

@app.route('/get_totals')
@login_required
def get_totals():
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    totals = calculate_totals(transactions)
    # Format the amounts in Indian Rupees
    totals['total_income'] = float(totals['total_income'])
    totals['total_expense'] = float(totals['total_expense'])
    totals['balance'] = float(totals['balance'])
    return jsonify(totals)

@app.route('/get_expense_categories')
@login_required
def get_expense_categories():
    # Get all expense transactions for the current user
    expenses = Transaction.query.filter_by(
        user_id=current_user.id,
        type='expense'
    ).all()
    
    # Calculate total amount for each category
    categories = {}
    for expense in expenses:
        if expense.category in categories:
            categories[expense.category] += expense.amount
        else:
            categories[expense.category] = expense.amount
    
    # Format data for the chart
    chart_data = {
        'labels': list(categories.keys()),
        'series': list(categories.values())
    }
    
    return jsonify(chart_data)

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    username = request.form.get('username')
    email = request.form.get('email')
    
    if not username or not email:
        return jsonify({
            'success': False,
            'message': 'All fields are required'
        }), 400
    
    # Email validation
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, email):
        return jsonify({
            'success': False,
            'message': 'Invalid email format'
        }), 400
    
    # Check if username is already taken by another user
    existing_user = User.query.filter(User.username == username, User.id != current_user.id).first()
    if existing_user:
        return jsonify({
            'success': False,
            'message': 'Username already taken'
        }), 400
    
    # Check if email is already taken by another user
    existing_email = User.query.filter(User.email == email, User.id != current_user.id).first()
    if existing_email:
        return jsonify({
            'success': False,
            'message': 'Email already registered'
        }), 400
    
    try:
        # Update user profile
        current_user.username = username
        current_user.email = email
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': 'Error updating profile'
        }), 500

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not all([current_password, new_password, confirm_password]):
        return jsonify({
            'success': False,
            'message': 'All password fields are required'
        }), 400
    
    # Verify current password
    if not current_user.check_password(current_password):
        return jsonify({
            'success': False,
            'message': 'Current password is incorrect'
        }), 400
    
    # Check if new passwords match
    if new_password != confirm_password:
        return jsonify({
            'success': False,
            'message': 'New passwords do not match'
        }), 400
    
    # Validate new password
    is_valid, message = validate_password(new_password)
    if not is_valid:
        return jsonify({
            'success': False,
            'message': message
        }), 400
    
    try:
        # Update password
        current_user.set_password(new_password)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Password updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': 'Error updating password'
        }), 500

@app.route('/update_notifications', methods=['POST'])
@login_required
def update_notifications():
    email_notifications = request.form.get('email_notifications') == 'on'
    transaction_alerts = request.form.get('transaction_alerts') == 'on'
    budget_warnings = request.form.get('budget_warnings') == 'on'
    
    try:
        # Here you would typically save these preferences to the database
        # For now, we'll just return success
        return jsonify({
            'success': True,
            'message': 'Notification preferences updated'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': 'Error updating preferences'
        }), 500

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    password = request.form.get('password')
    
    if not password:
        return jsonify({
            'success': False,
            'message': 'Password is required'
        }), 400
    
    # Verify password
    if not current_user.check_password(password):
        return jsonify({
            'success': False,
            'message': 'Incorrect password'
        }), 400
    
    try:
        # Delete user's transactions
        Transaction.query.filter_by(user_id=current_user.id).delete()
        
        # Delete user
        db.session.delete(current_user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Account deleted successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': 'Error deleting account'
        }), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 