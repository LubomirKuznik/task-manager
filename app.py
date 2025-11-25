# Load environment variables from .env file
from dotenv import load_dotenv
import os

load_dotenv() # Reads .env file and loads variables (API keys, secrets, etc.)

# Import Flask and extensions
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

# Initialize Flask application
app = Flask(__name__)

# Configure Flask app
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///tasks.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)
    tasks = db.relationship('Task', backref='user', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='created')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='task', lazy=True, cascade='all, delete-orphan')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    status_at_time = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now())
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Helper Functions
import secrets
import resend

resend.api_key = os.getenv('RESEND_API_KEY')

def generate_token():
    """Generate a secure random token"""
    return secrets.token_urlsafe(32)

def send_verification_email(email, username, token):
    """Send email verification link"""
    verification_url = url_for('verify_email', token=token, _external=True)
    
    params = {
        "from": "onboarding@resend.dev",
        "to": [email],
        "subject": "Verify your Task Manager account",
        "html": f"""
        <h2>Welcome to Task Manager, {username}!</h2>
        <p>Please click the link below to verify your email address:</p>
        <a href="{verification_url}">Verify Email</a>
        <p>If you didn't create an account, please ignore this email.</p>
        """
    }
    
    try:
        resend.Emails.send(params)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def send_password_reset_email(email, username, token):
    """Send password reset link"""
    reset_url = url_for('reset_password', token=token, _external=True)
    
    params = {
        "from": "onboarding@resend.dev",
        "to": [email],
        "subject": "Reset your Task Manager password",
        "html": f"""
        <h2>Hi {username},</h2>
        <p>You requested to reset your password. Click the link below:</p>
        <a href="{reset_url}">Reset Password</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
        """
    }
    
    try:
        resend.Emails.send(params)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('tasks'))
    return redirect(url_for('login'))

# Register route - Creates new user account with email verification
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            if existing_user.username == username:
                flash('Username already exists!', 'error')
            else:
                flash('Email already registered!', 'error')
            return redirect(url_for('register'))
        
        # Create new user with verification token
        hashed_password = generate_password_hash(password)
        verification_token = generate_token()
        
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            verification_token=verification_token,
            is_verified=False
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Send verification email
            if send_verification_email(email, username, verification_token):
                flash('Registration successful! Please check your email to verify your account.', 'success')
            else:
                flash('Registration successful, but failed to send verification email. Please contact support.', 'warning')
            
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

# Email verification route - Verifies user's email address
@app.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    
    if not user:
        flash('Invalid verification link!', 'error')
        return redirect(url_for('login'))
    
    if user.is_verified:
        flash('Email already verified. Please login.', 'info')
        return redirect(url_for('login'))
    
    # Verify the user
    user.is_verified = True
    user.verification_token = None  # Clear the token
    db.session.commit()
    
    flash('Email verified successfully! You can now login.', 'success')
    return redirect(url_for('login'))

# Login route - Authenticates user and checks email verification
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Invalid email or password!', 'error')
            return redirect(url_for('login'))
        
        if not check_password_hash(user.password, password):
            flash('Invalid email or password!', 'error')
            return redirect(url_for('login'))
        
        # Check if email is verified
        if not user.is_verified:
            flash('Please verify your email before logging in. Check your inbox.', 'error')
            return redirect(url_for('login'))
        
        # Login successful
        session['user_id'] = user.id
        session['username'] = user.username
        session['email'] = user.email
        flash('Login successful!', 'success')
        return redirect(url_for('tasks'))
    
    return render_template('login.html')

# Forgot password route - Request password reset
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token (expires in 1 hour)
            reset_token = generate_token()
            user.reset_token = reset_token
            user.reset_token_expiry = datetime.now() + timedelta(hours=1)
            db.session.commit()
            
            # Send reset email
            if send_password_reset_email(email, user.username, reset_token):
                flash('Password reset link sent to your email!', 'success')
            else:
                flash('Failed to send email. Please try again.', 'error')
        else:
            # Don't reveal if email exists (security)
            flash('If that email exists, a reset link has been sent.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

# Reset password route - Reset password with token
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or not user.reset_token_expiry or user.reset_token_expiry < datetime.now():
        flash('Invalid or expired reset link!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('reset_password.html', token=token)
        
        # Update password
        user.password = generate_password_hash(new_password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash('Password reset successful! You can now login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

# Logout route - Logs the user out by clearing their session data and redirects to login page.
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Tasks Page Route - Shows all tasks for the logged-in user, sorted by creation date.
@app.route('/tasks')
def tasks():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_tasks = Task.query.filter_by(user_id=session['user_id']).order_by(Task.created_at.desc()).all()
    return render_template('tasks.html', tasks=user_tasks, username=session['username'], Comment=Comment)

# New task Route - Creates a new task when user submits the add task form.
@app.route('/add', methods=['POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    title = request.form['title']
    description = request.form.get('description', '')
    
    new_task = Task(title=title, description=description, user_id=session['user_id'])
    db.session.add(new_task)
    db.session.commit()
    
    flash('Task added successfully!', 'success')
    return redirect(url_for('tasks'))

# Update Task Status Route - Changes a task's status between 'created' → 'in_progress' → 'completed'.
@app.route('/update_status/<int:task_id>/<new_status>')
def update_status(task_id, new_status):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    task = Task.query.get_or_404(task_id)
    
    if task.user_id != session['user_id']:
        flash('Unauthorized action!', 'error')
        return redirect(url_for('tasks'))
    
    if new_status in ['created', 'in_progress', 'completed']:
        task.status = new_status
        db.session.commit()
        flash(f'Task status updated to {new_status}!', 'success')
    
    return redirect(url_for('tasks'))

# Delete Task Route - Deletes a task from the database.
@app.route('/delete/<int:task_id>')
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    task = Task.query.get_or_404(task_id)
    
    if task.user_id != session['user_id']:
        flash('Unauthorized action!', 'error')
        return redirect(url_for('tasks'))
    
    db.session.delete(task)
    db.session.commit()
    
    flash('Task deleted successfully!', 'success')
    return redirect(url_for('tasks'))

# Add comment Route - Adds comments to tasks.
@app.route('/add_comment/<int:task_id>', methods=['POST'])
def add_comment(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    task = Task.query.get_or_404(task_id)
    
    if task.user_id != session['user_id']:
        flash('Unauthorized action!', 'error')
        return redirect(url_for('tasks'))
    
    comment_text = request.form['comment']
    
    if comment_text.strip():
        new_comment = Comment(
            text=comment_text,
            status_at_time=task.status,
            task_id=task_id,
            user_id=session['user_id']
        )
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added!', 'success')
    
    return redirect(url_for('tasks'))

# Run application - Only executes when app.py is run directly (not when imported)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)