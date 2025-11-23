from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-later'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('tasks'))
    return redirect(url_for('login'))

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('tasks'))
        else:
            flash('Invalid username or password!', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

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

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

