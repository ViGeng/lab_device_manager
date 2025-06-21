import os

from flask import (Flask, flash, redirect, render_template, request, session,
                   url_for)
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

# --- Configuration ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_very_secret_key_here' # Change this!
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(BASE_DIR, 'devices.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Device Model (represents a device type)
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True) # Device type name
    quantity = db.Column(db.Integer, nullable=False, default=0) # Total quantity in stock
    notes = db.Column(db.Text, nullable=True) # Optional notes

    def __repr__(self):
        return f'<Device {self.name} (Qty: {self.quantity})>'

# Revised BorrowLog Model to track current borrowed quantities
class BorrowLog(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), primary_key=True)
    quantity_borrowed = db.Column(db.Integer, nullable=False, default=0) # Number of units currently borrowed

    user = db.relationship('User', backref=db.backref('borrow_logs', lazy=True))
    device = db.relationship('Device', backref=db.backref('borrow_logs', lazy=True))

    def __repr__(self):
        return f'<BorrowLog: User {self.user_id} currently has {self.quantity_borrowed} of Device {self.device_id}>'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('employee_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('employee_dashboard'))
    # Pass the models to the template
    return render_template('admin_dashboard.html', Device=Device, User=User)

@app.route('/employee')
@login_required
def employee_dashboard():
    devices = Device.query.all()
    all_users = User.query.all() if current_user.is_admin else []
    return render_template('employee_dashboard.html', devices=devices, Device=Device, all_users=all_users)

@app.route('/add_new_device', methods=['POST'])
@login_required
def add_new_device():
    if not current_user.is_admin:
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('employee_dashboard'))
    
    name = request.form['name']
    quantity = request.form.get('quantity', 0, type=int)
    notes = request.form.get('notes', '')
    
    if not name:
        flash('Device name is required.', 'warning')
    else:
        existing_device = Device.query.filter_by(name=name).first()
        if existing_device:
            flash(f"Device '{name}' already exists.", 'warning')
        else:
            new_device = Device(name=name, quantity=quantity, notes=notes)
            db.session.add(new_device)
            db.session.commit()
            flash('Device added successfully!', 'success')
    
    return redirect(url_for('employee_dashboard'))

# --- Admin Routes ---
@app.route('/admin/devices/delete/<int:device_id>', methods=['POST'])
@login_required
def delete_device(device_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    device_to_delete = Device.query.get_or_404(device_id)
    # Check for related borrow logs and handle them if necessary, or prevent deletion.
    # For simplicity, we'll just delete. Consider implications for BorrowLog.
    BorrowLog.query.filter_by(device_id=device_id).delete() # Example: delete logs too
    db.session.delete(device_to_delete)
    db.session.commit()
    flash('Device deleted successfully!', 'success')
    return redirect(url_for('employee_dashboard'))


@app.route('/admin/employees', methods=['GET', 'POST'])
@login_required
def manage_employees():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        if username and password:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash(f"User '{username}' already exists.", 'warning')
            else:
                new_user = User(username=username, is_admin=is_admin)
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash('Employee/Admin added successfully!', 'success')
        else:
            flash('Username and password are required.', 'warning')
        return redirect(url_for('manage_employees'))
    
    employees = User.query.all()
    return render_template('employees.html', employees=employees, is_admin=True)

@app.route('/admin/employees/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_employee(user_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    if user_id == current_user.id:
        flash("You cannot delete your own account.", 'danger')
        return redirect(url_for('manage_employees'))
    
    user_to_delete = User.query.get_or_404(user_id)
    # Consider implications for BorrowLog if user is deleted.
    # For simplicity, we'll just delete.
    BorrowLog.query.filter_by(user_id=user_id).delete() # Example: delete logs too
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f"User '{user_to_delete.username}' deleted successfully!", 'success')
    return redirect(url_for('manage_employees'))


# --- Employee Routes ---
@app.route('/borrow/<int:device_id>', methods=['POST'])
@login_required
def borrow_device(device_id):
    device = Device.query.get_or_404(device_id)
    quantity_to_borrow = request.form.get('quantity', 1, type=int)
    
    target_user_id = current_user.id
    if current_user.is_admin and 'user_id' in request.form:
        target_user_id = request.form.get('user_id', current_user.id, type=int)
        target_user = User.query.get(target_user_id)
        if not target_user:
            flash('Invalid user selected.', 'danger')
            return redirect(url_for('employee_dashboard'))
    
    if quantity_to_borrow <= 0:
        flash('Quantity must be positive.', 'warning')
    elif device.quantity >= quantity_to_borrow:
        # Check if a borrow log already exists for this user and device
        borrow_log = BorrowLog.query.filter_by(user_id=target_user_id, device_id=device.id).first()
        if borrow_log:
            # Update existing log
            borrow_log.quantity_borrowed += quantity_to_borrow
        else:
            # Create new log
            borrow_log = BorrowLog(
                user_id=target_user_id,
                device_id=device.id,
                quantity_borrowed=quantity_to_borrow
            )
            db.session.add(borrow_log)
        
        device.quantity -= quantity_to_borrow
        db.session.commit()
        
        user_for_flash = User.query.get(target_user_id)
        flash(f"{user_for_flash.username} has borrowed {quantity_to_borrow} {device.name}(s). Total borrowed: {borrow_log.quantity_borrowed}.", 'success')
    else:
        flash(f"Not enough {device.name} available. Only {device.quantity} in stock.", 'warning')
    return redirect(url_for('employee_dashboard'))

@app.route('/return/<int:device_id>', methods=['POST'])
@login_required
def return_device(device_id):
    device = Device.query.get_or_404(device_id)
    quantity_to_return = request.form.get('quantity', 1, type=int)

    target_user_id = current_user.id
    user_for_flash = current_user

    if current_user.is_admin and 'user_id' in request.form:
        try:
            selected_user_id = int(request.form.get('user_id'))
            selected_user = User.query.get(selected_user_id)
            if selected_user:
                target_user_id = selected_user_id
                user_for_flash = selected_user
            else:
                flash('Invalid user selected for return.', 'danger')
                return redirect(url_for('employee_dashboard'))
        except ValueError:
            flash('Invalid user ID format.', 'danger')
            return redirect(url_for('employee_dashboard'))

    if quantity_to_return <= 0:
        flash('Quantity to return must be positive.', 'warning')
        return redirect(url_for('employee_dashboard'))

    borrow_log = BorrowLog.query.filter_by(
        device_id=device.id,
        user_id=target_user_id
    ).first()

    if borrow_log and borrow_log.quantity_borrowed >= quantity_to_return:
        device.quantity += quantity_to_return
        borrow_log.quantity_borrowed -= quantity_to_return
        
        if borrow_log.quantity_borrowed == 0:
            db.session.delete(borrow_log)
        
        db.session.commit()
        if target_user_id == current_user.id:
            flash(f"You have returned {quantity_to_return} {device.name}(s).", 'success')
        else:
            flash(f"{quantity_to_return} {device.name}(s) returned for {user_for_flash.username}.", 'success')
    elif borrow_log:
        flash(f'{user_for_flash.username} cannot return {quantity_to_return} {device.name}(s). They only have {borrow_log.quantity_borrowed} borrowed.', 'warning')
    else:
        flash(f'No active borrow record found for {device.name} by {user_for_flash.username} to return.', 'danger')
    return redirect(url_for('employee_dashboard'))

@app.route('/add_stock/<int:device_id>', methods=['POST'])
@login_required
def add_stock(device_id):
    # Ensure only admins can add stock
    if not current_user.is_admin:
        flash('Access denied: Admins only.', 'danger')
        return redirect(url_for('employee_dashboard'))

    device = Device.query.get_or_404(device_id)
    quantity = request.form.get('quantity', 1, type=int)
    
    if quantity <= 0:
        flash('Quantity must be positive.', 'warning')
    else:
        device.quantity += quantity
        # Removed BorrowLog creation as it's not for stock transactions anymore
        db.session.commit()
        flash(f"Added {quantity} {device.name}(s) to stock. Total now: {device.quantity}.", 'success')
    return redirect(url_for('employee_dashboard'))


# --- CLI commands ---
@app.cli.command("init-db")
def init_db_command():
    """Creates the database tables."""
    with app.app_context():
        db.create_all()
    print("Initialized the database.")

@app.cli.command("create-admin")
def create_admin_command():
    """Creates the admin user."""
    with app.app_context():
        username = 'admin'
        password = 'admin' # Change in production
        if User.query.filter_by(username=username).first():
            print(f"Admin user '{username}' already exists.")
            return
        admin_user = User(username=username, is_admin=True)
        admin_user.set_password(password)
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user '{username}' created with password '{password}'.")

if __name__ == '__main__':
    # Removed automatic db.create_all() and admin creation from here.
    # Use 'flask init-db' and 'flask create-admin' CLI commands instead.
    app.run(host='0.0.0.0', port=80, debug=True)

