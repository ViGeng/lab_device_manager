# Lab Device Management System

A comprehensive Flask-based web application for managing laboratory equipment and devices. This system enables efficient tracking of device inventory, borrowing/returning processes, and user management with role-based access control.

## Overview

The Lab Device Management System is designed to streamline the management of laboratory equipment in academic or research environments. It provides a centralized platform where administrators can manage device inventory and users, while employees can easily borrow and return equipment with full transaction history tracking.

## Screenshots

<details>
<summary>Click to view screenshots</summary>

![Device Management](assets/image.png)
![User Management](assets/image-1.png)
![Admin Dashboard](assets/image-2.png)
![Employee Dashboard](assets/image-3.png)
![Login](assets/image-4.png)

</details>

## Key Features

### For Administrators
- **Device Management**: Add, edit, and delete device types with quantity tracking
- **User Management**: Create and manage employee and admin accounts
- **Inventory Control**: Add stock, monitor device quantities
- **Proxy Operations**: Perform borrowing/returning operations on behalf of other users
- **Complete Oversight**: Access to all system functions
### For Employees
- **Device Browsing**: View available devices with real-time quantity information
- **Self-Service Borrowing**: Borrow devices with automatic quantity validation
- **Return Management**: Return borrowed devices with quantity specification
- **Personal History**: Track currently borrowed items
- **Stock Addition**: Add inventory to existing devices

### System Features
- **Role-Based Access Control**: Separate admin and employee permissions
- **Quantity Tracking**: Real-time inventory management with availability checks
- **Responsive Design**: Clean, modern web interface that works on all devices

## Technology Stack

- **Backend**: Flask (Python web framework)
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: Flask-Login for session management
- **Frontend**: Jinja2 templates with responsive CSS
- **Security**: Werkzeug password hashing

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Installation & Deployment

### Quick Start (Development)

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd lab_device_manager
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment**
   - On macOS/Linux:
     ```bash
     source venv/bin/activate
     ```
   - On Windows:
     ```bash
     venv\Scripts\activate
     ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Access the application**
   - Open your web browser and go to: `http://localhost:5000`
   - Default admin credentials:
     - Username: `admin`
     - Password: `adminpassword`

### Production Deployment

For production deployment, consider the following security and performance improvements:

1. **Change the secret key** in `app.py`:
   ```python
   app.config['SECRET_KEY'] = 'your-secure-random-secret-key'
   ```

2. **Change default admin password** immediately after first login

3. **Use a production WSGI server** like Gunicorn:
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

4. **Set up a reverse proxy** (nginx recommended) for SSL termination

5. **Use environment variables** for sensitive configuration

## Database Management

### Automatic Setup
The application automatically creates the database and a default admin user on first run.

### Manual Database Commands
```bash
# Initialize database
flask init-db

# Create admin user
flask create-admin
```

## System Architecture

### Database Schema

**Users Table**
- id, username, password_hash, is_admin

**Devices Table**
- id, name, quantity, notes

**BorrowLog Table**
- id, user_id, device_id, quantity_transacted, transaction_type, transaction_date

### Transaction Types
- `borrow`: User borrows devices (decreases inventory)
- `return`: User returns devices (increases inventory)
- `add_stock`: Adding new inventory (increases inventory)

## Security Considerations

- Passwords are hashed using Werkzeug's secure password hashing
- Session management handled by Flask-Login
- CSRF protection should be added for production use
- Change default secret key and admin password
- Consider implementing rate limiting for production

## Troubleshooting

1. **Port already in use**: Change port in `app.py` or kill existing process
2. **Database errors**: Delete `devices.db` file to reset database
3. **Permission errors**: Ensure proper file permissions in deployment directory
4. **Missing dependencies**: Run `pip install -r requirements.txt` again or install missing packages manually

## License

This project is open source. Please check the LICENSE file for details.

## Support

No official support is provided, but feel free to open issues for bugs or feature requests. Contributions are welcome!