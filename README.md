# Lab Device Management System

A simple system to manage devices in a lab.

## Features
- Device categories
- Employee borrowing and returning devices
- Admin management

## Setup
1. Create a virtual environment: `python -m venv venv`
2. Activate it: `source venv/bin/activate` (on macOS/Linux) or `venv\Scripts\activate` (on Windows)
3. Install dependencies: `pip install -r requirements.txt`
4. Initialize the database: `flask db init`, `flask db migrate -m "initial migration"`, `flask db upgrade` (Need to add Flask-Migrate for this, or do it manually)
   Alternatively, for a simple setup, the database can be created when the app first runs.
5. Run the application: `flask run`
