from flask import Flask, render_template,  request, redirect, send_file, send_from_directory, url_for, flash, session, jsonify, send_file
import os
import shutil
import random
import time
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from cryptography.fernet import Fernet
import psutil
import mysql.connector

app = Flask(__name__)




tcp_packets = []

# Generate a random secret key
app.secret_key = os.urandom(24)

# MySQL Database Configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'data_recover'
}

# Database connection
def get_db_connection():
    return mysql.connector.connect(**db_config)

# Home route
@app.route('/')
def home():
    return render_template('home.html')



# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
        user = cursor.fetchone()
        conn.close()
        if user:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "error")
            return redirect(url_for('login'))
    return render_template('login.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        phone_number = request.form['phone_number']

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for('register'))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, phone_number) VALUES (%s, %s, %s)",
                       (username, password, phone_number))
        conn.commit()
        conn.close()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

# Dashboard route (protected)
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash("Please log in to access the dashboard", "error")
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))

@app.route('/data_recovery')
def data_recovery():
    return render_template('datarecover.html')

@app.route('/network')
def network():
    return render_template('network.html')






RECYCLE_BIN_PATH = "Recycle Bin"  # Modify to actual path
RECOVERED_DIR = "Documents\recovered_files"  # Directory where recovered files are stored



@app.route('/scan_directory', methods=['GET'])
def scan_directory():
    # Get directory path
    dir_path = request.args.get('path')
    
    if not dir_path:
        return jsonify({'status': 'error', 'message': 'Directory path is required'})
    
    # List files in the directory (Here, the mock Recycle Bin path is used)
    try:
        files = [f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]
        if files:
            return jsonify({'status': 'success', 'files': files})
        else:
            return jsonify({'status': 'error', 'message': 'No deleted files found'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/recover_data', methods=['POST'])
def recover_data():
    # Get the files selected for recovery
    files_to_recover = request.json.get('files')
    if not files_to_recover:
        return jsonify({'status': 'error', 'message': 'No files selected to recover'})
    
    recovered_files = []
    try:
        for file in files_to_recover:
            # Full path of the file to be recovered
            file_path = os.path.join(RECYCLE_BIN_PATH, file)
            recovered_path = os.path.join(RECOVERED_DIR, file)
            
            # Simulate recovery by moving the file to the "recovered" directory
            if os.path.exists(file_path):
                shutil.copy(file_path, recovered_path)
                recovered_files.append(file)
            else:
                return jsonify({'status': 'error', 'message': f'File {file} not found in the Recycle Bin'})
        
        return jsonify({'status': 'success', 'message': 'Files recovered successfully', 'files': recovered_files})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    # Return the file from the recovered directory for download
    try:
        return send_from_directory(RECOVERED_DIR, filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'status': 'error', 'message': 'File not found'})
    
@app.route('/tcp_processes', methods=['GET'])
def tcp_processes():
    # Fetch TCP connection data
    connections = psutil.net_connections(kind='tcp')
    tcp_data = []
    for conn in connections:
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        status = conn.status
        pid = conn.pid if conn.pid else "N/A"
        process_name = "N/A"
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "N/A"

        tcp_data.append({
            "local_address": laddr,
            "remote_address": raddr,
            "status": status,
            "pid": pid,
            "process_name": process_name
        })
    return jsonify(tcp_data)

if __name__ == '__main__':
    app.run(debug=True)