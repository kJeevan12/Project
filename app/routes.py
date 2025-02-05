import os
from pathlib import Path
import random
import socket
import threading
import time
import random
from flask import Blueprint,jsonify, render_template, request, redirect, send_file, session, url_for, flash
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path


from . import db


bluePrint = Blueprint("auth",__name__)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)

# Home route
@bluePrint.route('/')
def home():
    return render_template('home.html')

# Registration route
@bluePrint.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        phone_number = request.form['phone_number']

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('auth.register'))

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

        # Save the user to the database
        new_user = User(username=username, password=hashed_password, phone_number=phone_number)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('auth.login'))
        except:
            flash("Username already exists.", "danger")
            return redirect(url_for('auth.register'))

    return render_template('register.html')

# Login route
@bluePrint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user exists
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            flash("Login successful!", "success")
            return redirect(url_for('auth.dashboard'))
        else:
            flash("Invalid username or password!", "danger")
            return redirect(url_for('auth.login'))

    return render_template('login.html')


@bluePrint.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.home'))

@bluePrint.route('/dashboard')
def dashboard():
   
    return render_template('dashboard.html')

@bluePrint.route('/data_recovery')
def data_recovery():
    return render_template('datarecover.html')
    

RECOVERED_DIR = Path("D:\\Project\\Testing\\RecoveredData")
RECOVERED_DIR.mkdir(exist_ok=True)

SECRET_KEY = Fernet.generate_key()  # Permanent key (store securely)
cipher = Fernet(SECRET_KEY)

class Recovery:
    def __init__(self, filetype, start_signature, end_signature, offset):
        self.filetype = filetype
        self.start_signature = start_signature
        self.end_signature = end_signature
        self.offset = offset

    def recover(self, drive_letter):
        drive_path = f"\\\\.\\{drive_letter}:"
        try:
            with open(drive_path, "rb") as drive:
                data = drive.read(512)
                offset = 0
                recovered_count = 0
                while data:
                    start_idx = data.find(self.start_signature)
                    if start_idx >= 0:
                        print(f"Found {self.filetype} at offset {hex(offset * 512 + start_idx)}")
                        file_path = RECOVERED_DIR / f"recovered_{recovered_count}.{self.filetype}"
                        
                        with open(file_path, "wb") as output_file:
                            output_file.write(data[start_idx:])
                            while True:
                                data = drive.read(512)
                                end_idx = data.find(self.end_signature)
                                if end_idx >= 0:
                                    output_file.write(data[:end_idx + self.offset])
                                    break
                                output_file.write(data)

                        self.encrypt_file(file_path)
                        os.remove(file_path)  # Delete original after encryption
                        recovered_count += 1
                    data = drive.read(512)
                    offset += 1
        except Exception as e:
            print(f"Error accessing drive {drive_letter}: {e}")

    def encrypt_file(self, filepath):
        """Encrypt a file with AES"""
        with open(filepath, "rb") as file:
            encrypted_data = cipher.encrypt(file.read())

        with open(str(filepath) + ".enc", "wb") as enc_file:
            enc_file.write(encrypted_data)

@bluePrint.route('/recover', methods=['POST'])
def recover_data():
    data = request.get_json()
    drive_letter = data.get("drive_letter")

    if not drive_letter:
        return jsonify({"error": "Drive letter is required"}), 400

    drive_letter = drive_letter.strip().upper()
    if len(drive_letter) != 1 or not drive_letter.isalpha():
        return jsonify({"error": "Invalid drive letter"}), 400

    recovery_tasks = [
        Recovery("pdf", b"\x25\x50\x44\x46\x2D", b"\x0A\x25\x25\x45\x4F\x46", 6),
        Recovery("jpg", b"\xFF\xD8\xFF\xE0", b"\xFF\xD9", 2),
        Recovery("png", b"\x89\x50\x4E\x47", b"\x49\x45\x4E\x44\xAE\x42\x60\x82", 8),
        Recovery("txt", b"U", b"U", 0),
        Recovery("mp4", b"\x00\x00\x00\x18\x66\x74\x79\x70", b"\x6D\x64\x61\x74", 0)
    ]

    threads = []
    for task in recovery_tasks:
        thread = threading.Thread(target=task.recover, args=(drive_letter,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return jsonify({"message": "Recovery process completed. Files are encrypted."})

@bluePrint.route('/decrypt', methods=['POST'])
def decrypt_files():
    data = request.get_json()
    password = data.get("password")

    if password != "SecurePassword123":  # Permanent password
        return jsonify({"error": "Incorrect password"}), 401

    for enc_file in RECOVERED_DIR.glob("*.enc"):
        with open(enc_file, "rb") as file:
            decrypted_data = cipher.decrypt(file.read())

        original_path = str(enc_file).replace(".enc", "")
        with open(original_path, "wb") as file:
            file.write(decrypted_data)

        os.remove(enc_file)  # Remove encrypted file after decryption

    return jsonify({"message": "Decryption successful. You can now access the files."})

received_packets = []



@bluePrint.route('/send_data')
def send_data():
    threading.Thread(target=simulate_sender).start()
    return "Sending Data..."

@bluePrint.route('/receive_data')
def receive_data():
    threading.Thread(target=simulate_receiver).start()
    return "Receiving Data..."

@bluePrint.route('/stored_packets')
def stored_packets():
    # Return the list of stored packets in JSON format
    return jsonify([{"sequence_number": packet.sequence_number, "data": packet.data} for packet in received_packets])

class Packet:
    def __init__(self, sequence_number, data):
        self.sequence_number = sequence_number
        self.data = data

    def to_bytes(self):
        return (self.sequence_number.to_bytes(4, 'big') +
                len(self.data).to_bytes(4, 'big') +
                self.data.encode())

    @classmethod
    def from_bytes(cls, data):
        sequence_number = int.from_bytes(data[:4], 'big')
        data_length = int.from_bytes(data[4:8], 'big')
        packet_data = data[8:8+data_length]
        return cls(sequence_number, packet_data.decode())

class Sender:
    def __init__(self, host, port, loss_rate=0.1):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.loss_rate = loss_rate

    def send_packet(self, sequence_number, data):
        packet = Packet(sequence_number, data)
        if random.random() > self.loss_rate:
            self.sock.sendto(packet.to_bytes(), (self.host, self.port))
            print(f"Sent packet {sequence_number}")
        else:
            print(f"Packet {sequence_number} dropped.")

def simulate_sender():
    sender = Sender('localhost', 10000)
    for i in range(10):  # Simulate sending 10 packets
        sender.send_packet(i, f"Data {i}")
        time.sleep(0.5)

class Receiver:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse
        self.sock.bind((self.host, self.port))
        print(f"Receiver is listening on {self.host}:{self.port}")

    def receive_packet(self):
        while True:
            try:
                print("Waiting for packets...")  # Debugging print

                # Receive data from sender
                data, addr = self.sock.recvfrom(1024)
                if not data:
                    print("No data received.")
                    continue  # Skip to next iteration

                # Convert bytes back to packet
                packet = Packet.from_bytes(data)
                print(f"✅ Received packet {packet.sequence_number}: {packet.data} from {addr}")

                # Send acknowledgment back to sender
                self.sock.sendto(packet.sequence_number.to_bytes(4, 'big'), addr)
                print(f"📩 Acknowledgment sent for packet {packet.sequence_number} to {addr}")

            except Exception as e:
                print(f"Error receiving packet: {e}")
                break  # Stop loop if an error occurs



def simulate_receiver():
    receiver = Receiver('localhost', 10000)  # Use a different port
    receiver.receive_packet()



@bluePrint.route('/network')
def network():
    return render_template("network.html")


key = Fernet.generate_key()
cipher_suite = Fernet(key)

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

key = Fernet.generate_key()
cipher_suite = Fernet(key)



@bluePrint.route('/file_encryption', methods=['GET', 'POST'])
def file_encryption():
    if request.method == 'POST':
        file = request.files.get('file')
        
        # Ensure that the file is present
        if file and file.filename != '':
            # Save the uploaded file to the server
            file_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(file_path)

            # Encrypt the file
            with open(file_path, 'rb') as f:
                file_data = f.read()

            encrypted_data = cipher_suite.encrypt(file_data)

            # Save the encrypted file with an absolute path
            encrypted_file_path = file_path + '.encrypted'
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)

            # Debugging: Log the absolute path of the encrypted file
            print(f"Encrypted file absolute path: {encrypted_file_path}")
            
            # Ensure the encrypted file exists at the absolute path
            if not os.path.exists(encrypted_file_path):
                print(f"Error: Encrypted file not found at {encrypted_file_path}")
                return f"Error: Encrypted file not found at {encrypted_file_path}", 500

            # Try to send the encrypted file using an absolute path
            try:
                return send_file(encrypted_file_path, as_attachment=True)
            except Exception as e:
                print(f"Error while sending file: {e}")
                return f"Error while sending file: {e}", 500

        else:
            return "No file selected", 400  # Bad Request if no file is selected

    return render_template('fileencryption.html')



sent_packets = []
received_packets = []
packet_id = 1


class Packet:
    def __init__(self, sequence_number, data):
        self.sequence_number = sequence_number
        self.data = data

    def to_bytes(self):
        return (self.sequence_number.to_bytes(4, 'big') +
                len(self.data).to_bytes(4, 'big') +
                self.data.encode())

    @classmethod
    def from_bytes(cls, data):
        sequence_number = int.from_bytes(data[:4], 'big')
        data_length = int.from_bytes(data[4:8], 'big')
        packet_data = data[8:8+data_length]
        return cls(sequence_number, packet_data.decode())

class Sender:
    def __init__(self, host, port, loss_rate=0.1):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.loss_rate = loss_rate

    def send_packet(self, sequence_number, data):
        packet = Packet(sequence_number, data)
        if random.random() > self.loss_rate:
            self.sock.sendto(packet.to_bytes(), (self.host, self.port))
            print(f"Sent packet {sequence_number}")
        else:
            print(f"Packet {sequence_number} dropped.")

def simulate_sender():
    sender = Sender('localhost', 10000)
    for i in range(10):  # Simulate sending 10 packets
        sender.send_packet(i, f"Data {i}")
        time.sleep(0.5)

class Receiver:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse
        self.sock.bind((self.host, self.port))
        print(f"Receiver is listening on {self.host}:{self.port}")

    def receive_packet(self):
        while True:
            try:
                print("Waiting for packets...")  # Debugging print

                # Receive data from sender
                data, addr = self.sock.recvfrom(1024)
                if not data:
                    print("No data received.")
                    continue  # Skip to next iteration

                # Convert bytes back to packet
                packet = Packet.from_bytes(data)
                print(f"✅ Received packet {packet.sequence_number}: {packet.data} from {addr}")

                # Send acknowledgment back to sender
                self.sock.sendto(packet.sequence_number.to_bytes(4, 'big'), addr)
                print(f"📩 Acknowledgment sent for packet {packet.sequence_number} to {addr}")

            except Exception as e:
                print(f"Error receiving packet: {e}")
                break  # Stop loop if an error occurs

def simulate_receiver():
    receiver = Receiver('localhost', 10000)  # Use a different port
    receiver.receive_packet()

@bluePrint.route('/monitoring')
def monitoring():
    return render_template('monitoring.html')

@bluePrint.route('/send_data', endpoint='auth_send_data')
def auth_send_data():
    threading.Thread(target=simulate_sender).start()
    return "Sending Data..."

@bluePrint.route('/receive_data', endpoint='auth_receive_data')
def auth_receive_data():
    threading.Thread(target=simulate_receiver).start()
    return "Receiving Data..."

@bluePrint.route('/stored_packets')
def auth_stored_packets():
    # Return the list of stored packets in JSON format
    return jsonify([{"sequence_number": packet.sequence_number, "data": packet.data} for packet in received_packets])

@bluePrint.route('/monitoring/send', methods=['POST'])
def send_packet():
    global packet_id
    data = request.json.get("data")
    protocol = request.json.get("protocol")
    ip_address = request.json.get("ip_address")
    port = int(request.json.get("port"))
    
    try:
        if protocol == "UDP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data.encode(), (ip_address, port))
            status = "UDP Packet Sent"
        elif protocol == "TCP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip_address, port))
            sock.sendall(data.encode())
            sock.close()
            status = "TCP Packet Sent"
        else:
            status = "Invalid Protocol"
    except Exception as e:
        status = f"Error: {str(e)}"

    packet = {
        "id": packet_id,
        "protocol": protocol,
        "ip_address": ip_address,
        "port": port,
        "data": data,
        "status": status
    }
    sent_packets.append(packet)
    packet_id += 1
    return jsonify(packet)

@bluePrint.route('/monitoring/delete/<int:packet_id>', methods=['DELETE'])
def delete_packet(packet_id):
    global sent_packets
    sent_packets = [p for p in sent_packets if p["id"] != packet_id]
    return jsonify({"success": True})


