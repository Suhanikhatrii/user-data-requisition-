import os
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import sqlite3
import uuid
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from fpdf import FPDF # Make sure you have fpdf2 installed (pip install fpdf2)

app = Flask(__name__)
# IMPORTANT: For production, replace "*" with your Render frontend URL (e.g., "https://your-frontend.onrender.com")
# This ensures that only your frontend can make requests to your backend.
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Database configuration
DATABASE = 'database.db'

def get_db():
    """Establishes a database connection and sets row_factory to sqlite3.Row."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema and creates a default admin user if not exists."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                cpf_id TEXT UNIQUE NOT NULL,
                name TEXT,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT,
                created_by TEXT
            )
        ''')
        # Create requisitions table with new fields for approval and user details
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS requisitions (
                id TEXT PRIMARY KEY,
                requisition_date TEXT,
                basin TEXT,
                block TEXT,
                area TEXT,
                dimension TEXT,
                return_date TEXT,
                data_type TEXT,
                objective TEXT,
                remarks TEXT,
                user_name TEXT,
                user_designation TEXT,
                user_cpf_no TEXT,
                user_mobile_no TEXT,
                user_group TEXT,
                requested_by_user_id TEXT,
                requested_by_user_cpf_id TEXT,
                status TEXT NOT NULL,
                created_at TEXT,
                approved_by_level2_user_id TEXT,
                approved_by_level2_user_cpf_id TEXT,
                approved_by_level2_user_name TEXT,
                decision_at TEXT
            )
        ''')
        db.commit()

        # Add a default admin user if one doesn't exist
        cursor.execute("SELECT * FROM users WHERE cpf_id = 'admin123'")
        if cursor.fetchone() is None:
            admin_id = str(uuid.uuid4())
            hashed_password = generate_password_hash('password123')
            cursor.execute(
                "INSERT INTO users (id, cpf_id, name, email, password_hash, role, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (admin_id, 'admin123', 'Admin User', 'admin@example.com', hashed_password, 'admin', datetime.datetime.now().isoformat(), 'system')
            )
            db.commit()
            print("Default admin user created: CPF ID: admin123 / Password: password123")
        db.close()

# Initialize the database when the application starts
init_db()

# Root endpoint for a simple health check or welcome message
@app.route('/', methods=['GET'])
def home():
    """Returns a welcome message for the API root."""
    return jsonify({"message": "Welcome to the Flask API!"}), 200

@app.route('/api/login', methods=['POST'])
def login():
    """Authenticates a user based on CPF ID and password."""
    data = request.get_json()
    cpf_id = data.get('cpfId')
    password = data.get('password')

    if not cpf_id or not password:
        return jsonify({"message": "CPF ID and password are required"}), 400

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE cpf_id = ?", (cpf_id,)).fetchone()
    db.close()

    if user and check_password_hash(user['password_hash'], password):
        # Return necessary user details including role
        return jsonify({
            "message": "Login successful",
            "cpfId": user['cpf_id'],
            "uid": user['id'], # Use 'id' as 'uid' for frontend consistency
            "name": user['name'],
            "email": user['email'],
            "role": user['role']
        }), 200
    else:
        return jsonify({"message": "Invalid CPF ID or password"}), 401

@app.route('/api/register', methods=['POST'])
def register_user():
    """Registers a new user (admin functionality)."""
    data = request.get_json()
    name = data.get('name')
    cpf_id = data.get('cpfId')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')
    created_by = data.get('createdBy', 'unknown')

    if not all([name, cpf_id, password, role]):
        return jsonify({"message": "Name, CPF ID, password, and role are required"}), 400

    if len(password) < 6:
        return jsonify({"message": "Password must be at least 6 characters long"}), 400

    db = get_db()
    cursor = db.cursor()

    # Check if CPF ID or email already exists
    existing_user_cpf = cursor.execute("SELECT * FROM users WHERE cpf_id = ?", (cpf_id,)).fetchone()
    if existing_user_cpf:
        db.close()
        return jsonify({"message": "User with this CPF ID already exists"}), 409

    if email: # Email is optional, only check uniqueness if provided
        existing_user_email = cursor.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if existing_user_email:
            db.close()
            return jsonify({"message": "User with this email already exists"}), 409

    user_id = str(uuid.uuid4())
    hashed_password = generate_password_hash(password)
    created_at = datetime.datetime.now().isoformat()

    try:
        cursor.execute(
            "INSERT INTO users (id, cpf_id, name, email, password_hash, role, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (user_id, cpf_id, name, email, hashed_password, role, created_at, created_by)
        )
        db.commit()
        return jsonify({"message": "User registered successfully", "userId": user_id}), 201
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        db.close()

@app.route('/api/users', methods=['GET'])
def get_users():
    """Retrieves a list of all users."""
    db = get_db()
    users = db.execute("SELECT id, cpf_id, name, email, role, created_at, created_by FROM users").fetchall()
    db.close()
    return jsonify([dict(user) for user in users]), 200

@app.route('/api/users/<user_id>/password', methods=['PUT'])
def change_password(user_id):
    """Changes a user's password."""
    data = request.get_json()
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')

    if not current_password or not new_password:
        return jsonify({"message": "Current and new passwords are required"}), 400
    
    if len(new_password) < 6:
        return jsonify({"message": "New password must be at least 6 characters long"}), 400

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        db.close()
        return jsonify({"message": "User not found"}), 404

    if not check_password_hash(user['password_hash'], current_password):
        db.close()
        return jsonify({"message": "Incorrect current password"}), 401
    
    # Check if new password is the same as current password (after hashing)
    if check_password_hash(user['password_hash'], new_password):
        db.close()
        return jsonify({"message": "New password cannot be the same as current password"}), 400

    hashed_new_password = generate_password_hash(new_password)
    try:
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_new_password, user_id))
        db.commit()
        return jsonify({"message": "Password changed successfully"}), 200
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        db.close()

@app.route('/api/requisitions', methods=['POST'])
def create_requisition():
    """Creates a new data requisition."""
    data = request.get_json()

    # Extract all fields from the request data
    requisition_data = {
        'requisition_date': data.get('requisitionDate'),
        'basin': data.get('basin'),
        'block': data.get('block'),
        'area': data.get('area'),
        'dimension': data.get('dimension'),
        'return_date': data.get('returnDate'),
        'data_type': data.get('dataType'),
        'objective': data.get('objective'),
        'remarks': data.get('remarks'),
        'user_name': data.get('userName'),
        'user_designation': data.get('userDesignation'),
        'user_cpf_no': data.get('userCPFNo'),
        'user_mobile_no': data.get('userMobileNo'),
        'user_group': data.get('userGroup'),
        'requested_by_user_id': data.get('requestedByUserId'),
        'requested_by_user_cpf_id': data.get('requestedByUserCpfId'),
        'status': 'pending_level2', # Default initial status
        'created_at': datetime.datetime.now().isoformat(),
        'title': f"Requisition for {data.get('basin')} - {data.get('area') or 'N/A'}", # Auto-generate title
        'description': data.get('objective') # Use objective as description
    }

    # Basic validation for mandatory fields based on frontend's required fields
    mandatory_fields = ['basin', 'user_cpf_no', 'user_mobile_no', 'user_group']
    for field in mandatory_fields:
        if not requisition_data.get(field):
            return jsonify({"message": f"Mandatory field '{field.replace('_', ' ').capitalize()}' is missing"}), 400

    req_id = str(uuid.uuid4())
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO requisitions (
                id, requisition_date, basin, block, area, dimension, return_date,
                data_type, objective, remarks, user_name, user_designation,
                user_cpf_no, user_mobile_no, user_group, requested_by_user_id,
                requested_by_user_cpf_id, status, created_at, title, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                req_id, requisition_data['requisition_date'], requisition_data['basin'],
                requisition_data['block'], requisition_data['area'], requisition_data['dimension'],
                requisition_data['return_date'], requisition_data['data_type'],
                requisition_data['objective'], requisition_data['remarks'],
                requisition_data['user_name'], requisition_data['user_designation'],
                requisition_data['user_cpf_no'], requisition_data['user_mobile_no'],
                requisition_data['user_group'], requisition_data['requested_by_user_id'],
                requisition_data['requested_by_user_cpf_id'], requisition_data['status'],
                requisition_data['created_at'], requisition_data['title'], requisition_data['description']
            )
        )
        db.commit()
        return jsonify({"message": "Requisition created successfully", "id": req_id}), 201
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        db.close()


@app.route('/api/requisitions', methods=['GET'])
def get_requisitions():
    """Retrieves requisitions based on query parameters (e.g., status, userId)."""
    status_filter = request.args.get('status')
    user_id_filter = request.args.get('userId')
    basin_filter = request.args.get('basin') # New filter for Level 3
    user_group_filter = request.args.get('userGroup') # New filter for Level 3

    db = get_db()
    query_str = "SELECT * FROM requisitions WHERE 1=1"
    params = []

    if status_filter:
        query_str += " AND status = ?"
        params.append(status_filter)
    if user_id_filter:
        query_str += " AND requested_by_user_id = ?"
        params.append(user_id_filter)
    if basin_filter:
        query_str += " AND basin LIKE ?"
        params.append(f"%{basin_filter}%")
    if user_group_filter:
        query_str += " AND user_group LIKE ?"
        params.append(f"%{user_group_filter}%")

    # Add ordering, e.g., by creation date descending
    query_str += " ORDER BY created_at DESC"

    requisitions = db.execute(query_str, params).fetchall()
    db.close()

    return jsonify([dict(req) for req in requisitions]), 200

@app.route('/api/requisitions/<string:requisition_id>', methods=['PUT'])
def update_requisition_status(requisition_id):
    """Updates the status of a specific requisition (Level 2 approval)."""
    data = request.get_json()
    new_status = data.get('status')
    approved_by_level2_user_id = data.get('approvedByLevel2UserId')
    approved_by_level2_user_cpf_id = data.get('approvedByLevel2UserCpfId')
    approved_by_level2_user_name = data.get('approvedByLevel2UserName') # New: approver's name

    if not new_status:
        return jsonify({"message": "New status is required"}), 400

    db = get_db()
    cursor = db.cursor()
    try:
        # Update requisition status and approval details
        cursor.execute(
            """
            UPDATE requisitions
            SET status = ?,
                approved_by_level2_user_id = ?,
                approved_by_level2_user_cpf_id = ?,
                approved_by_level2_user_name = ?,
                decision_at = ?
            WHERE id = ?
            """,
            (new_status, approved_by_level2_user_id, approved_by_level2_user_cpf_id,
             approved_by_level2_user_name, datetime.datetime.now().isoformat(), requisition_id)
        )
        db.commit()
        if cursor.rowcount == 0:
            return jsonify({"message": "Requisition not found"}), 404
        return jsonify({"message": f"Requisition {requisition_id} status updated to {new_status}"}), 200
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        db.close()

@app.route('/api/requisitions/<string:requisition_id>/pdf', methods=['GET'])
def download_requisition_pdf(requisition_id):
    """Generates and provides a PDF download for a specific requisition."""
    db = get_db()
    requisition = db.execute("SELECT * FROM requisitions WHERE id = ?", (requisition_id,)).fetchone()
    db.close()

    if not requisition:
        return jsonify({"message": "Requisition not found"}), 404

    # Create PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="User Data Requisition Form", ln=True, align="C")
    pdf.ln(10)

    # Convert row to dict for easier access (already handled by row_factory, but explicit)
    req_dict = dict(requisition)

    # Helper to add field to PDF
    def add_field(label, value):
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(0, 7, txt=f"{label}:", ln=0)
        pdf.set_font("Arial", '', 10)
        pdf.multi_cell(0, 7, txt=f"{value}", ln=True)

    add_field("Requisition ID", req_dict.get('id', 'N/A'))
    add_field("Date of Requisition", req_dict.get('requisition_date', 'N/A'))
    add_field("Basin", req_dict.get('basin', 'N/A'))
    add_field("Block", req_dict.get('block', 'N/A'))
    add_field("Area", req_dict.get('area', 'N/A'))
    add_field("2D/3D", req_dict.get('dimension', 'N/A'))
    add_field("Return Date (Data to GMS)", req_dict.get('return_date', 'N/A'))
    add_field("Type of Data Required", req_dict.get('data_type', 'N/A'))
    add_field("Objective", req_dict.get('objective', 'N/A'))
    add_field("Remarks", req_dict.get('remarks', 'N/A'))

    pdf.ln(5)
    pdf.set_font("Arial", 'BU', 12)
    pdf.cell(200, 10, txt="Requested By", ln=True, align="L")
    pdf.ln(2)

    add_field("Name", req_dict.get('user_name', 'N/A'))
    add_field("Designation", req_dict.get('user_designation', 'N/A'))
    add_field("CPF No.", req_dict.get('user_cpf_no', 'N/A'))
    add_field("Mobile No.", req_dict.get('user_mobile_no', 'N/A'))
    add_field("Group", req_dict.get('user_group', 'N/A'))

    pdf.ln(5)
    pdf.set_font("Arial", 'BU', 12)
    pdf.cell(200, 10, txt="Approval Details", ln=True, align="L")
    pdf.ln(2)

    status_display = req_dict.get('status', 'N/A').replace('_', ' ').title()
    add_field("Status", status_display)
    add_field("Approved/Denied By", req_dict.get('approved_by_level2_user_name') or req_dict.get('approved_by_level2_user_cpf_id') or 'N/A')
    add_field("Decision Date", req_dict.get('decision_at', 'N/A'))

    # Save PDF to a BytesIO object
    from io import BytesIO
    pdf_output = BytesIO()
    pdf.output(pdf_output)
    pdf_output.seek(0)

    return send_file(
        pdf_output,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"requisition_{requisition_id}.pdf"
    )

# This block ensures the Flask app runs when the script is executed
if __name__ == '__main__':
    # Use the PORT environment variable provided by Render, default to 5000 for local testing
    port = int(os.environ.get('PORT', 5000))
    # Bind to 0.0.0.0 to make the server accessible from outside localhost
    app.run(debug=False, host='0.0.0.0', port=port)
