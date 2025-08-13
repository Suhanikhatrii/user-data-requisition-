import os
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import uuid
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from fpdf import FPDF
import psycopg2
from psycopg2 import sql
import psycopg2.extras # Needed for DictCursor

app = Flask(__name__)
# IMPORTANT: For production, replace "*" with your Render frontend URL (e.g., "https://your-frontend.onrender.com")
CORS(app, resources={r"/api/*": {"origins": "*"}})

# --- DATABASE CONFIGURATION FOR POSTGRESQL ---
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    """Establishes a PostgreSQL database connection."""
    if not DATABASE_URL:
        raise Exception("DATABASE_URL environment variable is not set.")
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    """Initializes the database schema for PostgreSQL."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Create users table (email column removed)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id VARCHAR(255) PRIMARY KEY,
                cpf_id VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(255),
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(255) NOT NULL,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                created_by VARCHAR(255)
            )
        ''')
        # Create requisitions table - ADDED 'title' and 'description' back
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS requisitions (
                id VARCHAR(255) PRIMARY KEY,
                title TEXT, -- Added back
                description TEXT, -- Added back
                requisition_date DATE,
                basin VARCHAR(255),
                block VARCHAR(255),
                area VARCHAR(255),
                dimension VARCHAR(255),
                return_date DATE,
                data_type TEXT,
                objective TEXT,
                remarks TEXT,
                user_name VARCHAR(255),
                user_designation VARCHAR(255),
                user_cpf_no VARCHAR(255),
                user_mobile_no VARCHAR(255),
                user_group VARCHAR(255),
                requested_by_user_id VARCHAR(255),
                requested_by_user_cpf_id VARCHAR(255),
                status VARCHAR(255) NOT NULL,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                approved_by_level2_user_id VARCHAR(255),
                approved_by_level2_user_cpf_id VARCHAR(255),
                approved_by_level2_user_name VARCHAR(255),
                decision_at TIMESTAMP WITHOUT TIME ZONE
            )
        ''')
        conn.commit()

        # Add a default admin user if one doesn't exist
        cursor.execute("SELECT id FROM users WHERE cpf_id = 'admin123'")
        if cursor.fetchone() is None:
            admin_id = str(uuid.uuid4())
            hashed_password = generate_password_hash('password123')
            # Insert statement adjusted: email field removed
            cursor.execute(
                """INSERT INTO users (id, cpf_id, name, password_hash, role, created_by)
                VALUES (%s, %s, %s, %s, %s, %s)""",
                (admin_id, 'admin123', 'Admin User', hashed_password, 'admin', 'system')
            )
            conn.commit()
            print("Default admin user created: CPF ID: admin123 / Password: password123")
    except psycopg2.Error as e:
        print(f"Database initialization error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

with app.app_context():
    init_db()

@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Welcome to the Flask API!"}), 200

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    cpf_id = data.get('cpfId')
    password = data.get('password')

    if not cpf_id or not password:
        return jsonify({"message": "CPF ID and password are required"}), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("SELECT id, cpf_id, name, role, password_hash FROM users WHERE cpf_id = %s", (cpf_id,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            return jsonify({
                "message": "Login successful",
                "cpfId": user['cpf_id'],
                "uid": user['id'],
                "name": user['name'],
                "role": user['role']
            }), 200
        else:
            return jsonify({"message": "Invalid CPF ID or password"}), 401
    except psycopg2.Error as e:
        return jsonify({"message": f"Database error during login: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json()
    name = data.get('name')
    cpf_id = data.get('cpfId')
    password = data.get('password')
    role = data.get('role')
    created_by = data.get('createdBy', 'unknown')

    if not all([name, cpf_id, password, role]):
        return jsonify({"message": "Name, CPF ID, password, and role are required"}), 400

    if len(password) < 6:
        return jsonify({"message": "Password must be at least 6 characters long"}), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE cpf_id = %s", (cpf_id,))
        if cursor.fetchone():
            return jsonify({"message": "User with this CPF ID already exists"}), 409

        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)

        cursor.execute(
            """INSERT INTO users (id, cpf_id, name, password_hash, role, created_by)
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (user_id, cpf_id, name, hashed_password, role, created_by)
        )
        conn.commit()
        return jsonify({"message": "User registered successfully", "userId": user_id}), 201
    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/users', methods=['GET'])
def get_users():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("SELECT id, cpf_id, name, role, created_at, created_by FROM users ORDER BY created_at DESC")
        users = cursor.fetchall()
        return jsonify([dict(user) for user in users]), 200
    except psycopg2.Error as e:
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/users/<user_id>/password', methods=['PUT'])
def change_password(user_id):
    data = request.get_json()
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')

    if not current_password or not new_password:
        return jsonify({"message": "Current and new passwords are required"}), 400
    
    if len(new_password) < 6:
        return jsonify({"message": "New password must be at least 6 characters long"}), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"message": "User not found"}), 404

        if not check_password_hash(user['password_hash'], current_password):
            return jsonify({"message": "Incorrect current password"}), 401
        
        if check_password_hash(user['password_hash'], new_password):
            return jsonify({"message": "New password cannot be the same as current password"}), 400

        hashed_new_password = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed_new_password, user_id))
        conn.commit()
        return jsonify({"message": "Password changed successfully"}), 200
    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/requisitions', methods=['POST'])
def create_requisition():
    data = request.get_json()

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
        'status': 'pending_level2',
        'created_at': datetime.datetime.now(),
        # Generate title and description from existing fields if not directly provided
        'title': data.get('title', f"Requisition for {data.get('basin')} - {data.get('area') or 'N/A'}"), # Ensure title exists
        'description': data.get('description', data.get('objective')) # Ensure description exists
    }

    mandatory_fields = ['basin', 'user_cpf_no', 'user_mobile_no', 'user_group']
    for field in mandatory_fields:
        if not requisition_data.get(field):
            return jsonify({"message": f"Mandatory field '{field.replace('_', ' ').capitalize()}' is missing"}), 400

    req_id = str(uuid.uuid4())
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # INSERT statement now includes 'title' and 'description'
        cursor.execute(
            """
            INSERT INTO requisitions (
                id, title, description, requisition_date, basin, block, area, dimension, return_date,
                data_type, objective, remarks, user_name, user_designation,
                user_cpf_no, user_mobile_no, user_group, requested_by_user_id,
                requested_by_user_cpf_id, status, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                req_id, requisition_data['title'], requisition_data['description'], # Included title and description
                requisition_data['requisition_date'], requisition_data['basin'],
                requisition_data['block'], requisition_data['area'], requisition_data['dimension'],
                requisition_data['return_date'], requisition_data['data_type'],
                requisition_data['objective'], requisition_data['remarks'],
                requisition_data['user_name'], requisition_data['user_designation'],
                requisition_data['user_cpf_no'], requisition_data['user_mobile_no'],
                requisition_data['user_group'], requisition_data['requested_by_user_id'],
                requisition_data['requested_by_user_cpf_id'], requisition_data['status'],
                requisition_data['created_at']
            )
        )
        conn.commit()
        return jsonify({"message": "Requisition created successfully", "id": req_id}), 201
    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/requisitions', methods=['GET'])
def get_requisitions():
    status_filter = request.args.get('status')
    user_id_filter = request.args.get('userId')
    basin_filter = request.args.get('basin')
    user_group_filter = request.args.get('userGroup')

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        query_parts = ["SELECT * FROM requisitions WHERE 1=1"]
        params = []

        if status_filter:
            query_parts.append(" AND status = %s")
            params.append(status_filter)
        if user_id_filter:
            query_parts.append(" AND requested_by_user_id = %s")
            params.append(user_id_filter)
        if basin_filter:
            query_parts.append(" AND basin ILIKE %s")
            params.append(f"%{basin_filter}%")
        if user_group_filter:
            query_parts.append(" AND user_group ILIKE %s")
            params.append(f"%{user_group_filter}%")

        query_parts.append(" ORDER BY created_at DESC")
        
        query_str = " ".join(query_parts)
        cursor.execute(query_str, params)
        requisitions = cursor.fetchall()
        
        result_list = []
        for req in requisitions:
            req_dict = dict(req)
            if 'created_at' in req_dict and isinstance(req_dict['created_at'], datetime.datetime):
                req_dict['created_at'] = req_dict['created_at'].isoformat()
            if 'decision_at' in req_dict and isinstance(req_dict['decision_at'], datetime.datetime):
                req_dict['decision_at'] = req_dict['decision_at'].isoformat()
            result_list.append(req_dict)

        return jsonify(result_list), 200
    except psycopg2.Error as e:
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/requisitions/<string:requisition_id>', methods=['PUT'])
def update_requisition_status(requisition_id):
    data = request.get_json()
    new_status = data.get('status')
    approved_by_level2_user_id = data.get('approvedByLevel2UserId')
    approved_by_level2_user_cpf_id = data.get('approvedByLevel2UserCpfId')
    approved_by_level2_user_name = data.get('approvedByLevel2UserName')

    if not new_status:
        return jsonify({"message": "New status is required"}), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        decision_timestamp = datetime.datetime.now()

        cursor.execute(
            """
            UPDATE requisitions
            SET status = %s,
                approved_by_level2_user_id = %s,
                approved_by_level2_user_cpf_id = %s,
                approved_by_level2_user_name = %s,
                decision_at = %s
            WHERE id = %s
            """,
            (new_status, approved_by_level2_user_id, approved_by_level2_user_cpf_id,
             approved_by_level2_user_name, decision_timestamp, requisition_id)
        )
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"message": "Requisition not found"}), 404
        return jsonify({"message": f"Requisition {requisition_id} status updated to {new_status}"}), 200
    except psycopg2.Error as e:
        if conn:
            conn.rollback()
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/requisitions/<string:requisition_id>/pdf', methods=['GET'])
def download_requisition_pdf(requisition_id):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("SELECT * FROM requisitions WHERE id = %s", (requisition_id,))
        requisition = cursor.fetchone()

        if not requisition:
            return jsonify({"message": "Requisition not found"}), 404

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        pdf.cell(200, 10, txt="User Data Requisition Form", ln=True, align="C")
        pdf.ln(10)

        req_dict = dict(requisition)

        def add_field(label, value):
            display_value = value.isoformat() if isinstance(value, datetime.datetime) else str(value)
            pdf.set_font("Arial", 'B', 10)
            pdf.cell(0, 7, txt=f"{label}:", ln=0)
            pdf.set_font("Arial", '', 10)
            pdf.multi_cell(0, 7, txt=f"{display_value}", ln=True)

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
    except psycopg2.Error as e:
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
