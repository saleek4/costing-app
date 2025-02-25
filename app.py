from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import pandas as pd
import os
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests

# Configure database and JWT
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['JWT_SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
    approved = db.Column(db.Boolean, default=False)

# Create the database
with app.app_context():
    db.create_all()

# ✅ Default Home Route (Prevents 404)
@app.route('/')
def home():
    return jsonify({'message': 'Costing App is running successfully!'}), 200

# ✅ User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = generate_password_hash(data['password'], method="pbkdf2:sha256")
    new_user = User(username=data['username'], password=hashed_password, role='user', approved=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered, pending admin approval'})

# ✅ User Approval (Admin Only)
@app.route('/approve_user', methods=['POST'])
@jwt_required()
def approve_user():
    current_user = get_jwt_identity()
    admin = User.query.filter_by(username=current_user).first()

    if not admin or admin.role != 'admin':
        return jsonify({'message': 'Access Denied! Only admins can approve users.'}), 403
    
    data = request.json
    user_to_approve = User.query.filter_by(username=data['username']).first()

    if not user_to_approve:
        return jsonify({'message': 'User not found'}), 404

    user_to_approve.approved = True
    db.session.commit()
    return jsonify({'message': 'User approved successfully!'})

# ✅ User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    if not user.approved:
        return jsonify({'message': 'User not approved'}), 403
    
    access_token = create_access_token(identity=user.username)
    return jsonify({'token': access_token, 'role': user.role})

# ✅ Upload Costing Excel File (Admin Only)
@app.route('/upload_excel', methods=['POST'])
@jwt_required()
def upload_excel():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    if not user or user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    
    file = request.files.get('file')
    if file:
        file.save('costing_data.xlsx')
        return jsonify({'message': 'File uploaded successfully'})
    
    return jsonify({'message': 'No file received'}), 400

# ✅ Fetch Costing Data (Approved Users Only)
@app.route('/get_costing', methods=['GET'])
@jwt_required()
def get_costing():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if not user or not user.approved:
        return jsonify({'message': 'Access Denied!'}), 403

    excel_path = "costing_data.xlsm"

    if not os.path.exists(excel_path):
        return jsonify({'message': 'No costing data available'}), 404

    sheets = ["Sheet1", "Sheet2", "Sheet3", "Sheet4"]
    costing_data = {}

    for sheet in sheets:
        try:
            df = pd.read_excel(excel_path, sheet_name=sheet)
            costing_data[sheet] = df.to_dict(orient="records")
        except Exception as e:
            costing_data[sheet] = f"Error reading {sheet}: {str(e)}"

    return jsonify(costing_data)

# ✅ Download Costing Data
@app.route('/download_result', methods=['GET'])
@jwt_required()
def download_result():
    if not os.path.exists('costing_data.xlsx'):
        return jsonify({'message': 'No costing data available'}), 404
    return send_file('costing_data.xlsx', as_attachment=True)

# ✅ Run the Flask App with Gunicorn (Render Deployment)
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))  # Render sets PORT automatically
    app.run(host="0.0.0.0", port=port, debug=True)
