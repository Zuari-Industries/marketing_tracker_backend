import os
import io
import csv
from flask import Flask, request, jsonify,Response,url_for # type: ignore
from flask_sqlalchemy import SQLAlchemy # type: ignore
from flask_cors import CORS # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore
from datetime import datetime, date, timedelta
from flask_socketio import SocketIO # type: ignore
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager # type: ignore
from urllib.parse import urlencode
import jwt as pyjwt  # type: ignore
from datetime import timedelta
from itsdangerous import URLSafeTimedSerializer,SignatureExpired, BadSignature # type: ignore
import smtplib
from email.message import EmailMessage
from flask_mail import Mail, Message # type: ignore
from dotenv import load_dotenv # type: ignore
from flask_bcrypt import Bcrypt # type: ignore
from sqlalchemy import event # type: ignore


# Load environment variables
load_dotenv()

# Initialize Flask App
app = Flask(__name__)
CORS(app)

# --- JWT CONFIG ---
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-secret-key-change-in-prod")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)

# --- PASSWORD RESET CONFIG ---
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT", 587))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER", app.config['MAIL_USERNAME'])

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['MAIL_PASSWORD'])
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# --- Database Configuration (SQLite only) ---
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, "instance")
os.makedirs(instance_path, exist_ok=True)

# Use DATABASE_URL if present, otherwise fallback to SQLite
db_url = os.getenv(
    "DATABASE_URL", 
    "sqlite:///" + os.path.join(instance_path, "marketing_hub.db")
)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


allowed_origins = [
    "http://localhost:5173",                 # Vite dev
    "https://marketing-tracker-frontend-um49.vercel.app/",    # Vercel preview/prod
    # "https://your-custom-domain.com",       # if/when you add a custom domain
]

CORS(
    app,
    resources={r"/*": {"origins": allowed_origins}},
    supports_credentials=False   # keep False since you're using JWT in headers
)

# For Socket.IO
socketio = SocketIO(app, cors_allowed_origins=allowed_origins)


# --- SQLite WAL mode for better concurrency ---
if db_url.startswith("sqlite"):
    with app.app_context():
        @event.listens_for(db.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, _):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.close()
# --- Database Models (Schema) ---
class User(db.Model):
    """User Model"""
    __tablename__ = '"user"'  # double quotes for Postgres reserved keyword

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(50), nullable=False, default='User')
    business_unit = db.Column(db.String(100))
    joined_date = db.Column(db.DateTime, default=datetime.utcnow)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id, 'name': self.name, 'email': self.email, 'role': self.role,
            'businessUnit': self.business_unit,
            'joined': self.joined_date.strftime('%d/%m/%Y') if self.joined_date else None
        }

class Request(db.Model):
    """Marketing Request Model"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='Not Started')
    priority = db.Column(db.String(50), default='Medium')
    due_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(100), nullable=True)
    business_unit = db.Column(db.String(100), nullable=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    requester = db.relationship('User', foreign_keys=[created_by_id], backref='created_requests')
    assignee = db.relationship('User', foreign_keys=[assigned_to_id], backref='assigned_requests')

    def to_dict(self):
        return {
            'id': self.id, 'title': self.title, 'description': self.description,
            'status': self.status, 'priority': self.priority,
            'dueDate': self.due_date.strftime('%Y-%m-%d') if self.due_date else None,
            'createdAt': self.created_at.strftime('%Y-%m-%d') if self.created_at else None,
            'requester': self.requester.name if self.requester else None,
            'assignee': self.assignee.name if self.assignee else 'Unassigned',
            'type': self.type,
            'businessUnit': self.business_unit,
            'subtasks': [subtask.to_dict() for subtask in self.subtasks]
        }

class Subtask(db.Model):
    """Subtask Model"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Not Started')
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)

    request = db.relationship('Request', backref=db.backref('subtasks', lazy=True, cascade="all, delete-orphan"))
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'status': self.status,
            'startDate': self.start_date.strftime('%Y-%m-%d') if self.start_date else None,
            'endDate': self.end_date.strftime('%Y-%m-%d') if self.end_date else None,
            'requestId': self.request_id
        }

# --- ADD THIS ENTIRE NEW MODEL ---
class SubtaskTemplate(db.Model):
    """Subtask Template Model"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    request_type = db.Column(db.String(100), nullable=False) # e.g., 'Creative', 'Campaign'
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'requestType': self.request_type
        }

class Comment(db.Model):
    """Comment Model"""
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_internal = db.Column(db.Boolean, default=False)
    type = db.Column(db.String(50), default='General') # General or ActionRequired
    action_status = db.Column(db.String(50), nullable=True) # Pending, Approved, Rejected
    
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # --- ADD THESE TWO LINES ---
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy='joined', cascade="all, delete-orphan")
    request = db.relationship('Request', backref=db.backref('comments', lazy=True, cascade="all, delete-orphan"))
    user = db.relationship('User', backref='comments')

    def to_dict(self):
        return {
            'id': self.id, 'text': self.text, 'isInternal': self.is_internal,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'type': self.type, 'actionStatus': self.action_status,
            'userName': self.user.name if self.user else None,
            'parentId': self.parent_id, # ADD THIS LINE
            'replies': [reply.to_dict() for reply in self.replies]
        }

class ActivityLog(db.Model):
    """Activity Log Model for History"""
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    request = db.relationship('Request', backref=db.backref('history_logs', lazy=True, cascade="all, delete-orphan"))
    user = db.relationship('User', backref='activity_logs')
    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'userName': self.user.name if self.user else None
        }
    
class Notification(db.Model):
    """Notification Model"""
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref='notifications')

    def to_dict(self):
        return {
            'id': self.id,
            'message': self.message,
            'isRead': self.is_read,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }

class FormField(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group = db.Column(db.String(100), nullable=False)
    label = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), unique=True, nullable=False)
    type = db.Column(db.String(50), nullable=False)
    options = db.Column(db.Text, nullable=True)
    placeholder = db.Column(db.String(200), nullable=True)
    required = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True)
    help_text = db.Column(db.String(255), nullable=True) 
    depends_on_field_name = db.Column(db.String(100), nullable=True)
    depends_on_field_value = db.Column(db.String(255), nullable=True)

    def to_dict(self):
        return {
            'id': self.id, 'group': self.group, 'label': self.label, 'name': self.name,
            'type': self.type, 'options': self.options, 'placeholder': self.placeholder,
            'required': self.required, 'active': self.active,'helpText': self.help_text,
            'dependsOnFieldName': self.depends_on_field_name,
            'dependsOnFieldValue': self.depends_on_field_value
        }
    
# --- API Routes ---
@app.route('/api/test', methods=['GET'])
def test_route():
    """A simple test route to confirm the server is running."""
    return jsonify({'message': 'Backend is connected and running!'}), 200

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()

    if not user or not user.check_password(data.get('password')):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    access_token = create_access_token(identity=str(user.id))

    return jsonify({
        'message': 'Login successful', 
        'user': user.to_dict(), 
        'access_token': access_token
    }), 200

@app.route('/api/profile', methods=['GET'])
@jwt_required() 
def profile():
    current_user_id = get_jwt_identity()
    
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    return jsonify(user.to_dict()), 200

@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json
    email = data.get("email")

    token = serializer.dumps(email, salt="reset-password")

    reset_url = url_for("reset_password", token=token, _external=True)

    try:
        msg = Message("Password Reset Request", recipients=[email])
        msg.body = f"Click the link to reset your password: {reset_url}\n\nThis link is valid for 15 minutes."
        mail.send(msg)
        return jsonify({"message": "Reset link sent to your email"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reset-password/<token>", methods=["POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="reset-password", max_age=3600)  # 1 hr
    except (SignatureExpired, BadSignature):
        return jsonify({"message": "Invalid/Expired token"}), 400

    data = request.get_json()
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    user.password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    db.session.commit()
    return jsonify({"message": "Password reset successful!"})

@app.route('/api/dashboard-stats', methods=['GET'])
def get_dashboard_stats():
    """Endpoint to get stats. Can be filtered by userId."""
    user_id = request.args.get('userId', type=int)
    
    query = Request.query
    if user_id:
        query = query.filter_by(created_by_id=user_id)

    total_requests = query.count()
    in_progress = query.filter_by(status='In Progress').count()
    completed = query.filter_by(status='Completed').count()

    stats = {
        'totalRequests': total_requests,
        'inProgress': in_progress,
        'completed': completed
    }
    return jsonify(stats), 200
    
@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([user.to_dict() for user in users]), 200

@app.route('/api/users', methods=['POST'])
def create_user():
    """Endpoint for a SuperAdmin to create a new user."""
    data = request.get_json()
    if not all(k in data for k in ['email', 'name', 'role', 'password']):
        return jsonify({'message': 'Missing required fields'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'User with this email already exists'}), 409

    new_user = User(
        name=data['name'],
        email=data['email'],
        role=data.get('role', 'User'),
        business_unit=data.get('businessUnit')
    )
    new_user.set_password(data['password'])
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify(new_user.to_dict()), 201 

@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    """Endpoint to update a user's details."""
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    if 'name' in data:
        user.name = data['name']
    if 'role' in data:
        user.role = data['role']
    if 'businessUnit' in data:
        user.business_unit = data['businessUnit']
    if 'password' in data and data['password']:
        user.set_password(data['password'])
    
    db.session.commit()
    return jsonify(user.to_dict()), 200

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Endpoint to delete a user."""
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'}), 200

@app.route('/api/requests', methods=['GET'])
def get_requests():
    requests = Request.query.order_by(Request.created_at.desc()).all()
    return jsonify([req.to_dict() for req in requests]), 200

@app.route('/api/requests', methods=['POST'])
def create_request():
    """Endpoint to create a new marketing request."""
    data = request.get_json()
    if not data or not data.get('title') or not data.get('userId'):
        return jsonify({'message': 'Missing required fields'}), 400
    creator_id = data['userId']
    creator = User.query.get(creator_id)
    if not creator:
        return jsonify({'message': 'User not found'}), 404
    if data.get('dueDate'):
        try:
            due_date_obj = datetime.strptime(data['dueDate'], '%Y-%m-%d').date()
        except (ValueError, TypeError):
            pass
    new_request = Request(
        title=data.get('title'),
        description=data.get('description'),
        status='Not Started',
        priority=data.get('priority', 'Medium'),
        due_date=due_date_obj,
        created_by_id=creator_id,
        type=data.get('type'),
        business_unit=data.get('businessUnit') 
    )
    db.session.add(new_request)
    db.session.commit()
    # --- ADD THIS LOGIC BLOCK ---
    # Auto-add subtasks from templates
    if new_request.type:
        templates = SubtaskTemplate.query.filter_by(request_type=new_request.type).all()
        for template in templates:
            new_subtask = Subtask(
                title=template.title,
                status='Not Started',
                request_id=new_request.id,
                # start_date and end_date are intentionally left NULL
            )
            db.session.add(new_subtask)
    # --- END OF NEW LOGIC ---

    db.session.commit() # Commit again to save the new subtasks

    # NOTIFICATION LOGIC
    notification_message = f"New task '{new_request.title}' created by {creator.name}."
    socketio.emit('new_task_notification', {'message': notification_message})
    try:
        super_admins = User.query.filter_by(role='SuperAdmin').all()
        for admin in super_admins:
            notification = Notification(message=notification_message, user_id=admin.id)
            db.session.add(notification)
        db.session.commit()
    except Exception as e:
        print(f"Error saving notification to DB: {e}")

    print(f"--- EMITTED & SAVED NOTIFICATION: {notification_message} ---")
    return jsonify(new_request.to_dict()), 201

@app.route('/api/requests/<int:request_id>', methods=['DELETE'])
def delete_request(request_id):
    """Endpoint to delete a single request."""
    request_to_delete = Request.query.get_or_404(request_id)
    db.session.delete(request_to_delete)
    db.session.commit()
    
    return jsonify({'message': 'Request deleted successfully'}), 200

@app.route('/api/requests/<int:request_id>', methods=['PUT'])
def update_request(request_id):
    """Endpoint to update an existing request."""
    req = Request.query.get_or_404(request_id)
    data = request.get_json()
    req.title = data.get('title', req.title)
    req.status = data.get('status', req.status)
    req.priority = data.get('priority', req.priority)
    
    
    if 'assigneeId' in data:
        assignee_id = data.get('assigneeId')
        req.assigned_to_id = int(assignee_id) if assignee_id else None

    db.session.commit()
    return jsonify(req.to_dict()), 200

@app.route('/api/requests/<int:request_id>/subtasks', methods=['GET'])
def get_subtasks(request_id):
    """Endpoint to get all subtasks for a specific request."""
    req = Request.query.get_or_404(request_id)
    return jsonify([subtask.to_dict() for subtask in req.subtasks])

@app.route('/api/requests/<int:request_id>/subtasks', methods=['POST'])
def create_subtask(request_id):
    """Endpoint to create a new subtask for a specific request."""
    req = Request.query.get_or_404(request_id)
    data = request.get_json()

    if not data or not data.get('title'):
        return jsonify({'message': 'Title is required'}), 400

    start_date = datetime.strptime(data['startDate'], '%Y-%m-%d').date() if data.get('startDate') else None
    end_date = datetime.strptime(data['endDate'], '%Y-%m-%d').date() if data.get('endDate') else None

    new_subtask = Subtask(
        title=data['title'],
        status=data.get('status', 'Not Started'),
        start_date=start_date,
        end_date=end_date,
        request=req
    )
    db.session.add(new_subtask)
    db.session.commit()
    try:
        admin_user = User.query.get(2) 
        if admin_user:
            new_log = ActivityLog(
                action=f"created a new subtask: '{new_subtask.title}'",
                request_id=req.id,
                user_id=admin_user.id
            )
            db.session.add(new_log)
            db.session.commit()
    except Exception as e:
        print(f"Error creating activity log for subtask: {e}")

    return jsonify(new_subtask.to_dict()), 201

@app.route('/api/subtasks/<int:subtask_id>', methods=['DELETE'])
def delete_subtask(subtask_id):
    """Endpoint to delete a subtask."""
    subtask = Subtask.query.get_or_404(subtask_id)
    db.session.delete(subtask)
    db.session.commit()
    return jsonify({'message': 'Subtask deleted successfully'}), 200\

@app.route('/api/subtasks/<int:subtask_id>', methods=['PUT'])
def update_subtask(subtask_id):
    """Endpoint to update a subtask's details (status, dates, etc.)."""
    subtask = Subtask.query.get_or_404(subtask_id)
    data = request.get_json()

    # Update status if provided
    if 'status' in data:
        subtask.status = data['status']
    
    # Update dates if provided
    if data.get('startDate'):
        subtask.start_date = datetime.strptime(data['startDate'], '%Y-%m-%d').date()
    if data.get('endDate'):
        subtask.end_date = datetime.strptime(data['endDate'], '%Y-%m-%d').date()
        
    db.session.commit()
    # ... (activity log logic can be added here if needed) ...
    return jsonify(subtask.to_dict()), 200

@app.route('/api/requests/<int:request_id>/comments', methods=['GET'])
def get_comments(request_id):
    """Endpoint to get all comments for a specific request."""
    if not Request.query.get(request_id):
        return jsonify({'message': 'Request not found'}), 404
        
    top_level_comments = Comment.query.filter_by(
        request_id=request_id, 
        parent_id=None
    ).order_by(Comment.timestamp.asc()).all()
    
    return jsonify([comment.to_dict() for comment in top_level_comments])

# Purane add_comment function ko isse replace karein
@app.route('/api/requests/<int:request_id>/comments', methods=['POST'])
def add_comment(request_id):
    """Endpoint to add a new comment to a request."""
    req = Request.query.get_or_404(request_id)
    data = request.get_json()
    
    # Ab yeh frontend se userId lega
    if not data or not data.get('text') or not data.get('userId'):
        return jsonify({'message': 'Missing required fields for comment'}), 400
    
    user_id = data['userId']
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    new_comment = Comment(
        text=data['text'],
        is_internal=data.get('isInternal', False),
        type=data.get('type', 'General'),
        action_status='Pending' if data.get('type') == 'ActionRequired' else None,
        request=req,
        user_id=user_id,
        parent_id=data.get('parentId') # Hardcoded ID hata di gayi hai
    )
    db.session.add(new_comment)
    db.session.commit()
    return jsonify(new_comment.to_dict()), 201

@app.route('/api/comments/<int:comment_id>/action', methods=['PUT'])
def update_comment_action(comment_id):
    """Endpoint to update the action status of a comment."""
    comment = Comment.query.get_or_404(comment_id)
    data = request.get_json()
    if not data or not data.get('actionStatus'):
        return jsonify({'message': 'Action status is required'}), 400
    
    comment.action_status = data['actionStatus']
    db.session.commit()
    return jsonify(comment.to_dict()), 200

@app.route('/api/requests/<int:request_id>/history', methods=['GET'])
def get_history(request_id):
    """Endpoint to get all history logs for a specific request."""
    req = Request.query.get_or_404(request_id)
    return jsonify([log.to_dict() for log in req.history_logs])

@app.route('/api/requests/export', methods=['GET'])
def export_requests():
    """Endpoint to export all requests to a CSV file."""
    requests = Request.query.all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    headers = ['id', 'title', 'status', 'priority', 'requester', 'assignee', 'dueDate', 'type', 'businessUnit']
    writer.writerow(headers)
    for req in requests:
        writer.writerow([
            req.id,
            req.title,
            req.status,
            req.priority,
            req.requester.name if req.requester else '',
            req.assignee.name if req.assignee else '', 
            req.due_date.strftime('%Y-%m-%d') if req.due_date else '',
            req.type,
            req.business_unit
        ])
    
    output.seek(0)
    
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=requests_export.csv"}
    )
@app.route('/api/requests/import', methods=['POST'])
def import_requests():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    if file and file.filename.endswith('.csv'):
        try:
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_reader = csv.DictReader(stream)
            
            for row in csv_reader:
                requester = User.query.filter_by(name=row.get('requester')).first()
                if not requester:
                    continue 

                new_request = Request(
                    title=row.get('title'),
                    status=row.get('status', 'Not Started'),
                    priority=row.get('priority', 'Medium'),
                    due_date=datetime.strptime(row['dueDate'], '%Y-%m-%d').date() if row.get('dueDate') else None,
                    type=row.get('type'),
                    business_unit=row.get('businessUnit'),
                    created_by_id=requester.id
                )
                db.session.add(new_request)
                
            db.session.commit()
            return jsonify({'message': 'File imported successfully'}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': f'An error occurred: {str(e)}'}), 500

    return jsonify({'message': 'Invalid file type. Please upload a CSV.'}), 400

@app.route('/api/notifications', methods=['GET'])
def get_notifications():
    """Endpoint to get notifications for a specific user."""
    # Get the user ID from the request's query parameters (e.g., /api/notifications?userId=1)
    user_id = request.args.get('userId')
    if not user_id:
        return jsonify({'message': 'User ID is required'}), 400

    notifications = Notification.query.filter_by(user_id=user_id, is_read=False).order_by(Notification.timestamp.desc()).all()
    return jsonify([n.to_dict() for n in notifications])
@app.route('/api/notifications/<int:notification_id>/read', methods=['PUT'])
def mark_notification_as_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    notification.is_read = True
    db.session.commit()
    return jsonify({'message': 'Notification marked as read'}), 200

@app.route('/api/form-fields', methods=['GET'])
def get_form_fields():
    fields = FormField.query.order_by(FormField.id).all()
    return jsonify([field.to_dict() for field in fields])


@app.route('/api/form-fields', methods=['POST'])
def add_form_field():
    data = request.get_json()
    if FormField.query.filter_by(name=data['name']).first():
        return jsonify({'message': f"A field with the name '{data['name']}' already exists. Please use a unique name."}), 409
    new_field = FormField(
        group=data['group'], label=data['label'], name=data['name'],
        type=data['type'], options=data.get('options'),
        placeholder=data.get('placeholder'), required=data.get('required', False),
        depends_on_field_name=data.get('dependsOnFieldName'),
        depends_on_field_value=data.get('dependsOnFieldValue')
    )
    db.session.add(new_field)
    db.session.commit()
    return jsonify(new_field.to_dict()), 201

@app.route('/api/form-fields/<int:field_id>', methods=['PUT'])
def update_form_field(field_id):
    """Endpoint to update an existing form field."""
    field = FormField.query.get_or_404(field_id)
    data = request.get_json()
    field.group = data.get('group', field.group)
    field.label = data.get('label', field.label)
    field.name = data.get('name', field.name)
    field.type = data.get('type', field.type)
    field.options = data.get('options', field.options)
    field.placeholder = data.get('placeholder', field.placeholder)
    field.help_text = data.get('helpText', field.help_text)
    field.required = data.get('required', field.required)
    field.active = data.get('active', field.active)
    field.depends_on_field_name = data.get('dependsOnFieldName')
    field.depends_on_field_value = data.get('dependsOnFieldValue')
    
    db.session.commit()
    return jsonify(field.to_dict()), 200

@app.route('/api/form-fields/<int:field_id>', methods=['DELETE'])
def delete_form_field(field_id):
    """Endpoint to delete a form field."""
    field = FormField.query.get_or_404(field_id)
    
    db.session.delete(field)
    db.session.commit()
    
    return jsonify({'message': 'Form field deleted successfully'}), 200

@app.route('/api/workload', methods=['GET'])
def get_workload():
    """Endpoint to get all users and their task workload."""
    try:
        users = User.query.all()
        workload_data = []

        for user in users:
            user_dict = user.to_dict()
            assigned_tasks = Request.query.filter_by(assigned_to_id=user.id).all()
            active_count = sum(1 for task in assigned_tasks if task.status != 'Completed')
            completed_count = sum(1 for task in assigned_tasks if task.status == 'Completed')
            
            user_dict['workload'] = {
                'active': active_count,
                'completed': completed_count,
                'total': len(assigned_tasks)
            }
            workload_data.append(user_dict)
            
        return jsonify(workload_data), 200
    except Exception as e:
        return jsonify({'message': f'An error occurred: {str(e)}'}), 500
    # --- ADD THESE 3 NEW ROUTES ---
@app.route('/api/subtask-templates', methods=['GET'])
@jwt_required()
def get_subtask_templates():
    templates = SubtaskTemplate.query.all()
    return jsonify([template.to_dict() for template in templates])

@app.route('/api/subtask-templates', methods=['POST'])
@jwt_required()
def add_subtask_template():
    data = request.get_json()
    if not data or not data.get('title') or not data.get('requestType'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    new_template = SubtaskTemplate(
        title=data['title'],
        request_type=data['requestType']
    )
    db.session.add(new_template)
    db.session.commit()
    return jsonify(new_template.to_dict()), 201

@app.route('/api/subtask-templates/<int:template_id>', methods=['DELETE'])
@jwt_required()
def delete_subtask_template(template_id):
    template = SubtaskTemplate.query.get_or_404(template_id)
    db.session.delete(template)
    db.session.commit()
    return jsonify({'message': 'Template deleted successfully'}), 200
# --- CLI Command ---

@app.cli.command('init-db')
def init_db_command():
    """Creates and seeds the database with all user roles."""
    with app.app_context():
        db.drop_all()
        db.create_all()
        print('Initialized the database.')

        users_to_add = [
            {'name': 'Alex Johnson', 'email': 'superadmin@demo.com', 'role': 'SuperAdmin', 'business_unit': 'Strategy'},
            {'name': 'Maria Garcia', 'email': 'admin@demo.com', 'role': 'Admin', 'business_unit': 'Marketing'},
            {'name': 'John Doe', 'email': 'user@demo.com', 'role': 'User', 'business_unit': 'Infra'},
            {'name': 'Jane Smith', 'email': 'viewer@demo.com', 'role': 'Viewer', 'business_unit': 'Snackpure'}
        ]

        for user_data in users_to_add:
            if not User.query.filter_by(email=user_data['email']).first():
                print(f"Creating default {user_data['role']}...")
                user = User(name=user_data['name'], email=user_data['email'], role=user_data['role'], business_unit=user_data['business_unit'])
                user.set_password('password')
                db.session.add(user)
        
        db.session.commit()
        print('Default users created.')

        if Request.query.count() == 0:
            print('Seeding sample requests...')
            user_john = User.query.filter_by(email='user@demo.com').first()
            admin_maria = User.query.filter_by(email='admin@demo.com').first()
            
            if user_john and admin_maria:
                task1 = Request(title='Q3 Social Media Campaign', status='In Progress', due_date=date(2025, 8, 15), requester=user_john, type='Campaign', business_unit='Snackpure')
                task2 = Request(title='Website SEO Audit', status='Completed', due_date=date(2025, 7, 20), requester=admin_maria, type='Creative', business_unit='Infra')
                task3 = Request(title='New Blog Post Idea', status='Not Started', due_date=date(2025, 9, 5), requester=user_john, type='Social Post', business_unit='Infra')
                db.session.add_all([task1, task2, task3])
                db.session.commit()
                print('Sample requests seeded.')
        if FormField.query.count() == 0:
            print('Seeding default form fields...')
            default_fields = [
                # Basic Information
                FormField(group='Basic Information', label='Request Title', name='title', type='text', placeholder='Enter a descriptive title for your request', required=True, active=True),
                FormField(group='Basic Information', label='Request Type', name='type', type='select', options='Creative,Campaign,Social Post,Event', placeholder='Select the type of request', required=True, active=True),
                FormField(group='Basic Information', label='Business Unit', name='businessUnit', type='select', options='Infra,Snackpure,Marketing,Strategy', placeholder='Select the business unit', required=True, active=True),
                
                # Project Details
                FormField(group='Project Details', label='Project Brief', name='description', type='textarea', placeholder='Provide a detailed description of your request', help_text='Be specific about what you need', required=True, active=True),
                FormField(group='Project Details', label='Objectives / Expected Outcome', name='objectives', type='textarea', placeholder='What do you want to achieve with this task?', required=False, active=True),
                FormField(group='Project Details', label='Target Audience', name='targetAudience', type='text', placeholder='Who is the target audience?', required=False, active=True),
                FormField(group='Project Details', label='Key Message or CTA', name='keyMessage', type='text', placeholder='What is your main message or call-to-action?', required=False, active=True),

                # Logistics
                FormField(group='Logistics', label='Budget', name='budget', type='text', placeholder='Budget range or amount', required=False, active=True),
                FormField(group='Logistics', label='Target Completion Date', name='dueDate', type='date', placeholder='dd-mm-yyyy', required=False, active=True),
                FormField(group='Logistics', label='Work Approver', name='workApprover', type='text', placeholder='Who will approve this work?', required=False, active=True),
                
                # System Fields
                FormField(group='System Fields', label='Priority', name='priority', type='select', options='High,Medium,Low', required=True, active=True),
            ]
            db.session.bulk_save_objects(default_fields)
            db.session.commit()
            print('Default form fields seeded.')
    print('Database initialization complete.')

if __name__ == "__main__":
    # Only use db.create_all() locally, not in production
    import os
    if os.getenv("FLASK_ENV") == "development":
        with app.app_context():
            db.create_all()
    socketio.run(app, debug=os.getenv("FLASK_ENV") == "development")

