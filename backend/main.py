# 專案管理系統 - Python Flask 後端 (完整功能版)
# 檔案名稱: main.py

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
import uuid as py_uuid
from datetime import datetime, timezone, timedelta
import os
import logging
import jwt
from functools import wraps

app = Flask(__name__)
bcrypt = Bcrypt(app)

# --- 設定 ---
# ！！！生產環境中，強烈建議透過環境變數設定以下敏感資訊！！！
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_strong_and_random_secret_key_for_jwt_!@#$%%CHANGE_ME_IMMEDIATELY') 
DATABASE_URL = os.environ.get(
    'DATABASE_URL', 
    'postgresql://pm_user:12345@192.168.2.140:5432/project_management_db' # 請確認此連線字串的準確性
)

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)
app.logger.info(f"正在使用的資料庫 URL (DATABASE_URL): {DATABASE_URL}")

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = os.environ.get('SQLALCHEMY_ECHO', 'False').lower() == 'true' # 透過環境變數控制是否顯示 SQL log

db = SQLAlchemy(app)
# 調整 CORS 設定以允許來自特定前端網域的請求，或在開發時設為 "*"
# 例如: origins=["http://localhost:8080", "https://pmt.thm.com.tw"]
CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": "*"}}) 

# --- 輔助表格：使用者與群組的多對多關聯 ---
user_groups_table = db.Table('user_groups', # 更明確的命名
    db.Column('user_id', PG_UUID(as_uuid=True), db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    db.Column('group_id', PG_UUID(as_uuid=True), db.ForeignKey('groups.id', ondelete='CASCADE'), primary_key=True)
)

# --- 資料庫模型 (Models) ---
class Department(db.Model):
    __tablename__ = 'departments'
    id = db.Column(PG_UUID(as_uuid=True), primary_key=True, default=py_uuid.uuid4)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    users = db.relationship('User', backref='department_info', lazy='dynamic')

    def as_dict(self):
        return {'id': str(self.id), 'name': self.name, 'description': self.description,
                'created_at': self.created_at.isoformat() if self.created_at else None}

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(PG_UUID(as_uuid=True), primary_key=True, default=py_uuid.uuid4)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    department_id = db.Column(PG_UUID(as_uuid=True), db.ForeignKey('departments.id', ondelete='SET NULL'), nullable=True)
    tasks_assigned = db.relationship('Task', backref='assignee', lazy='dynamic', foreign_keys='Task.assignee_id') # Changed to lazy='dynamic'
    groups = db.relationship('Group', secondary=user_groups_table, lazy='subquery', # Use the renamed table
                             backref=db.backref('users', lazy=True))

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def as_dict(self, include_groups=True, include_department=True):
        department_data = None
        if include_department and self.department_info:
            department_data = self.department_info.as_dict()
        data = {'id': str(self.id), 'name': self.name, 'email': self.email, 'is_active': self.is_active,
                'created_at': self.created_at.isoformat() if self.created_at else None, 'department': department_data}
        if include_groups:
            data['groups'] = sorted([group.as_dict() for group in self.groups], key=lambda g: g['name'])
        return data

class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(PG_UUID(as_uuid=True), primary_key=True, default=py_uuid.uuid4)
    name = db.Column(db.String(80), unique=True, nullable=False, index=True)
    description = db.Column(db.String(255), nullable=True)

    def as_dict(self):
        return {'id': str(self.id), 'name': self.name, 'description': self.description}

class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(PG_UUID(as_uuid=True), primary_key=True, default=py_uuid.uuid4)
    name = db.Column(db.String(200), nullable=False, index=True) 
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    tasks = db.relationship('Task', backref='project', lazy='dynamic', cascade="all, delete-orphan")

    def as_dict(self):
        return {'id': str(self.id), 'name': self.name, 'description': self.description,
                'created_at': self.created_at.isoformat() if self.created_at else None}

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(PG_UUID(as_uuid=True), primary_key=True, default=py_uuid.uuid4)
    name = db.Column(db.String(255), nullable=False, index=True) 
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='待辦', index=True) 
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    due_date = db.Column(db.DateTime(timezone=True), nullable=True)
    project_id = db.Column(PG_UUID(as_uuid=True), db.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False) 
    assignee_id = db.Column(PG_UUID(as_uuid=True), db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True) 
    parent_id = db.Column(PG_UUID(as_uuid=True), db.ForeignKey('tasks.id', ondelete='CASCADE'), nullable=True) 
    children = db.relationship('Task', backref=db.backref('parent', remote_side=[id]), 
                               lazy='dynamic', cascade="all, delete-orphan")

    def as_dict(self):
        return {'id': str(self.id), 'name': self.name, 'description': self.description, 'status': self.status,
                'created_at': self.created_at.isoformat() if self.created_at else None,
                'due_date': self.due_date.isoformat() if self.due_date else None,
                'project_id': str(self.project_id),
                'assignee_id': str(self.assignee_id) if self.assignee_id else None,
                'parent_id': str(self.parent_id) if self.parent_id else None}

# --- JWT 驗證與權限裝飾器 ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try: token = auth_header.split(" ")[1]
            except IndexError: return jsonify({'message': '無效的 Token 格式 (未找到 Bearer)'}), 401
        if not token: return jsonify({'message': '缺少 Token'}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_id_from_token = payload.get('user_id')
            if not user_id_from_token: return jsonify({'message': 'Token 內容無效 (缺少 user_id)'}), 401
            current_user = User.query.get(py_uuid.UUID(user_id_from_token))
            if not current_user or not current_user.is_active: return jsonify({'message': 'Token 無效或使用者未啟用'}), 401
        except jwt.ExpiredSignatureError: return jsonify({'message': 'Token 已過期'}), 401
        except jwt.InvalidTokenError: return jsonify({'message': 'Token 無效'}), 401
        except Exception as e:
            app.logger.error(f"Token 驗證錯誤: {e}", exc_info=True)
            return jsonify({'message': 'Token 驗證時發生錯誤'}), 500
        return f(current_user, *args, **kwargs) 
    return decorated

def require_group(group_names_or_name):
    group_names = [group_names_or_name] if isinstance(group_names_or_name, str) else group_names_or_name
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, *args, **kwargs):
            user_groups_names = [group.name for group in current_user.groups]
            if not any(gn in user_groups_names for gn in group_names):
                app.logger.warning(f"使用者 {current_user.email} 權限不足。需要群組: {group_names}, 現有群組: {user_groups_names}")
                return jsonify({'message': f"權限不足，需要以下任一群組身份: {', '.join(group_names)}"}), 403
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator

from werkzeug.routing import BaseConverter
class UUIDStringConverter(BaseConverter):
    regex = r'[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}'
app.url_map.converters['uuid_string'] = UUIDStringConverter

# --- 認證 API 端點 ---
@app.route('/api/auth/register', methods=['POST'])
def register_user_api():
    data = request.get_json()
    required_fields = ['name', 'email', 'password']
    if not all(field in data and data[field] for field in required_fields): # Check for empty strings too
        return jsonify({'message': f"缺少必要欄位: {', '.join(required_fields)}"}), 400
    if len(data['password']) < 6: return jsonify({'message': '密碼長度至少需要6位'}), 400
    if User.query.filter_by(email=data['email']).first(): return jsonify({'message': '此電子郵件已被註冊'}), 409
    try:
        department_name = data.get('department')
        department_id_to_assign = None
        if department_name:
            department = Department.query.filter(db.func.lower(Department.name) == db.func.lower(department_name)).first() # Case-insensitive check
            if department:
                department_id_to_assign = department.id
            else:
                app.logger.info(f"註冊時提供的部門 '{department_name}' 未找到，將不設定部門。")
        
        user = User(name=data['name'], email=data['email'], department_id=department_id_to_assign)
        user.set_password(data['password'])
        db.session.add(user)
        
        default_group = Group.query.filter_by(name="DefaultUser").first()
        if default_group: user.groups.append(default_group)
        
        db.session.commit()
        app.logger.info(f"使用者已註冊: {user.email}")
        return jsonify({'message': '使用者註冊成功', 'user': user.as_dict(include_department=True)}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"註冊失敗: {e}", exc_info=True)
        return jsonify({'message': '註冊過程中發生錯誤', 'details': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login_user_api():
    auth = request.get_json()
    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({'message': '缺少 email 或 password'}), 401
    user = User.query.filter_by(email=auth['email']).first()
    if not user or not user.check_password(auth['password']) or not user.is_active:
        return jsonify({'message': '電子郵件或密碼錯誤，或帳戶未啟用'}), 401
    try:
        token_payload = {'user_id': str(user.id), 'name': user.name,
                         'groups': [group.name for group in user.groups],
                         'exp': datetime.now(timezone.utc) + timedelta(hours=24) }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")
        app.logger.info(f"使用者登入成功: {user.email}")
        return jsonify({'token': token, 'user': user.as_dict(include_groups=True, include_department=True)})
    except Exception as e:
        app.logger.error(f"登入時產生 Token 失敗: {e}", exc_info=True)
        return jsonify({'message': '登入失敗，無法產生 Token', 'details': str(e)}), 500

@app.route('/api/profile/me', methods=['GET'])
@token_required
def get_my_profile_api(current_user):
    return jsonify(current_user.as_dict(include_groups=True, include_department=True))

@app.route('/api/profile/me/password', methods=['PUT'])
@token_required
def update_my_password_api(current_user):
    data = request.get_json()
    if not data or not data.get('current_password') or not data.get('new_password'):
        return jsonify({'message': '缺少目前密碼或新密碼'}), 400
    if len(data['new_password']) < 6: return jsonify({'message': '新密碼長度至少需要6位'}), 400
    if not current_user.check_password(data['current_password']): return jsonify({'message': '目前密碼不正確'}), 403
    try:
        current_user.set_password(data['new_password'])
        db.session.commit()
        app.logger.info(f"使用者 {current_user.email} 已更新密碼")
        return jsonify({'message': '密碼更新成功'}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"使用者 {current_user.email} 更新密碼失敗: {e}", exc_info=True)
        return jsonify({'message': '更新密碼失敗', 'details': str(e)}), 500

# --- 管理員 API 端點 ---
@app.route('/api/admin/users', methods=['GET'])
@token_required
@require_group('Administrator') 
def admin_get_users_api(current_user): 
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int) 
        users_pagination = User.query.order_by(User.name).paginate(page=page, per_page=per_page, error_out=False)
        users = users_pagination.items
        return jsonify({'users': [user.as_dict(include_groups=True, include_department=True) for user in users],
                        'total': users_pagination.total, 'pages': users_pagination.pages,
                        'current_page': users_pagination.page})
    except Exception as e:
        app.logger.error(f"管理員獲取使用者列表失敗 (請求者: {current_user.email}): {e}", exc_info=True)
        return jsonify({"error": "獲取使用者列表失敗", "details": str(e)}), 500

@app.route('/api/admin/users/<uuid_string:user_id_str>', methods=['PUT'])
@token_required
@require_group('Administrator')
def admin_update_user_api(current_user, user_id_str):
    data = request.get_json()
    try:
        user_id = py_uuid.UUID(user_id_str)
        user_to_update = User.query.get(user_id)
        if not user_to_update: return jsonify({'message': '找不到使用者'}), 404
        if 'name' in data: user_to_update.name = data['name']
        if 'email' in data:
            if data['email'] != user_to_update.email and User.query.filter_by(email=data['email']).first():
                return jsonify({'message': '此電子郵件已被其他使用者使用'}), 409
            user_to_update.email = data['email']
        if 'department_id' in data:
            if data['department_id']:
                try: dept_id = py_uuid.UUID(data['department_id'])
                except ValueError: return jsonify({'message': '無效的部門 ID 格式'}), 400
                department = Department.query.get(dept_id)
                if not department: return jsonify({'message': '指定的部門不存在'}), 404
                user_to_update.department_id = department.id
            else: user_to_update.department_id = None
        if 'is_active' in data: user_to_update.is_active = data['is_active']
        if 'group_ids' in data and isinstance(data['group_ids'], list):
            admin_group_obj = Group.query.filter_by(name="Administrator").first()
            if admin_group_obj:
                is_editing_self_as_admin = (user_to_update.id == current_user.id and admin_group_obj in user_to_update.groups)
                is_removing_admin_group = str(admin_group_obj.id) not in data['group_ids']
                if is_editing_self_as_admin and is_removing_admin_group:
                    admin_users_count = User.query.join(user_groups_table).join(Group).filter(Group.name == "Administrator").count()
                    if admin_users_count <= 1:
                        return jsonify({'message': '無法移除最後一位管理員的 "Administrator" 權限'}), 403
            new_groups = []
            for group_id_str_payload in data['group_ids']:
                try:
                    group_id_payload = py_uuid.UUID(group_id_str_payload)
                    group = Group.query.get(group_id_payload)
                    if group: new_groups.append(group)
                except ValueError: app.logger.warning(f"更新使用者群組時，略過無效的群組 ID: {group_id_str_payload}")
            user_to_update.groups = new_groups
        db.session.commit()
        app.logger.info(f"管理員 {current_user.email} 更新了使用者 {user_to_update.email} 的資訊")
        return jsonify(user_to_update.as_dict(include_groups=True, include_department=True)), 200
    except ValueError: return jsonify({'message': '無效的使用者或部門 ID 格式'}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"管理員更新使用者 {user_id_str} 失敗: {e}", exc_info=True)
        return jsonify({'message': '更新使用者失敗', 'details': str(e)}), 500

@app.route('/api/admin/users/<uuid_string:user_id_str>/password', methods=['PUT'])
@token_required
@require_group('Administrator')
def admin_reset_user_password_api(current_user, user_id_str):
    data = request.get_json()
    if not data or not data.get('new_password'): return jsonify({'message': '缺少新密碼'}), 400
    if len(data['new_password']) < 6: return jsonify({'message': '新密碼長度至少需要6位'}), 400
    try:
        user_id = py_uuid.UUID(user_id_str)
        user_to_update = User.query.get(user_id)
        if not user_to_update: return jsonify({'message': '找不到使用者'}), 404
        user_to_update.set_password(data['new_password'])
        db.session.commit()
        app.logger.info(f"管理員 {current_user.email} 重設了使用者 {user_to_update.email} 的密碼")
        return jsonify({'message': f"使用者 {user_to_update.name} 的密碼已重設"}), 200
    except ValueError: return jsonify({'message': '無效的使用者 ID 格式'}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"管理員重設使用者 {user_id_str} 密碼失敗: {e}", exc_info=True)
        return jsonify({'message': '重設密碼失敗', 'details': str(e)}), 500

@app.route('/api/admin/groups', methods=['GET'])
@token_required
@require_group('Administrator')
def admin_get_groups_api(current_user):
    try:
        groups = Group.query.order_by(Group.name).all()
        return jsonify([group.as_dict() for group in groups]), 200
    except Exception as e:
        app.logger.error(f"管理員獲取群組列表失敗: {e}", exc_info=True)
        return jsonify({'message': '獲取群組列表失敗', 'details': str(e)}), 500

@app.route('/api/admin/departments', methods=['GET'])
@token_required
@require_group('Administrator')
def admin_get_departments_api(current_user):
    try:
        departments = Department.query.order_by(Department.name).all()
        return jsonify([dept.as_dict() for dept in departments]), 200
    except Exception as e:
        app.logger.error(f"管理員獲取部門列表失敗: {e}", exc_info=True)
        return jsonify({'message': '獲取部門列表失敗', 'details': str(e)}), 500

@app.route('/api/admin/departments', methods=['POST'])
@token_required
@require_group('Administrator')
def admin_create_department_api(current_user):
    data = request.get_json()
    if not data or not data.get('name'): return jsonify({'message': '缺少部門名稱'}), 400
    if Department.query.filter_by(name=data['name']).first(): return jsonify({'message': f"部門名稱 '{data['name']}' 已存在"}), 409
    try:
        new_dept = Department(name=data['name'], description=data.get('description'))
        db.session.add(new_dept)
        db.session.commit()
        app.logger.info(f"管理員 {current_user.email} 新增了部門: {new_dept.name}")
        return jsonify(new_dept.as_dict()), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"管理員新增部門失敗: {e}", exc_info=True)
        return jsonify({'message': '新增部門失敗', 'details': str(e)}), 500

@app.route('/api/admin/departments/<uuid_string:department_id_str>', methods=['PUT'])
@token_required
@require_group('Administrator')
def admin_update_department_api(current_user, department_id_str):
    data = request.get_json()
    try:
        dept_id = py_uuid.UUID(department_id_str)
        department = Department.query.get(dept_id)
        if not department: return jsonify({'message': '找不到部門'}), 404
        if 'name' in data:
            if data['name'] != department.name and Department.query.filter_by(name=data['name']).first():
                return jsonify({'message': f"部門名稱 '{data['name']}' 已被其他部門使用"}), 409
            department.name = data['name']
        if 'description' in data: department.description = data['description']
        db.session.commit()
        app.logger.info(f"管理員 {current_user.email} 更新了部門: {department.name}")
        return jsonify(department.as_dict()), 200
    except ValueError: return jsonify({'message': '無效的部門 ID 格式'}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"管理員更新部門 {department_id_str} 失敗: {e}", exc_info=True)
        return jsonify({'message': '更新部門失敗', 'details': str(e)}), 500

@app.route('/api/admin/departments/<uuid_string:department_id_str>', methods=['DELETE'])
@token_required
@require_group('Administrator')
def admin_delete_department_api(current_user, department_id_str):
    try:
        dept_id = py_uuid.UUID(department_id_str)
        department = Department.query.get(dept_id)
        if not department: return jsonify({'message': '找不到部門'}), 404
        if department.users.first(): 
            return jsonify({'message': '無法刪除，仍有使用者屬於此部門。請先處理相關使用者。'}), 409
        db.session.delete(department)
        db.session.commit()
        app.logger.info(f"管理員 {current_user.email} 刪除了部門: {department.name} (ID: {department_id_str})")
        return jsonify({'message': '部門已刪除'}), 200
    except ValueError: return jsonify({'message': '無效的部門 ID 格式'}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"管理員刪除部門 {department_id_str} 失敗: {e}", exc_info=True)
        return jsonify({'message': '刪除部門失敗', 'details': str(e)}), 500

# --- 專案 API 端點 ---
@app.route('/api/projects', methods=['GET'])
@token_required 
def get_projects_api(current_user):
    try:
        projects = Project.query.order_by(Project.created_at.desc()).all()
        return jsonify([project.as_dict() for project in projects])
    except Exception as e:
        app.logger.error(f"獲取專案列表失敗 (請求者: {current_user.email}): {e}", exc_info=True)
        return jsonify({"error": "獲取專案列表失敗", "details": str(e)}), 500

@app.route('/api/projects', methods=['POST'])
@token_required
@require_group(['Administrator', 'ProjectManager']) 
def create_project_api(current_user):
    payload = request.json
    if not payload or not payload.get('name'):
        return jsonify({"error": "缺少專案名稱或名稱為空"}), 400
    try:
        new_project = Project(name=payload["name"], description=payload.get("description", ""))
        db.session.add(new_project)
        db.session.commit()
        app.logger.info(f"專案已建立 (建立者: {current_user.email}): {new_project.id} - {new_project.name}")
        return jsonify(new_project.as_dict()), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"建立專案失敗 (請求者: {current_user.email}): {e}", exc_info=True)
        return jsonify({"error": "建立專案失敗", "details": str(e)}), 500

@app.route('/api/projects/<uuid_string:project_id_str>', methods=['GET'])
@token_required
def get_project_details_api(current_user, project_id_str):
    try:
        project_id = py_uuid.UUID(project_id_str)
        project = Project.query.get(project_id)
        if not project: return jsonify({"error": "找不到專案"}), 404
        return jsonify(project.as_dict())
    except ValueError: return jsonify({"error": "無效的專案 ID 格式"}), 400
    except Exception as e:
        app.logger.error(f"獲取專案 {project_id_str} 詳情失敗 (請求者: {current_user.email}): {e}", exc_info=True)
        return jsonify({"error": "獲取專案詳情失敗", "details": str(e)}), 500

@app.route('/api/projects/<uuid_string:project_id_str>', methods=['PUT'])
@token_required
@require_group(['Administrator', 'ProjectManager']) 
def update_project_api(current_user, project_id_str):
    payload = request.json
    try:
        project_id = py_uuid.UUID(project_id_str)
        project = Project.query.get(project_id)
        if not project: return jsonify({"error": "找不到專案"}), 404
        if 'name' in payload: project.name = payload["name"]
        if 'description' in payload: project.description = payload["description"]
        db.session.commit()
        app.logger.info(f"專案已更新 (更新者: {current_user.email}): {project.id} - {project.name}")
        return jsonify(project.as_dict())
    except ValueError: return jsonify({"error": "無效的專案 ID 格式"}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"更新專案 {project_id_str} 失敗 (請求者: {current_user.email}): {e}", exc_info=True)
        return jsonify({"error": "更新專案失敗", "details": str(e)}), 500

@app.route('/api/projects/<uuid_string:project_id_str>', methods=['DELETE'])
@token_required
@require_group('Administrator') 
def delete_project_api(current_user, project_id_str):
    try:
        project_id = py_uuid.UUID(project_id_str)
        project = Project.query.get(project_id)
        if not project: return jsonify({"error": "找不到專案"}), 404
        db.session.delete(project)
        db.session.commit()
        app.logger.info(f"專案已刪除 (刪除者: {current_user.email}): {project_id_str}")
        return jsonify({"message": "專案及其所有相關任務已刪除"}), 200
    except ValueError: return jsonify({"error": "無效的專案 ID 格式"}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"刪除專案 {project_id_str} 失敗 (請求者: {current_user.email}): {e}", exc_info=True)
        return jsonify({"error": "刪除專案失敗", "details": str(e)}), 500

# --- 任務 API 端點 ---
@app.route('/api/projects/<uuid_string:project_id_str>/tasks', methods=['GET'])
@token_required
def get_project_tasks_api(current_user, project_id_str):
    try:
        project_id = py_uuid.UUID(project_id_str)
        project = Project.query.get(project_id)
        if not project: return jsonify({"error": "找不到專案"}), 404
        tasks = project.tasks.order_by(Task.created_at).all()
        return jsonify([task.as_dict() for task in tasks])
    except ValueError: return jsonify({"error": "無效的專案 ID 格式"}), 400
    except Exception as e:
        app.logger.error(f"獲取專案 {project_id_str} 的任務失敗 (請求者: {current_user.email}): {e}", exc_info=True)
        return jsonify({"error": "獲取專案任務失敗", "details": str(e)}), 500

@app.route('/api/tasks', methods=['POST'])
@token_required
def create_task_api(current_user):
    payload = request.json
    required_fields = ['name', 'project_id', 'status']
    if not all(field in payload and payload[field] is not None for field in required_fields):
        return jsonify({"error": "缺少必要欄位 (name, project_id, status) 或值為 null"}), 400
    try:
        project_id = py_uuid.UUID(payload["project_id"])
        if not Project.query.get(project_id): return jsonify({"error": "指定的專案不存在"}), 404
        assignee_id = None
        if payload.get("assignee_id"):
            try: assignee_id = py_uuid.UUID(payload["assignee_id"])
            except ValueError: return jsonify({"error": "無效的負責人 ID 格式"}), 400
            if not User.query.get(assignee_id): return jsonify({"error": "指定的負責人不存在"}), 404
        parent_id = None
        if payload.get("parent_id"):
            try: parent_id = py_uuid.UUID(payload["parent_id"])
            except ValueError: return jsonify({"error": "無效的父任務 ID 格式"}), 400
            if not Task.query.get(parent_id): return jsonify({"error": "指定的父任務不存在"}), 404
        due_date_obj = None
        if payload.get("due_date"):
            try:
                due_date_str = payload["due_date"]
                if 'T' in due_date_str: # ISO format with time
                    due_date_obj = datetime.fromisoformat(due_date_str.replace('Z', '+00:00'))
                else: # Assume YYYY-MM-DD format
                    due_date_obj = datetime.strptime(due_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError: return jsonify({"error": "due_date 格式無效"}), 400
        new_task = Task(name=payload["name"], project_id=project_id, status=payload["status"],
                        description=payload.get("description", ""), assignee_id=assignee_id,
                        parent_id=parent_id, due_date=due_date_obj)
        db.session.add(new_task)
        db.session.commit()
        app.logger.info(f"任務已建立 (建立者: {current_user.email}): {new_task.id} - {new_task.name}")
        return jsonify(new_task.as_dict()), 201
    except ValueError as ve:
        app.logger.error(f"建立任務失敗 (ID/日期格式錯誤，請求者: {current_user.email}): {ve}", exc_info=True)
        return jsonify({"error": "ID 或日期格式錯誤", "details": str(ve)}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"建立任務失敗 (請求者: {current_user.email}): {e}", exc_info=True)
        return jsonify({"error": "建立任務失敗", "details": str(e)}), 500

@app.route('/api/tasks/<uuid_string:task_id_str>', methods=['GET'])
@token_required
def get_task_details_api(current_user, task_id_str):
    try:
        task_id = py_uuid.UUID(task_id_str)
        task = Task.query.get(task_id)
        if not task: return jsonify({"error": "找不到任務"}), 404
        return jsonify(task.as_dict())
    except ValueError: return jsonify({"error": "無效的任務 ID 格式"}), 400
    except Exception as e:
        app.logger.error(f"獲取任務 {task_id_str} 詳情失敗 (請求者: {current_user.email}): {e}", exc_info=True)
        return jsonify({"error": "獲取任務詳情失敗", "details": str(e)}), 500

@app.route('/api/tasks/<uuid_string:task_id_str>', methods=['PUT'])
@token_required
def update_task_api(current_user, task_id_str):
    payload = request.json
    try:
        task_id = py_uuid.UUID(task_id_str)
        task = Task.query.get(task_id)
        if not task: return jsonify({"error": "找不到任務"}), 404
        if 'name' in payload: task.name = payload["name"]
        if 'description' in payload: task.description = payload["description"]
        if 'status' in payload: task.status = payload["status"]
        if "due_date" in payload:
            if payload["due_date"]:
                try:
                    due_date_str = payload["due_date"]
                    if 'T' in due_date_str: task.due_date = datetime.fromisoformat(due_date_str.replace('Z', '+00:00'))
                    else: task.due_date = datetime.strptime(due_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except ValueError: return jsonify({"error": "due_date 格式無效"}), 400
            else: task.due_date = None
        if "assignee_id" in payload:
            if payload["assignee_id"]:
                try: assignee_id = py_uuid.UUID(payload["assignee_id"])
                except ValueError: return jsonify({"error": "無效的負責人 ID 格式"}), 400
                if not User.query.get(assignee_id): return jsonify({"error": "指定的負責人不存在"}), 400
                task.assignee_id = assignee_id
            else: task.assignee_id = None
        if "parent_id" in payload:
            if payload["parent_id"]:
                try: parent_id = py_uuid.UUID(payload["parent_id"])
                except ValueError: return jsonify({"error": "無效的父任務 ID 格式"}), 400
                if parent_id == task.id: return jsonify({"error": "不能設自己為父任務"}), 400
                temp_parent = Task.query.get(parent_id)
                if not temp_parent: return jsonify({"error": "指定的父任務不存在"}), 400
                ancestor = temp_parent.parent
                while ancestor:
                    if ancestor.id == task.id: return jsonify({"error": "會造成循環依賴"}), 400
                    ancestor = ancestor.parent
                task.parent_id = parent_id
            else: task.parent_id = None
        db.session.commit()
        app.logger.info(f"任務已更新 (更新者: {current_user.email}): {task.id} - {task.name}")
        return jsonify(task.as_dict())
    except ValueError as ve: 
        db.session.rollback()
        app.logger.error(f"更新任務 {task_id_str} 失敗 (ID/日期格式錯誤，請求者: {current_user.email}): {ve}", exc_info=True)
        return jsonify({"error": "ID 或日期格式錯誤", "details": str(ve)}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"更新任務 {task_id_str} 失敗 (請求者: {current_user.email}): {e}", exc_info=True)
        return jsonify({"error": "更新任務失敗", "details": str(e)}), 500

@app.route('/api/tasks/<uuid_string:task_id_str>', methods=['DELETE'])
@token_required
def delete_task_api(current_user, task_id_str):
    try:
        task_id = py_uuid.UUID(task_id_str)
        task = Task.query.get(task_id)
        if not task: return jsonify({"error": "找不到任務"}), 404
        db.session.delete(task)
        db.session.commit()
        app.logger.info(f"任務已刪除 (刪除者: {current_user.email}): {task_id_str}")
        return jsonify({"message": f"任務 {task_id_str} 及其所有子任務已刪除"}), 200
    except ValueError: return jsonify({"error": "無效的任務 ID 格式"}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"刪除任務 {task_id_str} 失敗 (請求者: {current_user.email}): {e}", exc_info=True)
        return jsonify({"error": "刪除任務失敗", "details": str(e)}), 500

# --- 應用程式啟動與資料庫初始化 ---
def initialize_database():
    with app.app_context():
        app.logger.info("正在檢查並初始化資料庫...")
        try:
            db.create_all() 
            app.logger.info("資料庫表格已成功檢查/建立。")
            default_groups_data = [
                {"name": "Administrator", "description": "系統管理員，擁有所有權限"},
                {"name": "ProjectManager", "description": "專案經理，可以管理專案和任務"},
                {"name": "Developer", "description": "開發人員，可以查看和更新被指派的任務"},
                {"name": "DefaultUser", "description": "預設使用者群組，基本查看權限"}
            ]
            for group_data in default_groups_data:
                if not Group.query.filter_by(name=group_data["name"]).first():
                    db.session.add(Group(name=group_data["name"], description=group_data["description"]))
            db.session.commit()

            default_departments_data = [
                {"name": "研發部", "description": "負責產品研發"},
                {"name": "市場部", "description": "負責市場推廣"},
                {"name": "行政部", "description": "負責行政事務"}
            ]
            for dept_data in default_departments_data:
                if not Department.query.filter_by(name=dept_data["name"]).first():
                    db.session.add(Department(name=dept_data["name"], description=dept_data["description"]))
            db.session.commit()

            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'AdminPassword123!')
            admin_user = User.query.filter_by(email=admin_email).first()
            it_department = Department.query.filter_by(name="研發部").first()

            if not admin_user:
                app.logger.info(f"正在建立預設管理員使用者: {admin_email}")
                admin_user = User(name="系統管理員", email=admin_email)
                if it_department: admin_user.department_id = it_department.id
                admin_user.set_password(admin_password)
                db.session.add(admin_user)
                db.session.commit() 
                app.logger.info(f"預設管理員使用者 {admin_email} 已建立。")
            
            admin_group = Group.query.filter_by(name="Administrator").first()
            if admin_group and admin_user and admin_group not in admin_user.groups:
                admin_user.groups.append(admin_group)
                app.logger.info(f"已將管理員 {admin_email} 加入 Administrator 群組。")
            
            db.session.commit()
            app.logger.info("預設群組、部門和管理員使用者檢查/建立完成。")
        except Exception as e:
            app.logger.error(f"資料庫初始化過程中發生錯誤: {e}", exc_info=True)
            db.session.rollback()

if __name__ == '__main__':
    initialize_database() 
    port = int(os.environ.get('PMT_APP_PORT', 5001)) 
    app.logger.info(f"PMT Flask 應用程式即將在 0.0.0.0:{port} 上啟動 (debug={app.debug})")
    app.run(debug=os.environ.get('FLASK_DEBUG', 'True').lower() == 'true', host='0.0.0.0', port=port)
