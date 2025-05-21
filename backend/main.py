# 專案管理系統 - Python Flask 後端 (整合使用者認證與群組)
# 檔案名稱: main.py

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt # 用於密碼雜湊
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
import uuid as py_uuid
from datetime import datetime, timezone, timedelta
import os
import logging
import jwt # PyJWT
from functools import wraps # 用於建立裝飾器

app = Flask(__name__)
bcrypt = Bcrypt(app) # 初始化 Bcrypt

# --- 設定 ---
# 建議將 SECRET_KEY 設為環境變數，用於 JWT 簽章
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_default_super_secret_key_for_jwt_!@#$%') # 務必在生產環境中更改此金鑰
DATABASE_URL = os.environ.get(
    'DATABASE_URL', 
    'postgresql://pm_user:12345@192.168.2.140:5432/project_management_db' # ！！！請替換為您的實際密碼！！！
)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False # 設為 True 可看 SQL log

db = SQLAlchemy(app)
CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": "*"}}) # 允許所有來源的 /api/* 請求，生產環境應更嚴格

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# --- 輔助表格：使用者與群組的多對多關聯 ---
user_groups = db.Table('user_groups',
    db.Column('user_id', PG_UUID(as_uuid=True), db.ForeignKey('users.id'), primary_key=True),
    db.Column('group_id', PG_UUID(as_uuid=True), db.ForeignKey('groups.id'), primary_key=True)
)

# --- 資料庫模型 (Models) ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(PG_UUID(as_uuid=True), primary_key=True, default=py_uuid.uuid4)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False) # 儲存雜湊後的密碼
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True) # 使用者是否啟用

    tasks_assigned = db.relationship('Task', backref='assignee', lazy=True, foreign_keys='Task.assignee_id')
    groups = db.relationship('Group', secondary=user_groups, lazy='subquery',
                             backref=db.backref('users', lazy=True))

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def as_dict(self, include_groups=False):
        data = {
            'id': str(self.id),
            'name': self.name,
            'email': self.email,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        if include_groups:
            data['groups'] = [group.as_dict() for group in self.groups]
        return data

class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(PG_UUID(as_uuid=True), primary_key=True, default=py_uuid.uuid4)
    name = db.Column(db.String(80), unique=True, nullable=False) # 例如：Administrators, ProjectManagers, Developers
    description = db.Column(db.String(255), nullable=True)

    def as_dict(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'description': self.description
        }

class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(PG_UUID(as_uuid=True), primary_key=True, default=py_uuid.uuid4)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    tasks = db.relationship('Task', backref='project', lazy='dynamic', cascade="all, delete-orphan")

    def as_dict(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(PG_UUID(as_uuid=True), primary_key=True, default=py_uuid.uuid4)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='待辦')
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    due_date = db.Column(db.DateTime(timezone=True), nullable=True)
    project_id = db.Column(PG_UUID(as_uuid=True), db.ForeignKey('projects.id'), nullable=False)
    assignee_id = db.Column(PG_UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=True)
    parent_id = db.Column(PG_UUID(as_uuid=True), db.ForeignKey('tasks.id'), nullable=True)
    children = db.relationship('Task', 
                               backref=db.backref('parent', remote_side=[id]), 
                               lazy='dynamic', 
                               cascade="all, delete-orphan")

    def as_dict(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'description': self.description,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'project_id': str(self.project_id),
            'assignee_id': str(self.assignee_id) if self.assignee_id else None,
            'parent_id': str(self.parent_id) if self.parent_id else None
        }

# --- JWT 驗證裝飾器 ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1] # Bearer <token>
            except IndexError:
                return jsonify({'message': '無效的 Token 格式'}), 401

        if not token:
            return jsonify({'message': '缺少 Token'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(py_uuid.UUID(data['user_id']))
            if not current_user or not current_user.is_active:
                return jsonify({'message': 'Token 無效或使用者未啟用'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token 已過期'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token 無效'}), 401
        except Exception as e:
            app.logger.error(f"Token 驗證錯誤: {e}")
            return jsonify({'message': 'Token 驗證時發生錯誤'}), 500
        
        return f(current_user, *args, **kwargs) # 將 current_user 傳遞給路由函式
    return decorated

# --- 權限檢查裝飾器 (範例) ---
def require_group(group_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user, *args, **kwargs):
            user_groups_names = [group.name for group in current_user.groups]
            if group_name not in user_groups_names:
                return jsonify({'message': f"權限不足，需要 '{group_name}' 群組身份"}), 403
            return f(current_user, *args, **kwargs)
        return decorated_function
    return decorator


# --- 自訂的 UUID URL 轉換器 ---
from werkzeug.routing import BaseConverter
class UUIDStringConverter(BaseConverter):
    regex = r'[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}'
app.url_map.converters['uuid_string'] = UUIDStringConverter

# --- 認證 API 端點 ---
@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password') or not data.get('name'):
        return jsonify({'message': '缺少必要欄位 (name, email, password)'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': '此電子郵件已被註冊'}), 409 # Conflict

    try:
        user = User(name=data['name'], email=data['email'])
        user.set_password(data['password'])
        db.session.add(user)
        
        # (可選) 新註冊使用者預設加入 "DefaultUser" 群組
        default_group = Group.query.filter_by(name="DefaultUser").first()
        if default_group:
            user.groups.append(default_group)

        db.session.commit()
        app.logger.info(f"使用者已註冊: {user.email}")
        return jsonify({'message': '使用者註冊成功'}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"註冊失敗: {e}")
        return jsonify({'message': '註冊過程中發生錯誤', 'details': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    auth = request.get_json()
    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({'message': '缺少 email 或 password'}), 401 # Unauthorized

    user = User.query.filter_by(email=auth['email']).first()

    if not user or not user.check_password(auth['password']) or not user.is_active:
        return jsonify({'message': '電子郵件或密碼錯誤，或帳戶未啟用'}), 401

    try:
        token = jwt.encode({
            'user_id': str(user.id),
            'name': user.name,
            'groups': [group.name for group in user.groups], # 將群組名稱加入 token
            'exp': datetime.now(timezone.utc) + timedelta(hours=24) # Token 有效期 24 小時
        }, app.config['SECRET_KEY'], algorithm="HS256")

        app.logger.info(f"使用者登入成功: {user.email}")
        return jsonify({
            'token': token,
            'user': user.as_dict(include_groups=True) # 回傳使用者資訊，包含群組
        })
    except Exception as e:
        app.logger.error(f"登入時產生 Token 失敗: {e}")
        return jsonify({'message': '登入失敗，無法產生 Token', 'details': str(e)}), 500

@app.route('/api/auth/me', methods=['GET'])
@token_required
def get_current_user_info(current_user):
    """獲取當前登入使用者的資訊"""
    if not current_user: # 雖然 token_required 應該會處理，但多一層保險
        return jsonify({'message': '找不到使用者資訊'}), 404
    return jsonify(current_user.as_dict(include_groups=True))


# --- 受保護的 API 端點 ---

@app.route('/api/users', methods=['GET'])
@token_required
@require_group('Administrator') # 只有 Administrator 群組可以獲取所有使用者列表
def get_users_api(current_user): # current_user 由 token_required 傳入
    """獲取所有使用者列表 (需要 Administrator 權限)"""
    try:
        users = User.query.order_by(User.name).all()
        return jsonify([user.as_dict(include_groups=True) for user in users])
    except Exception as e:
        app.logger.error(f"獲取使用者列表失敗 (請求者: {current_user.email}): {e}")
        return jsonify({"error": "獲取使用者列表失敗", "details": str(e)}), 500

@app.route('/api/projects', methods=['GET'])
@token_required
def get_projects_api(current_user):
    try:
        projects = Project.query.order_by(Project.created_at.desc()).all()
        return jsonify([project.as_dict() for project in projects])
    except Exception as e:
        app.logger.error(f"獲取專案列表失敗 (請求者: {current_user.email}): {e}")
        return jsonify({"error": "獲取專案列表失敗", "details": str(e)}), 500

@app.route('/api/projects', methods=['POST'])
@token_required
# @require_group('ProjectManager') # 範例：只有 ProjectManager 或 Administrator 可以建立專案
def create_project_api(current_user):
    payload = request.json
    if not payload or not payload.get('name'):
        return jsonify({"error": "缺少專案名稱或名稱為空"}), 400
    
    # 權限檢查範例 (更細緻的權限可以在這裡或裝飾器中實現)
    if "ProjectManager" not in [g.name for g in current_user.groups] and \
       "Administrator" not in [g.name for g in current_user.groups]:
        return jsonify({'message': '權限不足，無法建立專案'}), 403

    try:
        new_project = Project(name=payload["name"], description=payload.get("description", ""))
        db.session.add(new_project)
        db.session.commit()
        app.logger.info(f"專案已建立 (建立者: {current_user.email}): {new_project.id} - {new_project.name}")
        return jsonify(new_project.as_dict()), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"建立專案失敗 (請求者: {current_user.email}): {e}")
        return jsonify({"error": "建立專案失敗", "details": str(e)}), 500

# ... 其他 Project 和 Task 的 GET, PUT, DELETE 端點也需要加上 @token_required ...
# 並且根據需要加上 @require_group('...') 進行更細緻的權限控制

@app.route('/api/projects/<uuid_string:project_id_str>', methods=['GET'])
@token_required
def get_project_details_api(current_user, project_id_str):
    try:
        project_id = py_uuid.UUID(project_id_str)
        project = Project.query.get(project_id)
        if not project:
            return jsonify({"error": "找不到專案"}), 404
        return jsonify(project.as_dict())
    except ValueError:
        return jsonify({"error": "無效的專案 ID 格式"}), 400
    except Exception as e:
        app.logger.error(f"獲取專案 {project_id_str} 詳情失敗 (請求者: {current_user.email}): {e}")
        return jsonify({"error": "獲取專案詳情失敗", "details": str(e)}), 500

@app.route('/api/projects/<uuid_string:project_id_str>', methods=['PUT'])
@token_required
@require_group('ProjectManager') # 假設只有 ProjectManager 或 Admin 可以修改
def update_project_api(current_user, project_id_str):
    payload = request.json
    try:
        project_id = py_uuid.UUID(project_id_str)
        project = Project.query.get(project_id)
        if not project:
            return jsonify({"error": "找不到專案"}), 404
        
        if 'name' in payload: project.name = payload["name"]
        if 'description' in payload: project.description = payload["description"]
        
        db.session.commit()
        app.logger.info(f"專案已更新 (更新者: {current_user.email}): {project.id} - {project.name}")
        return jsonify(project.as_dict())
    except ValueError:
        return jsonify({"error": "無效的專案 ID 格式"}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"更新專案 {project_id_str} 失敗 (請求者: {current_user.email}): {e}")
        return jsonify({"error": "更新專案失敗", "details": str(e)}), 500

@app.route('/api/projects/<uuid_string:project_id_str>', methods=['DELETE'])
@token_required
@require_group('Administrator') # 假設只有 Admin 可以刪除專案
def delete_project_api(current_user, project_id_str):
    try:
        project_id = py_uuid.UUID(project_id_str)
        project = Project.query.get(project_id)
        if not project:
            return jsonify({"error": "找不到專案"}), 404

        db.session.delete(project)
        db.session.commit()
        app.logger.info(f"專案已刪除 (刪除者: {current_user.email}): {project_id_str}")
        return jsonify({"message": "專案及其所有相關任務已刪除"}), 200
    except ValueError:
        return jsonify({"error": "無效的專案 ID 格式"}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"刪除專案 {project_id_str} 失敗 (請求者: {current_user.email}): {e}")
        return jsonify({"error": "刪除專案失敗", "details": str(e)}), 500

@app.route('/api/projects/<uuid_string:project_id_str>/tasks', methods=['GET'])
@token_required
def get_project_tasks_api(current_user, project_id_str):
    try:
        project_id = py_uuid.UUID(project_id_str)
        project = Project.query.get(project_id)
        if not project:
            return jsonify({"error": "找不到專案"}), 404
        
        tasks = project.tasks.order_by(Task.created_at).all()
        return jsonify([task.as_dict() for task in tasks])
    except ValueError:
        return jsonify({"error": "無效的專案 ID 格式"}), 400
    except Exception as e:
        app.logger.error(f"獲取專案 {project_id_str} 的任務失敗 (請求者: {current_user.email}): {e}")
        return jsonify({"error": "獲取專案任務失敗", "details": str(e)}), 500

@app.route('/api/tasks', methods=['POST'])
@token_required
def create_task_api(current_user):
    payload = request.json
    required_fields = ['name', 'project_id', 'status']
    if not payload or not all(field in payload and payload[field] is not None for field in required_fields):
        return jsonify({"error": "缺少必要欄位 (name, project_id, status) 或值為 null"}), 400

    try:
        project_id = py_uuid.UUID(payload["project_id"])
        project = Project.query.get(project_id) # 檢查專案是否存在
        if not project:
            return jsonify({"error": "指定的專案不存在"}), 404
        
        # 權限檢查：只有專案經理或管理員，或者被指派到該專案的使用者可以建立任務 (範例)
        # 這裡的權限邏輯可以更複雜，例如檢查使用者是否是專案成員等
        is_admin_or_pm = "Administrator" in [g.name for g in current_user.groups] or \
                         "ProjectManager" in [g.name for g in current_user.groups]
        
        # 假設有一個 'ProjectMember' 群組，並且需要檢查使用者是否屬於該專案的成員群組
        # if not is_admin_or_pm and not user_is_member_of_project(current_user, project):
        #    return jsonify({'message': '權限不足，無法在此專案建立任務'}), 403
        # 為了簡化，我們先假設有權限建立任務
        
        assignee_id = None
        if payload.get("assignee_id"):
            assignee_id = py_uuid.UUID(payload["assignee_id"])
            if not User.query.get(assignee_id):
                 return jsonify({"error": "指定的負責人不存在"}), 404
        
        parent_id = None
        if payload.get("parent_id"):
            parent_id = py_uuid.UUID(payload["parent_id"])
            if not Task.query.get(parent_id):
                return jsonify({"error": "指定的父任務不存在"}), 404

        due_date_obj = None
        if payload.get("due_date"):
            try:
                due_date_obj = datetime.fromisoformat(payload["due_date"].replace('Z', '+00:00'))
                if due_date_obj.tzinfo is None or due_date_obj.tzinfo.utcoffset(due_date_obj) is None:
                    due_date_obj = datetime.strptime(payload["due_date"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                return jsonify({"error": "due_date 格式無效"}), 400

        new_task = Task(
            name=payload["name"], project_id=project_id, status=payload["status"],
            description=payload.get("description", ""), assignee_id=assignee_id,
            parent_id=parent_id, due_date=due_date_obj
        )
        db.session.add(new_task)
        db.session.commit()
        app.logger.info(f"任務已建立 (建立者: {current_user.email}): {new_task.id} - {new_task.name}")
        return jsonify(new_task.as_dict()), 201
    except ValueError as ve:
        app.logger.error(f"建立任務失敗 (ID 或日期格式錯誤，請求者: {current_user.email}): {ve}")
        return jsonify({"error": "ID 或日期格式錯誤", "details": str(ve)}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"建立任務失敗 (請求者: {current_user.email}): {e}")
        return jsonify({"error": "建立任務失敗", "details": str(e)}), 500

# Task GET, PUT, DELETE 也需要加上 @token_required 和可能的 @require_group
@app.route('/api/tasks/<uuid_string:task_id_str>', methods=['GET'])
@token_required
def get_task_details_api(current_user, task_id_str):
    try:
        task_id = py_uuid.UUID(task_id_str)
        task = Task.query.get(task_id)
        if not task:
            return jsonify({"error": "找不到任務"}), 404
        # 權限：是否只有任務相關人員或管理者可看？
        return jsonify(task.as_dict())
    except ValueError:
        return jsonify({"error": "無效的任務 ID 格式"}), 400
    except Exception as e:
        app.logger.error(f"獲取任務 {task_id_str} 詳情失敗 (請求者: {current_user.email}): {e}")
        return jsonify({"error": "獲取任務詳情失敗", "details": str(e)}), 500

@app.route('/api/tasks/<uuid_string:task_id_str>', methods=['PUT'])
@token_required
def update_task_api(current_user, task_id_str):
    payload = request.json
    try:
        task_id = py_uuid.UUID(task_id_str)
        task = Task.query.get(task_id)
        if not task:
            return jsonify({"error": "找不到任務"}), 404
        
        # 權限：是否只有任務負責人、專案經理或管理員可修改？
        # if task.assignee_id != current_user.id and "ProjectManager" not in [g.name for g in current_user.groups] ...

        if 'name' in payload: task.name = payload["name"]
        if 'description' in payload: task.description = payload["description"]
        if 'status' in payload: task.status = payload["status"]
        if "due_date" in payload:
            if payload["due_date"]:
                try:
                    due_date_obj = datetime.fromisoformat(payload["due_date"].replace('Z', '+00:00'))
                    if due_date_obj.tzinfo is None or due_date_obj.tzinfo.utcoffset(due_date_obj) is None:
                        due_date_obj = datetime.strptime(payload["due_date"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    task.due_date = due_date_obj
                except ValueError: return jsonify({"error": "due_date 格式無效"}), 400
            else: task.due_date = None
        if "assignee_id" in payload:
            if payload["assignee_id"]:
                assignee_id = py_uuid.UUID(payload["assignee_id"])
                if not User.query.get(assignee_id): return jsonify({"error": "指定的負責人不存在"}), 400
                task.assignee_id = assignee_id
            else: task.assignee_id = None
        if "parent_id" in payload:
            if payload["parent_id"]:
                parent_id = py_uuid.UUID(payload["parent_id"])
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
        app.logger.error(f"更新任務 {task_id_str} 失敗 (ID/日期格式錯誤，請求者: {current_user.email}): {ve}")
        return jsonify({"error": "ID 或日期格式錯誤", "details": str(ve)}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"更新任務 {task_id_str} 失敗 (請求者: {current_user.email}): {e}")
        return jsonify({"error": "更新任務失敗", "details": str(e)}), 500

@app.route('/api/tasks/<uuid_string:task_id_str>', methods=['DELETE'])
@token_required
def delete_task_api(current_user, task_id_str):
    try:
        task_id = py_uuid.UUID(task_id_str)
        task = Task.query.get(task_id)
        if not task:
            return jsonify({"error": "找不到任務"}), 404
        
        # 權限：是否只有任務建立者、專案經理或管理員可刪除？

        db.session.delete(task)
        db.session.commit()
        app.logger.info(f"任務已刪除 (刪除者: {current_user.email}): {task_id_str}")
        return jsonify({"message": f"任務 {task_id_str} 及其所有子任務已刪除"}), 200
    except ValueError:
        return jsonify({"error": "無效的任務 ID 格式"}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"刪除任務 {task_id_str} 失敗 (請求者: {current_user.email}): {e}")
        return jsonify({"error": "刪除任務失敗", "details": str(e)}), 500

# --- 應用程式啟動與資料庫初始化 ---
def initialize_database():
    with app.app_context():
        app.logger.info("正在檢查並初始化資料庫...")
        try:
            db.create_all() 
            app.logger.info("資料庫表格已成功檢查/建立。")

            # 建立預設群組
            default_groups = [
                {"name": "Administrator", "description": "系統管理員，擁有所有權限"},
                {"name": "ProjectManager", "description": "專案經理，可以管理專案和任務"},
                {"name": "Developer", "description": "開發人員，可以查看和更新被指派的任務"},
                {"name": "DefaultUser", "description": "預設使用者群組，基本查看權限"}
            ]
            for group_data in default_groups:
                if not Group.query.filter_by(name=group_data["name"]).first():
                    db.session.add(Group(name=group_data["name"], description=group_data["description"]))
            
            # 建立預設管理員使用者 (如果不存在)
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'AdminPassword123!') # 生產環境務必更改
            
            if not User.query.filter_by(email=admin_email).first():
                app.logger.info(f"正在建立預設管理員使用者: {admin_email}")
                admin_user = User(name="Administrator", email=admin_email)
                admin_user.set_password(admin_password)
                admin_group = Group.query.filter_by(name="Administrator").first()
                if admin_group:
                    admin_user.groups.append(admin_group)
                db.session.add(admin_user)
                app.logger.info(f"預設管理員使用者 {admin_email} 已建立。")
            
            db.session.commit()
            app.logger.info("預設群組和管理員使用者檢查/建立完成。")

        except Exception as e:
            app.logger.error(f"資料庫初始化過程中發生錯誤: {e}")
            db.session.rollback()


if __name__ == '__main__':
    initialize_database() 
    port = int(os.environ.get('PMT_APP_PORT', 5001)) 
    app.logger.info(f"PMT Flask 應用程式即將在 0.0.0.0:{port} 上啟動 (debug={app.debug})")
    app.run(debug=True, host='0.0.0.0', port=port)
