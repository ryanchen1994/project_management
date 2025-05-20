# 專案管理系統 - Python Flask 後端 (整合 PostgreSQL)
# 檔案名稱: main.py (或者您後端主程式的檔案名)

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID as PG_UUID # 為了與 Python 內建的 uuid 區分
import uuid as py_uuid # Python 標準的 UUID 函式庫
from datetime import datetime, timezone # 確保使用 timezone-aware datetimes
import os
import logging # 加入日誌記錄

app = Flask(__name__)

# --- 資料庫設定 ---
# 優先從環境變數讀取資料庫 URL，若無則使用預設值
# 實際生產環境中，DATABASE_URL 應透過環境變數設定
# 格式: postgresql://使用者名稱:密碼@主機位址:埠號/資料庫名稱
# ！！！請務必將下面的 'your_secure_password' 替換為您為 pm_user 設定的實際密碼！！！
DATABASE_URL = os.environ.get(
    'DATABASE_URL', 
    'postgresql://pm_user:12345@192.168.2.140:5432/project_management_db' 
)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # 關閉不必要的追蹤，節省資源
app.config['SQLALCHEMY_ECHO'] = False # 設定為 True 可以看到執行的 SQL 語句，用於本地除錯

db = SQLAlchemy(app)
CORS(app) # 允許跨來源請求

# 設定日誌
logging.basicConfig(level=logging.INFO) # 設定日誌級別
app.logger.setLevel(logging.INFO)


# --- 資料庫模型 (Models) ---
# 使用者模型
class User(db.Model):
    __tablename__ = 'users'
    # 使用 PostgreSQL 的 UUID 型別，並讓 Python 端作為 uuid.UUID 物件處理
    id = db.Column(PG_UUID(as_uuid=True), primary_key=True, default=py_uuid.uuid4)
    name = db.Column(db.String(100), nullable=False, unique=True) # 使用者名稱通常是唯一的
    
    # 建立與 Task 模型的關聯，一個使用者可以被指派多個任務
    tasks_assigned = db.relationship('Task', backref='assignee', lazy=True, foreign_keys='Task.assignee_id')

    def as_dict(self):
        # 將模型物件轉換為字典，方便序列化為 JSON
        return {
            'id': str(self.id), # 將 UUID 物件轉為字串
            'name': self.name
        }

# 專案模型
class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(PG_UUID(as_uuid=True), primary_key=True, default=py_uuid.uuid4)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    # 使用 timezone-aware 的 UTC 時間
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # 建立與 Task 模型的關聯，一個專案可以有多個任務
    # cascade="all, delete-orphan" 表示刪除專案時，其下所有任務也會被刪除
    tasks = db.relationship('Task', backref='project', lazy='dynamic', cascade="all, delete-orphan")

    def as_dict(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# 任務模型
class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(PG_UUID(as_uuid=True), primary_key=True, default=py_uuid.uuid4)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='待辦') # 例如: '待辦', '進行中', '已完成'
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    due_date = db.Column(db.DateTime(timezone=True), nullable=True)

    # 外鍵，關聯到 projects 表的 id 欄位
    project_id = db.Column(PG_UUID(as_uuid=True), db.ForeignKey('projects.id'), nullable=False)
    # 外鍵，關聯到 users 表的 id 欄位 (負責人)
    assignee_id = db.Column(PG_UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=True)
    
    # 外鍵，自我關聯，用於表示父任務 (實現階層結構)
    parent_id = db.Column(PG_UUID(as_uuid=True), db.ForeignKey('tasks.id'), nullable=True)
    # 建立與子任務的關聯
    # remote_side=[id] 用於處理自我參照的關聯
    children = db.relationship('Task', 
                               backref=db.backref('parent', remote_side=[id]), 
                               lazy='dynamic', # 使用 'dynamic' 可以在需要時才載入子任務
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

# --- 自訂的 UUID URL 轉換器 (用於路由中的 ID) ---
from werkzeug.routing import BaseConverter
class UUIDStringConverter(BaseConverter):
    """
    接受 UUID 字串 (有或沒有連字號) 並在路由函式中作為字串傳遞。
    實際的 UUID 物件轉換將在路由函式內部進行。
    """
    regex = r'[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}'

app.url_map.converters['uuid_string'] = UUIDStringConverter


# --- API 端點 ---

# 使用者 API
@app.route('/api/users', methods=['GET'])
def get_users_api():
    """獲取所有使用者列表"""
    try:
        users = User.query.order_by(User.name).all()
        return jsonify([user.as_dict() for user in users])
    except Exception as e:
        app.logger.error(f"獲取使用者列表失敗: {e}")
        return jsonify({"error": "獲取使用者列表失敗", "details": str(e)}), 500

@app.route('/api/users', methods=['POST'])
def create_user_api():
    """建立新使用者"""
    payload = request.json
    if not payload or not payload.get('name'):
        return jsonify({"error": "缺少使用者名稱或名稱為空"}), 400
    
    try:
        if User.query.filter_by(name=payload['name']).first():
            return jsonify({"error": f"使用者名稱 '{payload['name']}' 已存在"}), 409
        
        new_user = User(name=payload['name'])
        db.session.add(new_user)
        db.session.commit()
        app.logger.info(f"使用者已建立: {new_user.id} - {new_user.name}")
        return jsonify(new_user.as_dict()), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"建立使用者失敗: {e}")
        return jsonify({"error": "建立使用者失敗", "details": str(e)}), 500

# 專案 API
@app.route('/api/projects', methods=['GET'])
def get_projects_api():
    """獲取所有專案列表"""
    try:
        projects = Project.query.order_by(Project.created_at.desc()).all()
        return jsonify([project.as_dict() for project in projects])
    except Exception as e:
        app.logger.error(f"獲取專案列表失敗: {e}")
        return jsonify({"error": "獲取專案列表失敗", "details": str(e)}), 500

@app.route('/api/projects', methods=['POST'])
def create_project_api():
    """建立新專案"""
    payload = request.json
    if not payload or not payload.get('name'):
        return jsonify({"error": "缺少專案名稱或名稱為空"}), 400
    
    try:
        new_project = Project(
            name=payload["name"],
            description=payload.get("description", "")
        )
        db.session.add(new_project)
        db.session.commit()
        app.logger.info(f"專案已建立: {new_project.id} - {new_project.name}")
        return jsonify(new_project.as_dict()), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"建立專案失敗: {e}")
        return jsonify({"error": "建立專案失敗", "details": str(e)}), 500

@app.route('/api/projects/<uuid_string:project_id_str>', methods=['GET'])
def get_project_details_api(project_id_str):
    """獲取特定專案詳情"""
    try:
        project_id = py_uuid.UUID(project_id_str)
        project = Project.query.get(project_id)
        if not project:
            return jsonify({"error": "找不到專案"}), 404
        return jsonify(project.as_dict())
    except ValueError:
        return jsonify({"error": "無效的專案 ID 格式"}), 400
    except Exception as e:
        app.logger.error(f"獲取專案 {project_id_str} 詳情失敗: {e}")
        return jsonify({"error": "獲取專案詳情失敗", "details": str(e)}), 500

@app.route('/api/projects/<uuid_string:project_id_str>', methods=['PUT'])
def update_project_api(project_id_str):
    """更新專案資訊"""
    payload = request.json
    try:
        project_id = py_uuid.UUID(project_id_str)
        project = Project.query.get(project_id)
        if not project:
            return jsonify({"error": "找不到專案"}), 404
        
        if 'name' in payload: project.name = payload["name"]
        if 'description' in payload: project.description = payload["description"]
        
        db.session.commit()
        app.logger.info(f"專案已更新: {project.id} - {project.name}")
        return jsonify(project.as_dict())
    except ValueError:
        return jsonify({"error": "無效的專案 ID 格式"}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"更新專案 {project_id_str} 失敗: {e}")
        return jsonify({"error": "更新專案失敗", "details": str(e)}), 500

@app.route('/api/projects/<uuid_string:project_id_str>', methods=['DELETE'])
def delete_project_api(project_id_str):
    """刪除專案及其所有任務"""
    try:
        project_id = py_uuid.UUID(project_id_str)
        project = Project.query.get(project_id)
        if not project:
            return jsonify({"error": "找不到專案"}), 404

        db.session.delete(project)
        db.session.commit()
        app.logger.info(f"專案已刪除: {project_id_str}")
        return jsonify({"message": "專案及其所有相關任務已刪除"}), 200
    except ValueError:
        return jsonify({"error": "無效的專案 ID 格式"}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"刪除專案 {project_id_str} 失敗: {e}")
        return jsonify({"error": "刪除專案失敗", "details": str(e)}), 500

# 任務 API
@app.route('/api/projects/<uuid_string:project_id_str>/tasks', methods=['GET'])
def get_project_tasks_api(project_id_str):
    """獲取專案下的所有任務 (扁平列表)"""
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
        app.logger.error(f"獲取專案 {project_id_str} 的任務失敗: {e}")
        return jsonify({"error": "獲取專案任務失敗", "details": str(e)}), 500

@app.route('/api/tasks', methods=['POST'])
def create_task_api():
    """建立新任務"""
    payload = request.json
    required_fields = ['name', 'project_id', 'status']
    if not payload or not all(field in payload and payload[field] is not None for field in required_fields):
        return jsonify({"error": "缺少必要欄位 (name, project_id, status) 或值為 null"}), 400

    try:
        project_id = py_uuid.UUID(payload["project_id"])
        if not Project.query.get(project_id):
            return jsonify({"error": "指定的專案不存在"}), 404
        
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
                # 如果前端傳來的是不含時區的日期字串 (YYYY-MM-DD)，則設為當天 UTC 午夜
                if due_date_obj.tzinfo is None or due_date_obj.tzinfo.utcoffset(due_date_obj) is None:
                    # 假設 YYYY-MM-DD 是本地日期，轉為 UTC
                    # 這部分可能需要根據前端傳送的格式更精確處理
                    # 為了簡單起見，如果沒有時區，我們假設它是 UTC 日期
                    due_date_obj = datetime.strptime(payload["due_date"], "%Y-%m-%d").replace(tzinfo=timezone.utc)

            except ValueError:
                return jsonify({"error": "due_date 格式無效，應為 ISO 格式 (例如 YYYY-MM-DDTHH:MM:SSZ 或 YYYY-MM-DD)"}), 400

        new_task = Task(
            name=payload["name"],
            project_id=project_id,
            status=payload["status"],
            description=payload.get("description", ""),
            assignee_id=assignee_id,
            parent_id=parent_id,
            due_date=due_date_obj
        )
        db.session.add(new_task)
        db.session.commit()
        app.logger.info(f"任務已建立: {new_task.id} - {new_task.name}")
        return jsonify(new_task.as_dict()), 201
    except ValueError as ve:
        app.logger.error(f"建立任務失敗 (ID 或日期格式錯誤): {ve}")
        return jsonify({"error": "ID 或日期格式錯誤", "details": str(ve)}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"建立任務失敗: {e}")
        return jsonify({"error": "建立任務失敗", "details": str(e)}), 500

@app.route('/api/tasks/<uuid_string:task_id_str>', methods=['GET'])
def get_task_details_api(task_id_str):
    """獲取特定任務詳情"""
    try:
        task_id = py_uuid.UUID(task_id_str)
        task = Task.query.get(task_id)
        if not task:
            return jsonify({"error": "找不到任務"}), 404
        return jsonify(task.as_dict())
    except ValueError:
        return jsonify({"error": "無效的任務 ID 格式"}), 400
    except Exception as e:
        app.logger.error(f"獲取任務 {task_id_str} 詳情失敗: {e}")
        return jsonify({"error": "獲取任務詳情失敗", "details": str(e)}), 500

@app.route('/api/tasks/<uuid_string:task_id_str>', methods=['PUT'])
def update_task_api(task_id_str):
    """更新任務 (狀態、負責人、內容等)"""
    payload = request.json
    try:
        task_id = py_uuid.UUID(task_id_str)
        task = Task.query.get(task_id)
        if not task:
            return jsonify({"error": "找不到任務"}), 404

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
                except ValueError:
                    return jsonify({"error": "due_date 格式無效"}), 400
            else:
                task.due_date = None
        
        if "assignee_id" in payload:
            if payload["assignee_id"]:
                assignee_id = py_uuid.UUID(payload["assignee_id"])
                if not User.query.get(assignee_id):
                    return jsonify({"error": "更新任務失敗：指定的負責人不存在"}), 400
                task.assignee_id = assignee_id
            else: 
                task.assignee_id = None
        
        if "parent_id" in payload:
            if payload["parent_id"]:
                parent_id = py_uuid.UUID(payload["parent_id"])
                if parent_id == task.id: 
                     return jsonify({"error": "不能將任務設為自己的父任務"}), 400
                temp_parent = Task.query.get(parent_id)
                if not temp_parent:
                    return jsonify({"error": "更新任務失敗：指定的父任務不存在"}), 400
                
                ancestor = temp_parent.parent
                while ancestor:
                    if ancestor.id == task.id:
                        return jsonify({"error": "更新任務失敗：會造成循環依賴"}), 400
                    ancestor = ancestor.parent
                task.parent_id = parent_id
            else: 
                task.parent_id = None
            
        db.session.commit()
        app.logger.info(f"任務已更新: {task.id} - {task.name}")
        return jsonify(task.as_dict())
    except ValueError as ve: 
        db.session.rollback()
        app.logger.error(f"更新任務 {task_id_str} 失敗 (ID 或日期格式錯誤): {ve}")
        return jsonify({"error": "ID 或日期格式錯誤", "details": str(ve)}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"更新任務 {task_id_str} 失敗: {e}")
        return jsonify({"error": "更新任務失敗", "details": str(e)}), 500

@app.route('/api/tasks/<uuid_string:task_id_str>', methods=['DELETE'])
def delete_task_api(task_id_str):
    """刪除任務 (其子任務會因 cascade delete-orphan 而被一併刪除)"""
    try:
        task_id = py_uuid.UUID(task_id_str)
        task = Task.query.get(task_id)
        if not task:
            return jsonify({"error": "找不到任務"}), 404

        db.session.delete(task)
        db.session.commit()
        app.logger.info(f"任務已刪除: {task_id_str}")
        return jsonify({"message": f"任務 {task_id_str} 及其所有子任務已刪除"}), 200
    except ValueError:
        return jsonify({"error": "無效的任務 ID 格式"}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"刪除任務 {task_id_str} 失敗: {e}")
        return jsonify({"error": "刪除任務失敗", "details": str(e)}), 500

# --- 應用程式啟動與資料庫初始化 ---
def initialize_database():
    """在應用程式上下文中建立資料庫表格 (如果尚不存在) 並新增預設資料"""
    with app.app_context():
        app.logger.info("正在檢查並初始化資料庫...")
        try:
            db.create_all() 
            app.logger.info("資料庫表格已成功檢查/建立。")

            if User.query.count() == 0:
                app.logger.info("資料庫中沒有使用者，正在建立預設使用者...")
                default_users_data = [
                    {"name": "小明"},
                    {"name": "小華"},
                    {"name": "小李"}
                ]
                for user_data in default_users_data:
                    if not User.query.filter_by(name=user_data["name"]).first():
                        db.session.add(User(name=user_data["name"]))
                
                db.session.commit()
                app.logger.info("預設使用者已建立。")
            else:
                app.logger.info(f"資料庫中已存在 {User.query.count()} 位使用者。")

        except Exception as e:
            app.logger.error(f"資料庫初始化過程中發生錯誤: {e}")
            db.session.rollback()


if __name__ == '__main__':
    initialize_database() 
    
    # 根據您的 Nginx 設定，PMT 後端應監聽 5001 port
    port = int(os.environ.get('PMT_APP_PORT', 5001)) 
    app.logger.info(f"PMT Flask 應用程式即將在 0.0.0.0:{port} 上啟動 (debug={app.debug})")
    app.run(debug=True, host='0.0.0.0', port=port)
