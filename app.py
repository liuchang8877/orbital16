from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError
from sqlalchemy.dialects.postgresql import UUID
import hashlib
import binascii
import base64
import uuid
import os
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

# JWT配置
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key')  # 在生产环境中应该使用环境变量
JWT_EXPIRATION_DAYS = 28

# 从环境变量读取数据库配置
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_USER = os.getenv('DB_USER', 'postgres')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'difyai123456')
DB_NAME = os.getenv('DB_NAME', 'dify')

# 数据库配置
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 定义 Accounts 模型
class Account(db.Model):
    __tablename__ = 'accounts'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255))  # 存储加密后的密码
    password_salt = db.Column(db.String(255))  # 存储 Base64 编码的盐值
    avatar = db.Column(db.String(255))
    status = db.Column(db.String(16), default='active', nullable=False)

# App model
class App(db.Model):
    __tablename__ = 'apps'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = db.Column(UUID(as_uuid=True), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    mode = db.Column(db.String(255), nullable=False, default='completion')
    icon = db.Column(db.String(255))
    status = db.Column(db.String(255), nullable=False, default='normal')
    enable_site = db.Column(db.Boolean, nullable=False, default=True)
    enable_api = db.Column(db.Boolean, nullable=False, default=True)
    created_by = db.Column(UUID(as_uuid=True))
    is_public = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    description = db.Column(db.Text, nullable=False, default='')
    sites = db.relationship('Site', backref='app', lazy=True)

# Site model
class Site(db.Model):
    __tablename__ = 'sites'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    app_id = db.Column(UUID(as_uuid=True), db.ForeignKey('apps.id'), nullable=False)
    code = db.Column(db.String(255))

# 密码处理函数
def hash_password(password_str, salt_byte):
    dk = hashlib.pbkdf2_hmac("sha256", password_str.encode("utf-8"), salt_byte, 10000)
    return binascii.hexlify(dk)

def compare_password(password_str, password_hashed_base64, salt_base64):
    return hash_password(password_str, base64.b64decode(salt_base64)) == base64.b64decode(password_hashed_base64)

def generate_token(user_id):
    """生成JWT token"""
    payload = {
        'user_id': str(user_id),
        'exp': datetime.utcnow() + timedelta(days=JWT_EXPIRATION_DAYS)
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def token_required(f):
    """验证JWT token的装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({
                'code': 401,
                'message': 'Token is missing'
            }), 401

        if token.startswith('Bearer '):
            token = token[7:]
        
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            request.user_id = payload['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({
                'code': 401,
                'message': 'Token has expired'
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                'code': 401,
                'message': 'Invalid token'
            }), 401
            
        return f(*args, **kwargs)
    return decorated

# 登录接口
@app.route('/api/login', methods=['POST'])
def login():
    """
    POST /api/login

    Parameters:
        - email: String, required
        - password: String, required

    Returns:
        - code: Integer, 0 for success, 1 for failure
        - message: String, error message
        - data: Object, user data
            - id: String, user id
            - name: String, user name
            - email: String, user email
            - avatar: String, user avatar
            - status: Integer, user status
            - token: String, jwt token
    """
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({
            'code': 1,
            'message': 'Missing email or password'
        }), 400

    user = Account.query.filter_by(email=email).first()
    if not user:
        return jsonify({
            'code': 1,
            'message': 'User not found'
        }), 404

    if not compare_password(password, user.password, user.password_salt):
        return jsonify({
            'code': 1,
            'message': 'Invalid password'
        }), 401

    # 生成token
    token = generate_token(user.id)

    return jsonify({
        'code': 0,
        'data': {
            'id': str(user.id),
            'name': user.name,
            'email': user.email,
            'avatar': user.avatar,
            'status': user.status,
            'token': token
        }
    }), 200

@app.route('/api/apps', methods=['GET'])
@token_required
def get_apps_with_sites():
    try:
        # 首先查询所有 apps
        apps = App.query.all()
        apps_data = []
        
        for app in apps:
            # 对于每个 app，获取其关联的第一个 site
            site = Site.query.filter_by(app_id=app.id).first()
            
            # 构建基本的 app 数据
            app_dict = {
                'name': app.name,
                'icon': app.icon,
                'status': app.status,
                'created_by': str(app.created_by) if app.created_by else None,
                'is_public': app.is_public,
                'created_at': app.created_at.isoformat() if app.created_at else None,
                'description': app.description,
                'site_code': site.code if site else None  # 只返回第一个 site 的 code
            }
            apps_data.append(app_dict)
        
        return jsonify({
            'code': 0,
            'data': apps_data,
            'message': 'Success'
        })
    
    except Exception as e:
        return jsonify({
            'code': 1,
            'message': str(e)
        }), 500

if __name__ == '__main__':
    try:
        with app.app_context():
            db.create_all()  # 初始化数据库表
        print("Database connected and tables initialized successfully!")
    except OperationalError as e:
        print(f"Error connecting to the database: {e}")
        print("Please check your database configuration and ensure the database server is running.")
        exit(1)

    # 启动应用
    app.run(host='0.0.0.0', port=5123)