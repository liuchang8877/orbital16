from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError
from sqlalchemy.dialects.postgresql import UUID
import hashlib
import binascii
import base64
import uuid
import os

app = Flask(__name__)

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

# 密码处理函数
def hash_password(password_str, salt_byte):
    dk = hashlib.pbkdf2_hmac("sha256", password_str.encode("utf-8"), salt_byte, 10000)
    return binascii.hexlify(dk)

def compare_password(password_str, password_hashed_base64, salt_base64):
    return hash_password(password_str, base64.b64decode(salt_base64)) == base64.b64decode(password_hashed_base64)

# 登录接口
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    # 检查请求参数
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # 检索用户信息
    user = Account.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Invalid email or password"}), 401

    # 校验密码
    if not compare_password(password, user.password, user.password_salt):
        return jsonify({"error": "Invalid email or password"}), 401

    return jsonify({
        "message": "Login successful",
        "user": {
            "id": str(user.id),
            "name": user.name,
            "email": user.email,
            "avatar": user.avatar,
            "status": user.status
        }
    }), 200

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