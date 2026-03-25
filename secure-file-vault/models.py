# models.py
import bcrypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
#第一周
db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # 存哈希值
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        # 使用 bcrypt 加密密码
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))




# models.py（第二周追加）
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)        # 原始文件名
    encrypted_path = db.Column(db.String(255), nullable=False)  # 加密文件存储路径
    file_size = db.Column(db.Integer, nullable=False)           # 原始文件大小（字节）
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))
    share_token = db.Column(db.String(64), unique=True, nullable=True)  # 分享令牌
    share_expires_at = db.Column(db.DateTime, nullable=True)           # 过期时间
    share_used = db.Column(db.Boolean, default=False)                  # 是否已使用（一次性


# models.py（第三周追加）
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # 如 'upload', 'download', 'share', 'delete'
    target = db.Column(db.String(255))  # 如文件名或 share_token
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('logs', lazy=True))