# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, Response
from models import db, User, File, AuditLog  # 👈 关键：加上 AuditLog
import bcrypt
from werkzeug.utils import secure_filename
import os
from io import BytesIO
from cryptography.exceptions import InvalidTag
from datetime import datetime   # 如果还没有这行，请加上
import urllib.parse  # 用于 URL 编码

# 导入加密工具（确保 crypto_utils.py 在同目录）
try:
    from crypto_utils import encrypt_file, decrypt_file
except ImportError:
    # 如果还没写 crypto_utils.py，先注释掉上传/下载功能
    pass

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-prod'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 配置上传文件夹
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db.init_app(app)


# ========== 路由定义（全部在全局作用域）==========
@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('用户名和密码不能为空')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('用户名已存在')
            return render_template('register.html')

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('注册成功，请登录')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            flash('用户名或密码错误')

    return render_template('login.html')


# 第三周 修改路由：
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_files = File.query.filter_by(user_id=session['user_id']).all()
    return render_template(
        'dashboard.html',
        username=session['username'],
        files=user_files,
        now=datetime.utcnow()  # 👈 关键：把当前时间传给模板
    )
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ====== 文件上传路由（关键：必须在全局！）======
# 第三周已修改
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash('未选择文件')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    password = request.form.get('password')

    if file.filename == '':
        flash('文件名为空')
        return redirect(url_for('dashboard'))

    if not password:
        flash('请输入密码用于加密')
        return redirect(url_for('dashboard'))

    # >>>>>>>>>>>>> 新增：安全限制校验 <<<<<<<<<<<<<<
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
    DANGEROUS_EXTENSIONS = {'.exe', '.bat', '.sh', '.com', '.pif', '.scr', '.jar', '.msi'}

    # 读取文件内容（注意：这里会加载整个文件到内存！课程项目可接受）
    original_data = file.read()
    original_filename = secure_filename(file.filename)
    file_size = len(original_data)

    # 检查文件大小
    if file_size > MAX_FILE_SIZE:
        flash('❌ 文件不能超过 50MB')
        return redirect(url_for('dashboard'))

    # 检查文件扩展名（转小写，提取后缀）
    _, ext = os.path.splitext(original_filename.lower())
    if ext in DANGEROUS_EXTENSIONS:
        flash(f'❌ 禁止上传可执行文件（{ext} 类型不安全）')
        return redirect(url_for('dashboard'))
    # >>>>>>>>>>>>> 安全校验结束 <<<<<<<<<<<<<<

    try:
        # 加密（原有逻辑不变）
        salt, nonce, ciphertext_with_tag = encrypt_file(original_data, password)

        encrypted_filename = f"{session['user_id']}_{os.urandom(8).hex()}.enc"
        encrypted_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)

        with open(encrypted_path, 'wb') as f:
            f.write(salt + nonce + ciphertext_with_tag)

        new_file = File(
            filename=original_filename,
            encrypted_path=encrypted_path,
            file_size=file_size,
            user_id=session['user_id']
        )
        db.session.add(new_file)
        db.session.commit()
        log_action('upload', original_filename)  # 记得加日志
        flash('✅ 文件上传并加密成功！')
    except Exception as e:
        flash(f'加密失败：{str(e)}')

    return redirect(url_for('dashboard'))

# ====== 文件下载路由 ======
@app.route('/download/<int:file_id>', methods=['GET', 'POST'])
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file_record = File.query.filter_by(id=file_id, user_id=session['user_id']).first_or_404()

    if request.method == 'GET':
        return render_template('download.html', file=file_record)

    password = request.form.get('password')
    if not password:
        flash('请输入密码')
        return render_template('download.html', file=file_record)

    try:
        with open(file_record.encrypted_path, 'rb') as f:
            data = f.read()
        salt = data[:16]
        nonce = data[16:28]
        ciphertext_with_tag = data[28:]
        decrypted_data = decrypt_file(salt, nonce, ciphertext_with_tag, password)
        log_action('download', file_record.filename)  # ← 第三周 新增这一行！

        encoded_filename = urllib.parse.quote(file_record.filename.encode('utf-8'))
        headers = {
            "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"
        }
        return Response(
            decrypted_data,
            mimetype='application/octet-stream',
            headers=headers
        )

    except InvalidTag:
        flash('密码错误或文件已损坏')
        return render_template('download.html', file=file_record)
    except Exception as e:
        flash(f'解密失败：{str(e)}')
        return render_template('download.html', file=file_record)


# app.py（第三周的追加）
def log_action(action: str, target: str = None):
    if 'user_id' in session:
        log = AuditLog(user_id=session['user_id'], action=action, target=target)
        db.session.add(log)
        db.session.commit()


# app.py（第三周 新增“生成分享链接”路由）
import secrets
from datetime import datetime, timedelta


@app.route('/share/<int:file_id>', methods=['POST'])
def create_share_link(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file_record = File.query.filter_by(id=file_id, user_id=session['user_id']).first_or_404()

    # 生成唯一 token
    token = secrets.token_urlsafe(32)  # 如 "aBc123...xyz"
    expires_at = datetime.utcnow() + timedelta(hours=24)  # 24小时有效

    file_record.share_token = token
    file_record.share_expires_at = expires_at
    file_record.share_used = False
    db.session.commit()

    log_action('share', f"{file_record.filename} -> {token}")
    flash(f'分享链接已生成（24小时内有效）：')
    flash(url_for('public_download', token=token, _external=True))
    return redirect(url_for('dashboard'))


# app.py（第三周 新增公开下载页 无需登录）
@app.route('/s/<token>', methods=['GET', 'POST'])
def public_download(token):
    # 查找有效分享
    file_record = File.query.filter_by(share_token=token).first_or_404()

    # 检查是否过期
    if file_record.share_expires_at < datetime.utcnow():
        flash('分享链接已过期')
        return redirect(url_for('login'))

    # 检查是否已使用（一次性）
    if file_record.share_used:
        flash('该链接已被使用过，不可重复下载')
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('public_download.html', filename=file_record.filename)

    # POST: 输入密码解密
    password = request.form.get('password')
    if not password:
        flash('请输入密码')
        return render_template('public_download.html', filename=file_record.filename)

    try:
        with open(file_record.encrypted_path, 'rb') as f:
            data = f.read()
        salt = data[:16]
        nonce = data[16:28]
        ciphertext_with_tag = data[28:]

        decrypted_data = decrypt_file(salt, nonce, ciphertext_with_tag, password)

        # 标记为已使用（一次性）
        file_record.share_used = True
        db.session.commit()

        # 记录日志（无用户ID，可用 token 代替）
        log = AuditLog(user_id=file_record.user_id, action='public_download', target=token)
        db.session.add(log)
        db.session.commit()

        from flask import send_file
        from io import BytesIO

        encoded_filename = urllib.parse.quote(file_record.filename.encode('utf-8'))
        headers = {
            "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"
        }
        return Response(
            decrypted_data,
            mimetype='application/octet-stream',
            headers=headers
        )
    except InvalidTag:
        flash('密码错误')
        return render_template('public_download.html', filename=file_record.filename)


# app.py（新增删除上传的文件功能）
@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # 查询文件（确保属于当前用户）
    file_record = File.query.filter_by(id=file_id, user_id=session['user_id']).first_or_404()

    # 1. 从磁盘删除加密文件
    encrypted_path = file_record.encrypted_path
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)

    # 2. 从数据库删除记录
    filename = file_record.filename  # 先保存名字用于日志
    db.session.delete(file_record)
    db.session.commit()

    # 3. 记录日志
    log_action('delete', filename)

    flash(f'文件已删除：{filename}')
    return redirect(url_for('dashboard'))


# app.py（添加取消分享功能）
@app.route('/unshare/<int:file_id>', methods=['POST'])
def unshare_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file_record = File.query.filter_by(id=file_id, user_id=session['user_id']).first_or_404()

    # 清除分享信息
    file_record.share_token = None
    file_record.share_expires_at = None
    file_record.share_used = False
    db.session.commit()

    log_action('unshare', file_record.filename)
    flash(f'已取消分享：{file_record.filename}')
    return redirect(url_for('dashboard'))


# ========== 应用启动 ==========
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)