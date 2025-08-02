import os
import sys
import json
import uuid
import random
import string
import time
import subprocess
import ctypes
import win32net
import win32security
import win32api
import win32con
import win32netcon
import socket
import logging
import hashlib
import base64  # 添加base64模块
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('accountpro_service.log'),
        logging.StreamHandler()
    ]
)

class AccountDB:
    DB_FILE = 'accounts.json'
    MAX_BACKUPS = 5
    
    def __init__(self):
        self.accounts = {}
        self.tokens = {}
        self.groups = {
            'users': {'name': 'users', 'permissions': ['remote_login', 'basic_access']},
            'admins': {'name': 'admins', 'permissions': ['full_control']},
        }
        
        if not os.path.exists(self.DB_FILE):
            self._save()
        else:
            self._load()
        
        self.initialize_api_token()
    
    def initialize_api_token(self):
        if not self.tokens:
            token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            self.tokens = {
                'main_token': {
                    'token': token,
                    'created': int(time.time()),
                    'description': 'AccountPro API主令牌'
                }
            }
            self._save()
    
    def _load(self):
        try:
            with open(self.DB_FILE, 'r') as f:
                data = json.load(f)
                self.accounts = data.get('accounts', {})
                self.tokens = data.get('tokens', {})
                self.groups = data.get('groups', {})
        except (json.JSONDecodeError, FileNotFoundError):
            logging.error("数据库文件损坏或不存在，将初始化新数据库")
            self.accounts = {}
            self.tokens = {}
            self.groups = {}
            self._save()
    
    def _save(self):
        # 创建备份
        if os.path.exists(self.DB_FILE):
            for i in range(self.MAX_BACKUPS - 1, 0, -1):
                src = f"{self.DB_FILE}.{i-1}" if i > 1 else self.DB_FILE
                dst = f"{self.DB_FILE}.{i}"
                if os.path.exists(src):
                    os.replace(src, dst)
        
        # 保存当前数据库
        with open(self.DB_FILE, 'w') as f:
            # 关键修复：确保所有数据都是JSON可序列化的
            serializable_data = {
                'accounts': self.accounts,
                'tokens': self.tokens,
                'groups': self.groups
            }
            
            # 转换密码哈希值为字符串
            for username, account in serializable_data['accounts'].items():
                if isinstance(account.get('password'), bytes):
                    account['password'] = base64.b64encode(account['password']).decode('utf-8')
            
            json.dump(serializable_data, f, indent=2)
    
    def validate_token(self, token):
        if token == self.tokens.get('main_token', {}).get('token'):
            return True
        for key, token_data in self.tokens.items():
            if token == token_data.get('token'):
                return True
        return False
    
    def create_system_user(self, username, password, group='users'):
        try:
            if not self.is_admin():
                return False, "需要管理员权限来创建用户"
            
            if username in self.accounts or self.user_exists(username):
                return False, "用户已存在"
            
            if not self.is_valid_username(username):
                return False, "无效的用户名格式"
            
            if not self.validate_password_strength(password):
                return False, "密码不符合强度要求"
            
            user_info = {
                'name': username,
                'password': password,
                'priv': win32netcon.USER_PRIV_USER,
                'flags': win32netcon.UF_SCRIPT
            }
            
            try:
                win32net.NetUserAdd(None, 1, user_info)
            except win32net.error as e:
                if e.winerror != 2224:  # 2224 = NERR_UserExists
                    raise
                return False, "用户已存在"
            
            # 添加到组
            if group in self.groups:
                try:
                    groupname = "Administrators" if group == 'admins' else "Users"
                    self.add_user_to_group(username, groupname)
                except Exception as e:
                    logging.warning(f"添加用户到组时出错: {str(e)}")
            
            # 添加到远程桌面用户组
            try:
                self.add_user_to_remote_desktop_group(username)
            except Exception as e:
                logging.warning(f"添加用户到远程桌面组时出错: {str(e)}")
            
            # 保存到内存数据库
            self.accounts[username] = {
                'username': username,
                'password': self._hash_password(password),  # 存储哈希值
                'group': group,
                'created_at': int(time.time()),
                'status': 'active'
            }
            
            self._save()
            
            return True, "用户创建成功"
        except Exception as e:
            logging.error(f"创建用户错误: {str(e)}")
            return False, f"创建用户失败: {str(e)}"
    
    def add_user_to_group(self, username, group_name):
        domain = win32api.GetComputerName()
        user_entry = {
            'domainandname': f"{domain}\\{username}"
        }
        win32net.NetLocalGroupAddMembers(None, group_name, 3, [user_entry])
    
    def add_user_to_remote_desktop_group(self, username):
        domain = win32api.GetComputerName()
        user_entry = {
            'domainandname': f"{domain}\\{username}"
        }
        win32net.NetLocalGroupAddMembers(None, "Remote Desktop Users", 3, [user_entry])
    
    def is_valid_username(self, username):
        invalid_chars = "\"\\/:|<>[]+=;,?*@"
        return all(char not in invalid_chars for char in username) and len(username) <= 20
    
    def validate_password_strength(self, password):
        if len(password) < 8:
            return False
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        return has_upper and has_lower and has_digit
    
    def set_user_status(self, username, status):
        try:
            if not self.is_admin():
                return False, "需要管理员权限来修改用户状态"
            
            if username not in self.accounts:
                return False, "用户不存在"
            
            if status not in ['active', 'disabled']:
                return False, "无效的状态"
            
            # 更新内存状态
            self.accounts[username]['status'] = status
            self._save()
            
            # 更新Windows账户状态
            user_info = {"flags": win32netcon.UF_NORMAL_ACCOUNT}
            if status == 'disabled':
                user_info["flags"] |= win32netcon.UF_ACCOUNTDISABLE
            
            win32net.NetUserSetInfo(None, username, 1008, user_info)
            
            return True, "用户状态更新成功"
        except Exception as e:
            logging.error(f"更新用户状态错误: {str(e)}")
            return False, f"更新用户状态失败: {str(e)}"
    
    def delete_system_user(self, username):
        try:
            if not self.is_admin():
                return False, "需要管理员权限来删除用户"
            
            if username not in self.accounts:
                return False, "用户不存在"
            
            # 从系统中删除用户
            win32net.NetUserDel(None, username)
            
            # 从数据库中删除
            del self.accounts[username]
            self._save()
            
            return True, "用户删除成功"
        except Exception as e:
            logging.error(f"删除用户错误: {str(e)}")
            return False, f"删除用户失败: {str(e)}"
    
    def get_user_status(self, username):
        try:
            if username not in self.accounts:
                return {'status': 'not_found', 'message': '用户不存在'}
            
            # 获取Windows用户状态
            user_info = win32net.NetUserGetInfo(None, username, 4)
            flags = user_info.get('flags', 0)
            
            status = "active"
            if flags & win32netcon.UF_ACCOUNTDISABLE:
                status = "disabled"
            
            # 验证数据库状态
            if self.accounts[username]['status'] != status:
                self.accounts[username]['status'] = status
                self._save()
            
            return {'status': 'success', 'user_status': status}
        except win32net.error as e:
            if e.winerror == 2221:  # NERR_UserNotFound
                # 如果用户在Windows上不存在但在我们数据库中存在，从数据库删除
                if username in self.accounts:
                    del self.accounts[username]
                    self._save()
                return {'status': 'not_found', 'message': '用户不存在'}
            return {'status': 'error', 'message': f"获取用户状态错误: {str(e)}"}
        except Exception as e:
            return {'status': 'error', 'message': f"获取用户状态错误: {str(e)}"}
    
    def user_exists(self, username):
        try:
            win32net.NetUserGetInfo(None, username, 1)
            return True
        except win32net.error as e:
            if e.winerror == 2221:  # NERR_UserNotFound
                return False
            raise
        return False
    
    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def _hash_password(self, password):
        """密码哈希（安全存储）"""
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return salt + key
    
    def generate_password(self):
        """生成高强度随机密码"""
        length = 16
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`'
        
        # 确保包含每种类型
        password = [
            random.choice(uppercase),
            random.choice(lowercase),
            random.choice(digits),
            random.choice(symbols)
        ]
        
        # 添加随机字符
        all_chars = uppercase + lowercase + digits + symbols
        password.extend(random.choices(all_chars, k=length - 4))
        
        # 打乱顺序
        return ''.join(random.sample(password, len(password)))


class AccountProHandler(BaseHTTPRequestHandler):
    db = AccountDB()
    
    def do_OPTIONS(self):
        """处理CORS预检请求"""
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Max-Age', '86400')
        self.end_headers()
    
    def authenticate(self):
        """验证请求的Authorization头"""
        auth_header = self.headers.get('Authorization', '')
        if not auth_header:
            return False, "缺少Authorization头"
        
        parts = auth_header.split()
        if len(parts) != 2 or parts[0] != 'Bearer':
            return False, "无效的Authorization头格式"
        
        token = parts[1]
        if not self.db.validate_token(token):
            return False, "无效的API令牌"
        
        return True, ""
    
    def parse_json_body(self):
        """解析JSON请求体"""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}
            
        try:
            data = self.rfile.read(content_length)
            return json.loads(data.decode('utf-8'))
        except json.JSONDecodeError:
            return {}
    
    def send_json_response(self, data, status_code=200):
        """发送JSON响应"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        response = json.dumps(data, ensure_ascii=False, indent=2)
        self.wfile.write(response.encode('utf-8'))
    
    def handle_create_user(self):
        """处理创建用户请求"""
        data = self.parse_json_body()
        
        # 验证必须字段
        if 'username' not in data or not data['username']:
            return self.send_json_response({
                'status': 'error',
                'message': '缺少用户名'
            }, 400)
        
        if 'password' not in data or not data['password']:
            return self.send_json_response({
                'status': 'error',
                'message': '缺少密码'
            }, 400)
        
        username = data['username']
        password = data['password']
        group = data.get('group', 'users')
        
        # 创建用户
        success, message = self.db.create_system_user(username, password, group)
        
        if success:
            response = {
                'status': 'success',
                'message': message,
                'username': username
            }
            logging.info(f"用户创建成功: {username}")
        else:
            response = {'status': 'error', 'message': message}
            logging.error(f"用户创建失败: {message}")
        
        self.send_json_response(response, 201 if success else 400)
    
    def handle_suspend_user(self, username):
        """处理暂停用户请求"""
        success, message = self.db.set_user_status(username, 'disabled')
        if success:
            response = {'status': 'success', 'message': message}
            logging.info(f"用户 {username} 已暂停")
        else:
            response = {'status': 'error', 'message': message}
            logging.error(f"暂停用户 {username} 失败: {message}")
        self.send_json_response(response, 200 if success else 400)
    
    def handle_activate_user(self, username):
        """处理激活用户请求"""
        success, message = self.db.set_user_status(username, 'active')
        if success:
            response = {'status': 'success', 'message': message}
            logging.info(f"用户 {username} 已激活")
        else:
            response = {'status': 'error', 'message': message}
            logging.error(f"激活用户 {username} 失败: {message}")
        self.send_json_response(response, 200 if success else 400)
    
    def handle_delete_user(self, username):
        """处理删除用户请求"""
        success, message = self.db.delete_system_user(username)
        if success:
            response = {'status': 'success', 'message': message}
            logging.info(f"用户 {username} 已删除")
        else:
            response = {'status': 'error', 'message': message}
            logging.error(f"删除用户 {username} 失败: {message}")
        self.send_json_response(response, 200 if success else 400)
    
    def handle_get_user_status(self, username):
        """处理获取用户状态请求"""
        result = self.db.get_user_status(username)
        self.send_json_response(result, 200)
    
    def handle_ping(self):
        """处理健康检查请求"""
        hostname = socket.gethostname()
        try:
            ip_address = socket.gethostbyname(hostname)
        except:
            ip_address = "127.0.0.1"
        
        response = {
            'status': 'success',
            'message': 'AccountPro服务正常运行',
            'hostname': hostname,
            'ip': ip_address,
            'admin': self.db.is_admin(),
            'platform': sys.platform,
            'users_count': len(self.db.accounts)
        }
        self.send_json_response(response)
    
    def do_GET(self):
        """处理GET请求"""
        # 验证授权
        auth_success, auth_message = self.authenticate()
        if not auth_success:
            return self.send_json_response({
                'status': 'error',
                'message': f"认证失败: {auth_message}"
            }, 401)
        
        # 路由请求
        if self.path == '/ping':
            self.handle_ping()
        elif self.path.startswith('/user_status/'):
            username = self.path.split('/')[-1]
            self.handle_get_user_status(username)
        else:
            self.send_json_response({
                'status': 'error',
                'message': '无效的API端点'
            }, 404)
    
    def do_POST(self):
        """处理POST请求"""
        # 验证授权
        auth_success, auth_message = self.authenticate()
        if not auth_success:
            return self.send_json_response({
                'status': 'error',
                'message': f"认证失败: {auth_message}"
            }, 401)
        
        # 路由请求
        if self.path == '/create_user':
            self.handle_create_user()
        elif self.path.startswith('/suspend_user/'):
            username = self.path.split('/')[-1]
            self.handle_suspend_user(username)
        elif self.path.startswith('/activate_user/'):
            username = self.path.split('/')[-1]
            self.handle_activate_user(username)
        else:
            self.send_json_response({
                'status': 'error',
                'message': '无效的API端点'
            }, 404)
    
    def do_DELETE(self):
        """处理DELETE请求"""
        # 验证授权
        auth_success, auth_message = self.authenticate()
        if not auth_success:
            return self.send_json_response({
                'status': 'error',
                'message': f"认证失败: {auth_message}"
            }, 401)
        
        # 路由请求
        if self.path.startswith('/delete_user/'):
            username = self.path.split('/')[-1]
            self.handle_delete_user(username)
        else:
            self.send_json_response({
                'status': 'error',
                'message': '无效的API端点'
            }, 404)


# 自定义HTTP服务器
class AccountProServer(ThreadingHTTPServer):
    def __init__(self, *args, **kwargs):
        self.start_time = time.time()
        super().__init__(*args, **kwargs)


def main():
    # 检查操作系统
    if os.name != 'nt':
        logging.critical("此服务只能运行在Windows系统上！")
        sys.exit(1)
    
    # 检查管理员权限
    db = AccountDB()
    if not db.is_admin():
        logging.critical("需要管理员权限运行此服务！")
        logging.critical("请右键点击脚本并选择'以管理员身份运行'")
        sys.exit(1)
    
    # 配置服务
    server_host = os.getenv('ACCOUNTPRO_HOST', '0.0.0.0')
    server_port = int(os.getenv('ACCOUNTPRO_PORT', '5000'))
    
    # 获取API令牌
    api_token = db.tokens['main_token']['token']
    
    # 启动信息
    logging.info(f"启动 AccountPro Windows系统账户管理器")
    logging.info(f"监听地址: {server_host}:{server_port}")
    logging.info(f"API 令牌: {api_token}")
    logging.info("-" * 60)
    logging.info("API 端点:")
    logging.info("  GET /ping                     - 健康检查")
    logging.info("  GET /user_status/{username}   - 查询用户状态")
    logging.info("  POST /create_user             - 创建新用户")
    logging.info("  POST /suspend_user/{username} - 禁用用户")
    logging.info("  POST /activate_user/{username} - 启用用户")
    logging.info("  DELETE /delete_user/{username} - 删除用户")
    logging.info("-" * 60)
    logging.info("按 Ctrl+C 停止服务")
    
    # 启动HTTP服务器
    try:
        with AccountProServer((server_host, server_port), AccountProHandler) as httpd:
            logging.info(f"服务正在端口 {server_port} 上运行...")
            httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("\n服务已停止")
    except Exception as e:
        logging.error(f"启动服务失败: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
