import server
from comfy.cli_args import args
import aiohttp
from aiohttp_session import setup, get_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp import web
from jinja2 import Environment, FileSystemLoader, select_autoescape
import base64
import os
import folder_paths
import bcrypt
from datetime import datetime, timedelta
import logging
import sqlite3
from contextlib import contextmanager

# 파일 경로 설정
node_dir = os.path.dirname(__file__)
comfy_dir = os.path.dirname(folder_paths.__file__)
password_path = os.path.join(comfy_dir, "login", "PASSWORD")
guest_mode_path = os.path.join(comfy_dir, "login", "GUEST_MODE")
secret_key_path = os.path.join(node_dir, '.secret-key.txt')
login_html_path = os.path.join(node_dir, "login.html")
DATABASE_PATH = os.path.join(comfy_dir, "login", "users.db")  # SQLite 데이터베이스 경로

# 상수 설정
KEY_AGE_LIMIT = timedelta(days=30)  # 키 만료 기간
TOKEN = ""

# 로깅 설정
logging.basicConfig(level=logging.INFO)

# SQLite 데이터베이스 연결 관리
@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # 딕셔너리 형태로 결과 반환
    try:
        yield conn
    finally:
        conn.close()

# 데이터베이스 초기화
def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER,
                logged_in INTEGER DEFAULT 0,
                guest_mode INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()

# 데이터베이스 초기화 실행
init_db()

# 사용자 추가 함수
def add_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()

# 사용자 조회 함수
def get_user(username):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
        return cursor.fetchone()

# 세션 생성 함수
def create_session(session_id, user_id, logged_in=False, guest_mode=False):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO sessions (session_id, user_id, logged_in, guest_mode) VALUES (?, ?, ?, ?)', 
                       (session_id, user_id, logged_in, guest_mode))
        conn.commit()

# 세션 정보 조회 함수
def get_session_info(session_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT session_id, user_id, logged_in, guest_mode FROM sessions WHERE session_id = ?', (session_id,))
        return cursor.fetchone()

# 세션 업데이트 함수
def update_session(session_id, logged_in=None, guest_mode=None):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if logged_in is not None:
            cursor.execute('UPDATE sessions SET logged_in = ? WHERE session_id = ?', (logged_in, session_id))
        if guest_mode is not None:
            cursor.execute('UPDATE sessions SET guest_mode = ? WHERE session_id = ?', (guest_mode, session_id))
        conn.commit()

# 세션 삭제 함수
def delete_session(session_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
        conn.commit()

# 키 생성 및 관리 함수
def generate_key():
    return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')

def write_key_to_file(key):
    with open(secret_key_path, 'w') as file:
        file.write(f"{key},{datetime.now().isoformat()}")

def read_key_from_file():
    try:
        with open(secret_key_path, 'r') as file:
            key, timestamp = file.read().split(',')
            return key, datetime.fromisoformat(timestamp)
    except FileNotFoundError:
        return None, None

def key_is_old(timestamp):
    return datetime.now() - timestamp > KEY_AGE_LIMIT

def get_or_refresh_key():
    key, timestamp = read_key_from_file()
    if key is None or timestamp is None or key_is_old(timestamp):
        key = generate_key()
        write_key_to_file(key)
    return key

# PromptServer 및 app 설정
prompt_server = server.PromptServer.instance
app = prompt_server.app
routes = prompt_server.routes

# 세션 설정
secret_key = get_or_refresh_key()
setup(app, EncryptedCookieStorage(secret_key))

# 로그인 페이지
@routes.get("/login")
async def get_root(request):
    session = await get_session(request)
    wrong_password = request.query.get('wrong_password', '')
    if 'logged_in' in session and session['logged_in']:
        raise web.HTTPFound('/')
    else:
        env = Environment(
            loader=FileSystemLoader(node_dir),
            autoescape=select_autoescape(['html', 'xml']),
            cache_size=0  # 캐시 비활성화
        )
        template = env.get_template('login.html')
        env.cache.clear()  # 캐시 초기화
        guest_mode = os.path.exists(guest_mode_path)
        return web.Response(text=template.render(wrong_password=wrong_password, guest_mode=guest_mode), content_type='text/html')

# 로그인 처리
@routes.post("/login")
async def login_handler(request):
    data = await request.post()
    username_input = data.get('username')
    password_input = data.get('password').encode('utf-8')
    guest_mode = data.get('guest_mode') == '1'

    if guest_mode and os.path.exists(guest_mode_path):
        session = await get_session(request)
        session['guest_mode'] = True
        return web.HTTPFound('/')

    user = get_user(username_input)
    if user:
        user_id, username, hashed_password = user
        if bcrypt.checkpw(password_input, hashed_password):
            session = await get_session(request)
            session_id = session.identity
            create_session(session_id, user_id, logged_in=True)
            session['logged_in'] = True
            session['username'] = username
            return web.HTTPFound('/')
        else:
            return web.HTTPFound('/login?wrong_password=1')
    else:
        return web.HTTPFound('/login?wrong_password=1')

# 로그아웃 처리
@routes.get("/logout")
async def get_root(request):
    session = await get_session(request)
    session_id = session.identity
    delete_session(session_id)
    session['logged_in'] = False
    session['guest_mode'] = False
    session.pop('username', None)
    response = web.HTTPFound('/login')
    return response

# 게스트 모드 확인
@routes.get("/guest_mode")
async def get_guest_mode(request):
    session = await get_session(request)
    if 'guest_mode' in session and session['guest_mode']:
        return web.json_response({'guestMode': True})
    else:
        return web.json_response({'guestMode': False})

@routes.get("/register")
async def get_register(request):
    env = Environment(
        loader=FileSystemLoader(node_dir),
        autoescape=select_autoescape(['html', 'xml'])
    )
    template = env.get_template('register.html')  # register.html 파일 필요
    return web.Response(text=template.render(), content_type='text/html')

@routes.post("/register")
async def register_handler(request):
    data = await request.post()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return web.HTTPFound('/register?error=1')  # 필수 필드 누락 시 에러

    # 사용자 이름 중복 확인
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            return web.HTTPFound('/register?error=2')  # 중복 사용자 이름

    # 사용자 추가
    add_user(username, password)
    return web.HTTPFound('/login')  # 로그인 페이지로 리디렉션

# 미들웨어: 로그인 상태 확인
@web.middleware
async def check_login_status(request: web.Request, handler):
    # 예외 경로: 로그인, 회원가입, 정적 파일 등
    excluded_paths = [
        '/login',
        '/register',  # 회원가입 페이지 추가
        '/static',    # 정적 파일 경로 (필요한 경우)
    ]

    # 현재 요청 경로가 예외 경로인지 확인
    if any(request.path.startswith(path) for path in excluded_paths):
        return await handler(request)

    # 세션 확인
    session = await get_session(request)
    session_id = session.identity
    session_info = get_session_info(session_id)

    # 로그인 상태 확인
    if session_info and session_info['logged_in']:
        return await process_request(request, handler)

    # 게스트 모드 확인
    if session_info and session_info['guest_mode']:
        not_allowed_get_path = []
        allowed_post_path = ['/prompt', '/upload/image']
        if request.method == "GET" and request.path not in not_allowed_get_path:
            return await process_request(request, handler)
        elif request.method == "POST" and request.path in allowed_post_path:
            return await process_request(request, handler)
        else:
            return web.json_response({})

    # 토큰 기반 인증 확인
    if args.enable_cors_header is None or args.enable_cors_header == '*' or args.enable_cors_header == request.headers.get('Origin'):
        authorization_header = request.headers.get("Authorization")
        if authorization_header:
            auth_type, token_from_header = authorization_header.split()
            if auth_type == 'Bearer' and token_from_header == TOKEN:
                return await process_request(request, handler)

        if request.query.get("token") == TOKEN:
            return await process_request(request, handler)

    # 로그인되지 않은 경우 리디렉션
    accept_header = request.headers.get('Accept', '')
    if 'text/html' in accept_header:
        raise web.HTTPFound('/login')
    else:
        return web.json_response({'error': 'Authentication required.'}, status=401)

# 미들웨어 추가
app.middlewares.append(check_login_status)

# 정적 파일 서빙
old_css_path = os.path.join(node_dir, "old_css")
app.router.add_static('/old_css/', old_css_path)

# 노드 클래스 매핑 (필요한 경우 추가)
NODE_CLASS_MAPPINGS = {}
