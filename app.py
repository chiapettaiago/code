from flask import Flask, render_template, request, jsonify, send_file, send_from_directory, make_response
import subprocess
import os
import tempfile
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
from flask_cors import CORS

# Certifique-se de que o diretório de templates está configurado corretamente
app = Flask(__name__, template_folder='templates')
CORS(app, supports_credentials=True)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'  

# Criar diretório instance se não existir
instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
if not os.path.exists(instance_path):
    os.makedirs(instance_path)

# Configurar o caminho do banco de dados
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "ide.db")}'

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limite de 16MB para uploads
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    files = db.relationship('UserFile', backref='owner', lazy=True, cascade='all, delete-orphan')

class UserFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def validate_username(username):
    if not 3 <= len(username) <= 150:
        return False
    return bool(re.match('^[a-zA-Z0-9_-]+$', username))

def validate_password(password):
    return len(password) >= 8

@app.before_request
def before_request():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
        return response
    if request.method in ['POST', 'PUT'] and request.content_type != 'application/json':
        return jsonify({'success': False, 'error': 'Content-Type deve ser application/json'}), 415

@app.after_request
def add_cors_headers(response):
    response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({'success': False, 'error': 'Autenticação necessária'}), 401

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'success': False, 'error': 'Método não permitido'}), 405

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({'success': False, 'error': 'Usuário e senha obrigatórios.'})
        if not validate_username(username):
            return jsonify({'success': False, 'error': 'Nome de usuário inválido. Use entre 3 e 150 caracteres alfanuméricos.'})
        if not validate_password(password):
            return jsonify({'success': False, 'error': 'Senha deve ter pelo menos 8 caracteres.'})
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Usuário já existe.'})
        hashed_pw = generate_password_hash(password)
        user = User(username=username, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Usuário ou senha inválidos.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'success': True})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run', methods=['POST'])
def run_code():
    code = request.json.get('code', '')
    filename = request.json.get('filename', '')
    
    # Melhor detecção de linguagem
    python_extensions = {'.py', '.pyw'}
    c_extensions = {'.c', '.cpp', '.h', '.hpp'}
    ext = os.path.splitext(filename)[1].lower()
    
    if ext in python_extensions:
        language = 'python'
    elif ext in c_extensions:
        language = 'c'
    else:
        return jsonify({'output': 'Erro: Extensão de arquivo não suportada'})
    
    if len(code) > 50000:  # 50KB
        return jsonify({'output': 'Erro: Código fonte muito grande'})
    
    # Lista de palavras-chave e funções proibidas
    forbidden_keywords = [
        'system', 'exec', 'popen', 'fork', 'socket', 'getenv', 'environ',
        'remove', 'unlink', 'rmdir', 'mkdir', 'chdir', 'subprocess',
        'os.system', 'os.popen', 'os.spawn', 'pty.spawn', '__import__',
        'importlib', 'builtins', 'eval', 'pickle', 'shelve'
    ]
    
    # Verifica se há palavras-chave proibidas no código
    for keyword in forbidden_keywords:
        if keyword in code:
            return jsonify({'output': f'Erro: Uso de função não permitida: {keyword}'})
    
    try:
        if language == 'python':
            # Configura variáveis de ambiente para o Python
            env = os.environ.copy()
            env['PYTHONHASHSEED'] = '0'  # Desabilita hash randomization
            env['PYTHONIOENCODING'] = 'utf-8'
            
            # Verifica se o Python está disponível
            try:
                python_version = subprocess.run(
                    ['python', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    env=env
                )
                if python_version.returncode != 0:
                    return jsonify({'output': 'Erro: Python não está instalado ou acessível'})
            except Exception as e:
                return jsonify({'output': f'Erro ao verificar Python: {str(e)}'})

            # Executa código Python em um ambiente restrito
            with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w', encoding='utf-8') as f:
                restricted_code = """import sys
import math
import random
import time
import string
from typing import *
import io
import traceback

# Redireciona stdout para capturar a saída
stdout = io.StringIO()
stderr = io.StringIO()
sys.stdout = stdout
sys.stderr = stderr

try:
    # Código do usuário
%s
except Exception as e:
    print("=== ERRO ===")
    traceback.print_exc(file=sys.stderr)
finally:
    # Restaura stdout e stderr
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    output = stdout.getvalue()
    errors = stderr.getvalue()
    if errors:
        print("=== ERROS ===")
        print(errors)
    print(output)
""" % ('\n'.join('    ' + line for line in code.splitlines()))

                f.write(restricted_code)
                temp_file = f.name

            # Executa o código Python com timeout e ambiente configurado
            try:
                run_result = subprocess.run(
                    ['python', '-E', temp_file],  # -E desabilita variáveis de ambiente PYTHON*
                    capture_output=True,
                    text=True,
                    timeout=5,
                    env=env
                )
                
                output = []
                if run_result.stdout:
                    output.append(run_result.stdout)
                if run_result.stderr:
                    output.append(f'Erros:\n{run_result.stderr}')
                    
                return jsonify({'output': '\n'.join(output)})
            except subprocess.TimeoutExpired:
                return jsonify({'output': 'Erro: Tempo de execução excedido (5 segundos)'})
            except Exception as e:
                return jsonify({'output': f'Erro na execução: {str(e)}'})
            finally:
                # Limpa o arquivo temporário
                try:
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)
                except:
                    pass
            
        else:  # Código C/C++
            temp_file = None
            exe_file = None
            
            try:
                with tempfile.NamedTemporaryFile(suffix=ext, delete=False, mode='w', encoding='utf-8') as f:
                    # Código para C/C++ com proteções
                    restricted_code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#ifdef __linux__
#include <sys/resource.h>
#endif

// Proteção contra timeout
volatile int __timeout = 0;
void __timeout_handler(int sig) {
    __timeout = 1;
    exit(1);
}

// Proteção contra alocação excessiva de memória
void* __check_malloc(size_t size) {
    static size_t total_memory = 0;
    const size_t memory_limit = 50 * 1024 * 1024; // 50MB
    
    if (size > memory_limit || total_memory + size > memory_limit) {
        fprintf(stderr, "Erro: Limite de memória excedido\\n");
        exit(1);
    }
    
    void* ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "Erro: Falha na alocação de memória\\n");
        exit(1);
    }
    
    total_memory += size;
    return ptr;
}

#define malloc(size) __check_malloc(size)

// Código do usuário
%s
""" % code
                    f.write(restricted_code)
                    temp_file = f.name

                # Define o nome do executável baseado no SO
                if os.name == 'nt':
                    exe_file = os.path.join(tempfile.gettempdir(), 'temp.exe')
                else:
                    exe_file = os.path.join(tempfile.gettempdir(), 'temp')

                # Configura flags do compilador
                compiler = 'g++' if ext in ['.cpp', '.hpp'] else 'gcc'
                compiler_flags = [
                    '-O1',           # Otimização básica
                    '-Wall',         # Todos os warnings
                    '-Wextra',       # Warnings extras
                    '-fno-asm',      # Desabilita assembly inline
                    '-Werror=format-security'  # Erros de formato como erro
                ]
                
                if os.name == 'nt':
                    compiler_flags.append('-Wl,--stack,4194304')

                # Compilar com flags de segurança
                compile_result = subprocess.run(
                    [compiler, temp_file, '-o', exe_file] + compiler_flags,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if compile_result.returncode != 0:
                    return jsonify({'output': f'Erro de compilação:\n{compile_result.stderr}'})

                # Define limites de recursos no Linux
                def limit_resources():
                    if os.name != 'nt':
                        import resource
                        memory_limit = 50 * 1024 * 1024  # 50MB
                        resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
                        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))

                # Executar o código compilado com limites
                run_result = subprocess.run(
                    [exe_file],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    preexec_fn=limit_resources if os.name != 'nt' else None
                )

                output = run_result.stdout
                if run_result.stderr:
                    output += f'\nErros:\n{run_result.stderr}'

                return jsonify({'output': output})

            finally:
                try:
                    if temp_file and os.path.exists(temp_file):
                        os.unlink(temp_file)
                    if exe_file and os.path.exists(exe_file):
                        os.unlink(exe_file)
                except:
                    pass

    except subprocess.TimeoutExpired:
        return jsonify({'output': 'Erro: Tempo de execução excedido (5s)'})
    except Exception as e:
        return jsonify({'output': f'Erro: {str(e)}'})

@app.route('/download', methods=['POST'])
@login_required
def download_code():
    file_id = request.json.get('file_id')
    user_file = UserFile.query.filter_by(id=file_id, user_id=current_user.id).first()
    if not user_file:
        return jsonify({'success': False, 'error': 'Arquivo não encontrado.'}), 404
    
    # Normaliza as quebras de linha
    content = user_file.content or ''
    content = content.replace('\r\n', '\n').replace('\r', '\n')
    content = content.rstrip('\n') + '\n'
    
    with tempfile.NamedTemporaryFile(suffix=os.path.splitext(user_file.filename)[1], delete=False, mode='w', encoding='utf-8', newline='\n') as f:
        f.write(content)
        temp_file = f.name
    return send_file(temp_file, as_attachment=True, download_name=user_file.filename)

@app.route('/new_file', methods=['POST'])
@login_required
def new_file():
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'Dados JSON inválidos'}), 400
            
        filename = data.get('filename')
        if not filename:
            return jsonify({'success': False, 'error': 'Nome do arquivo não fornecido'})
            
        filename = os.path.basename(filename)
        allowed_extensions = {'.c', '.h', '.cpp', '.hpp', '.py'}
        _, ext = os.path.splitext(filename)
        
        if ext not in allowed_extensions:
            return jsonify({'success': False, 'error': 'Extensão não permitida. Use: .c, .h, .cpp, .hpp ou .py'})
            
        # Verifica se o usuário já tem um arquivo com esse nome
        if UserFile.query.filter_by(user_id=current_user.id, filename=filename).first():
            return jsonify({'success': False, 'error': 'Arquivo já existe.'})
            
        user_file = UserFile(filename=filename, content='', user_id=current_user.id)
        db.session.add(user_file)
        db.session.commit()
        return jsonify({'success': True, 'file_id': user_file.id})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/list_files', methods=['GET'])
@login_required
def list_files():
    files = UserFile.query.filter_by(user_id=current_user.id).all()
    return jsonify({'files': [{'id': f.id, 'filename': f.filename} for f in files]})

@app.route('/save_file', methods=['POST'])
@login_required
def save_file():
    try:
        data = request.json
        file_id = data.get('file_id')
        content = data.get('content', '')
        
        if len(content.encode('utf-8')) > 16 * 1024 * 1024:  # 16MB limit
            return jsonify({'success': False, 'error': 'Arquivo muito grande.'})
            
        user_file = UserFile.query.filter_by(id=file_id, user_id=current_user.id).first()
        if not user_file:
            return jsonify({'success': False, 'error': 'Arquivo não encontrado.'})
        
        # Normaliza as quebras de linha para evitar problemas
        content = content.replace('\r\n', '\n').replace('\r', '\n')
        # Remove quebras de linha extras no final do arquivo
        content = content.rstrip('\n') + '\n'
            
        user_file.content = content
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Erro ao salvar arquivo.'}), 500

@app.route('/delete_file', methods=['POST'])
@login_required
def delete_file():
    try:
        data = request.get_json()
        file_id = data.get('file_id')
        user_file = UserFile.query.filter_by(id=file_id, user_id=current_user.id).first()
        if not user_file:
            return jsonify({'success': False, 'error': 'Arquivo não encontrado.'}), 404
        db.session.delete(user_file)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Adicione uma rota para inicializar o banco de dados e redirecionar para a página inicial após a inicialização
@app.route('/init_db')
def init_db():
    db.create_all()
    return render_template('index.html')

# Rota para servir o favicon
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

# Forçar a criação das tabelas ao iniciar o servidor
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=13000)