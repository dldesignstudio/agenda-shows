from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
import sqlite3

app = Flask(__name__)
app.secret_key = 'segredo-super-seguro'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

def get_db():
    conn = sqlite3.connect('agenda.db')
    conn.row_factory = sqlite3.Row
    return conn

class Usuario(UserMixin):
    def __init__(self, id, nome, email):
        self.id = id
        self.nome = nome
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM usuarios WHERE id = ?", (user_id,)).fetchone()
    if user:
        return Usuario(user['id'], user['nome'], user['email'])
    return None

with app.app_context():
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL
        )
    ''')
    db.execute('''
        CREATE TABLE IF NOT EXISTS shows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data TEXT NOT NULL,
            valor REAL NOT NULL,
            local TEXT NOT NULL,
            contratante TEXT NOT NULL,
            usuario_id INTEGER NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        )
    ''')
    db.commit()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        db = get_db()
        user = db.execute("SELECT * FROM usuarios WHERE email = ?", (email,)).fetchone()
        if user and bcrypt.check_password_hash(user['senha'], senha):
            user_obj = Usuario(user['id'], user['nome'], user['email'])
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        flash("Email ou senha inválidos", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = bcrypt.generate_password_hash(request.form['senha']).decode('utf-8')
        db = get_db()
        try:
            db.execute("INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)", (nome, email, senha))
            db.commit()
            flash("Cadastro realizado com sucesso", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Email já está em uso", "danger")
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    db = get_db()
    if request.method == 'POST':
        data = request.form['data']
        valor = request.form['valor']
        local = request.form['local']
        contratante = request.form['contratante']
        db.execute("INSERT INTO shows (data, valor, local, contratante, usuario_id) VALUES (?, ?, ?, ?, ?)",
                   (data, valor, local, contratante, current_user.id))
        db.commit()
    shows = db.execute("SELECT * FROM shows WHERE usuario_id = ?", (current_user.id,)).fetchall()
    return render_template('dashboard.html', shows=shows)

@app.route('/delete/<int:show_id>')
@login_required
def delete(show_id):
    db = get_db()
    db.execute("DELETE FROM shows WHERE id = ? AND usuario_id = ?", (show_id, current_user.id))
    db.commit()
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
