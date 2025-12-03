import os
import random
import shutil
from flask import Flask, render_template, session, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

# --- App Initialization and Configuration ---

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['LEARNED_THRESHOLD'] = 5

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите, чтобы получить доступ к этой странице.'

@app.context_processor
def inject_constants():
    """Делает константы доступными во всех шаблонах."""
    return dict(LEARNED_THRESHOLD=app.config['LEARNED_THRESHOLD'])


# --- Database Models ---

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    dictionaries = db.relationship('Dictionary', backref='owner', lazy=True, cascade="all, delete-orphan")
    login_history = db.relationship('LoginHistory', backref='user', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Dictionary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_completed = db.Column(db.Boolean, default=False)

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- Forms ---

class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Это имя пользователя уже занято.')

class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

# --- Flask-Login User Loader ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper Functions ---

def get_user_dictionary_path(username, dictionary_name):
    """Возвращает путь к файлу словаря пользователя."""
    return os.path.join(app.config['UPLOAD_FOLDER'], username, dictionary_name)

def get_user_completed_path(username, dictionary_name):
    """Возвращает путь к файлу завершенного словаря пользователя."""
    return os.path.join(app.config['UPLOAD_FOLDER'], username, 'completed', dictionary_name)

def load_user_dictionary(username, dictionary_name):
    """Загружает словарь пользователя."""
    path = get_user_dictionary_path(username, dictionary_name)
    if not os.path.exists(path):
        path = get_user_completed_path(username, dictionary_name)
        if not os.path.exists(path):
            return None
            
    dictionary = {}
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 2:
                eng = parts[0].lower()
                rus = parts[1]
                score = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
                dictionary[eng] = {'translation': rus, 'score': score}
    return dictionary

def save_user_dictionary(username, dictionary_name, dictionary_data):
    """Сохраняет словарь пользователя."""
    path = get_user_dictionary_path(username, dictionary_name)
    if not os.path.exists(path):
         path = get_user_completed_path(username, dictionary_name)
         if not os.path.exists(path):
            flash(f'Не удалось найти путь для сохранения словаря {dictionary_name}', 'error')
            return
            
    with open(path, 'w', encoding='utf-8') as f:
        for eng, data in dictionary_data.items():
            line = f"{eng}:{data['translation']}:{data['score']}\n"
            f.write(line)

# --- Routes ---

@app.route('/')
def home():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    completed_folder = os.path.join(user_folder, 'completed')
    os.makedirs(user_folder, exist_ok=True)
    os.makedirs(completed_folder, exist_ok=True)

    active_dictionaries = Dictionary.query.filter_by(user_id=current_user.id, is_completed=False).all()
    completed_dictionaries = Dictionary.query.filter_by(user_id=current_user.id, is_completed=True).all()
    
    return render_template('home.html', 
                           active_dictionaries=active_dictionaries,
                           completed_dictionaries=completed_dictionaries)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            # Record the login event
            login_record = LoginHistory(user_id=user.id)
            db.session.add(login_record)
            db.session.commit()
            return redirect(url_for('home'))
        else:
            flash('Неверное имя пользователя или пароль.', 'error')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        # --- Create user folder and copy default dictionary ---
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], user.username)
        completed_folder = os.path.join(user_folder, 'completed')
        os.makedirs(user_folder, exist_ok=True)
        os.makedirs(completed_folder, exist_ok=True)

        # Copy default dictionary
        default_dic_path = 'default.txt'
        if os.path.exists(default_dic_path):
            shutil.copy(default_dic_path, os.path.join(user_folder, 'default.txt'))
            # Add to database
            new_dict = Dictionary(name='default.txt', user_id=user.id)
            db.session.add(new_dict)
            db.session.commit()

        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('Не могу найти файл')
        return redirect(url_for('home'))
    file = request.files['file']
    if file.filename == '':
        flash('Файл не выбран')
        return redirect(url_for('home'))
    if file and '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() == 'txt':
        filename = secure_filename(file.filename)
        
        # Проверяем, не существует ли уже такой словарь
        if Dictionary.query.filter_by(user_id=current_user.id, name=filename).first():
            flash(f'Словарь с именем "{filename}" уже существует.')
            return redirect(url_for('home'))
            
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
        file.save(os.path.join(user_folder, filename))
        
        new_dict = Dictionary(name=filename, user_id=current_user.id)
        db.session.add(new_dict)
        db.session.commit()
        
        flash(f'Словарь "{filename}" успешно загружен!')
    else:
        flash('Разрешены только файлы с расширением .txt')
    return redirect(url_for('home'))


@app.route('/quiz/<string:dictionary_name>')
@login_required
def quiz(dictionary_name):
    dic = Dictionary.query.filter_by(user_id=current_user.id, name=dictionary_name).first_or_404()
    
    session_key = f"quiz_dict_{current_user.id}_{dictionary_name}"

    if session_key not in session:
        full_dictionary = load_user_dictionary(current_user.username, dictionary_name)
        if full_dictionary is None:
            flash(f"Словарь '{dictionary_name}' не найден.")
            return redirect(url_for('home'))
        session[session_key] = full_dictionary
        session.modified = True

    current_dictionary = session[session_key]
    word_pool = [word for word, data in current_dictionary.items() if data['score'] < app.config['LEARNED_THRESHOLD']]

    if not word_pool:
        return redirect(url_for('completed', dictionary_name=dictionary_name))

    word_to_translate = random.choice(word_pool)
    correct_translation = current_dictionary[word_to_translate]['translation']
    
    all_translations = [data['translation'] for data in current_dictionary.values()]
    incorrect_translations = [t for t in all_translations if t != correct_translation]
    
    num_incorrect = min(3, len(incorrect_translations))
    random_incorrect_options = random.sample(incorrect_translations, num_incorrect) if incorrect_translations else []

    options = random_incorrect_options + [correct_translation]
    random.shuffle(options)

    return render_template('quiz.html', 
                           word_to_translate=word_to_translate.capitalize(), 
                           options=options,
                           dictionary_name=dictionary_name)

@app.route('/check/<string:dictionary_name>')
@login_required
def check_answer(dictionary_name):
    word = request.args.get('word', '').lower()
    user_answer = request.args.get('answer', '')
    session_key = f"quiz_dict_{current_user.id}_{dictionary_name}"

    if not word or not user_answer or session_key not in session:
        flash('Сессия для данного словаря устарела, начните заново.', 'warning')
        return redirect(url_for('home'))

    current_dictionary = session[session_key]
    correct_translation = current_dictionary.get(word, {}).get('translation')
    is_correct = (user_answer == correct_translation)

    if is_correct:
        current_dictionary[word]['score'] += 1
        session.modified = True
        save_user_dictionary(current_user.username, dictionary_name, current_dictionary)
    
    return render_template('answer.html',
                           word_to_translate=word.capitalize(),
                           options=request.args.getlist('option'),
                           user_answer=user_answer,
                           correct_answer=correct_translation,
                           is_correct=is_correct,
                           score=current_dictionary.get(word, {}).get('score', 0),
                           dictionary_name=dictionary_name)


@app.route('/move_to_completed/<string:dictionary_name>')
@login_required
def move_to_completed(dictionary_name):
    dic = Dictionary.query.filter_by(user_id=current_user.id, name=dictionary_name).first_or_404()
    
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    completed_folder = os.path.join(user_folder, 'completed')
    
    src = os.path.join(user_folder, dictionary_name)
    dest = os.path.join(completed_folder, dictionary_name)
    
    if os.path.exists(src):
        shutil.move(src, dest)
        dic.is_completed = True
        db.session.commit()
        flash(f'Словарь "{dictionary_name}" перемещен в завершенные.')
    else:
        flash('Файл не найден.', 'error')
    return redirect(url_for('home'))


@app.route('/restore_from_completed/<string:dictionary_name>')
@login_required
def restore_from_completed(dictionary_name):
    dic = Dictionary.query.filter_by(user_id=current_user.id, name=dictionary_name).first_or_404()

    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    completed_folder = os.path.join(user_folder, 'completed')
    
    src = os.path.join(completed_folder, dictionary_name)
    dest = os.path.join(user_folder, dictionary_name)

    if os.path.exists(src):
        shutil.move(src, dest)
        dic.is_completed = False
        db.session.commit()
        flash(f'Словарь "{dictionary_name}" восстановлен.')
    else:
        flash('Файл не найден.', 'error')
    return redirect(url_for('home'))


@app.route('/delete/<string:dictionary_name>')
@login_required
def delete_dictionary(dictionary_name):
    dic = Dictionary.query.filter_by(user_id=current_user.id, name=dictionary_name).first_or_404()
    
    path = get_user_dictionary_path(current_user.username, dictionary_name)
    if not os.path.exists(path):
        path = get_user_completed_path(current_user.username, dictionary_name)

    if os.path.exists(path):
        os.remove(path)

    session_key = f"quiz_dict_{current_user.id}_{dictionary_name}"
    if session_key in session:
        del session[session_key]
        session.modified = True

    db.session.delete(dic)
    db.session.commit()
    flash(f'Словарь "{dictionary_name}" удален.')
    return redirect(url_for('home'))


@app.route('/reset_scores/<string:dictionary_name>')
@login_required
def reset_scores(dictionary_name):
    dic = Dictionary.query.filter_by(user_id=current_user.id, name=dictionary_name).first_or_404()
    
    full_dictionary = load_user_dictionary(current_user.username, dictionary_name)
    if full_dictionary:
        for word in full_dictionary:
            full_dictionary[word]['score'] = 0
        save_user_dictionary(current_user.username, dictionary_name, full_dictionary)
        
        session_key = f"quiz_dict_{current_user.id}_{dictionary_name}"
        if session_key in session:
            del session[session_key]
            session.modified = True
        flash(f'Счет для словаря "{dictionary_name}" сброшен.')
    else:
        flash(f'Не удалось найти словарь "{dictionary_name}".', 'error')
        
    return redirect(url_for('home'))

@app.route('/completed/<string:dictionary_name>')
@login_required
def completed(dictionary_name):
    return render_template('completed.html', dictionary_name=dictionary_name)

# --- Admin Routes ---
@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице.')
        return redirect(url_for('home'))
    # Subquery to find the latest login time for each user
    last_login_subquery = db.session.query(
        LoginHistory.user_id,
        db.func.max(LoginHistory.timestamp).label('last_login_time')
    ).group_by(LoginHistory.user_id).subquery()

    # Query users and join with the subquery to get the last login time
    users = db.session.query(
        User,
        last_login_subquery.c.last_login_time
    ).outerjoin(
        last_login_subquery, User.id == last_login_subquery.c.user_id
    ).all()

    return render_template('admin.html', users_with_login=users)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице.')
        return redirect(url_for('home'))
    
    user_to_edit = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        original_username = request.form.get('original_username')
        new_username = request.form.get('username')
        is_admin = request.form.get('is_admin') == 'on'
        
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate username
        if new_username != original_username and User.query.filter_by(username=new_username).first():
            flash('Это имя пользователя уже занято.', 'error')
            return render_template('edit_user.html', user=user_to_edit)

        # Validate password
        if new_password:
            if new_password != confirm_password:
                flash('Пароли не совпадают.', 'error')
                return render_template('edit_user.html', user=user_to_edit)
            user_to_edit.set_password(new_password)

        # Rename folder if username changes
        if new_username != original_username:
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], original_username)
            new_path = os.path.join(app.config['UPLOAD_FOLDER'], new_username)
            if os.path.exists(old_path):
                try:
                    os.rename(old_path, new_path)
                except OSError as e:
                    flash(f'Не удалось переименовать папку пользователя: {e}', 'error')
                    return render_template('edit_user.html', user=user_to_edit)

        user_to_edit.username = new_username
        user_to_edit.is_admin = is_admin
        db.session.commit()
        flash(f'Данные пользователя {user_to_edit.username} обновлены.', 'success')
        return redirect(url_for('admin_panel'))

    return render_template('edit_user.html', user=user_to_edit)


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('У вас нет прав для доступа к этой странице.')
        return redirect(url_for('home'))
    
    if user_id == current_user.id:
        flash('Вы не можете удалить самого себя.', 'error')
        return redirect(url_for('admin_panel'))

    user_to_delete = User.query.get_or_404(user_id)
    
    # Remove user's dictionary folder
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], user_to_delete.username)
    if os.path.exists(user_folder):
        shutil.rmtree(user_folder)
        
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f'Пользователь {user_to_delete.username} был удален.', 'success')
    return redirect(url_for('admin_panel'))


def init_db_and_admin():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created.")

            # --- Create admin folder and copy default dictionary ---
            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], admin.username)
            completed_folder = os.path.join(user_folder, 'completed')
            os.makedirs(user_folder, exist_ok=True)
            os.makedirs(completed_folder, exist_ok=True)

            # Copy default dictionary
            default_dic_path = 'default.txt'
            if os.path.exists(default_dic_path):
                shutil.copy(default_dic_path, os.path.join(user_folder, 'default.txt'))
                # Add to database
                new_dict = Dictionary(name='default.txt', user_id=admin.id)
                db.session.add(new_dict)
                db.session.commit()
                print("Default dictionary copied for admin.")


if __name__ == '__main__':
    init_db_and_admin()
    app.run(host='0.0.0.0', debug=True, port=5001)
