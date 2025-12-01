import os
import random
from flask import Flask, render_template, session, redirect, url_for, request, flash
from werkzeug.utils import secure_filename

# --- Конфигурация ---
UPLOAD_FOLDER = 'uploads'
COMPLETED_FOLDER = os.path.join(UPLOAD_FOLDER, 'completed')
ALLOWED_EXTENSIONS = {'txt'}
LEARNED_THRESHOLD = 5

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['COMPLETED_FOLDER'] = COMPLETED_FOLDER
app.secret_key = 'super_secret_key_for_multi_dictionary_quiz_app'

@app.context_processor
def inject_constants():
    """Делает константы доступными во всех шаблонах."""
    return dict(LEARNED_THRESHOLD=LEARNED_THRESHOLD)

# --- Вспомогательные функции ---

def allowed_file(filename):
    """Проверяет, что у файла разрешенное расширение."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_dictionary_path(dictionary_name):
    """
    Возвращает путь к файлу словаря, ищет в обеих папках.
    Возвращает None, если файл не найден.
    """
    if dictionary_name == 'default.txt':
        return 'default.txt'
    
    active_path = os.path.join(app.config['UPLOAD_FOLDER'], dictionary_name)
    completed_path = os.path.join(app.config['COMPLETED_FOLDER'], dictionary_name)
    
    if os.path.exists(active_path):
        return active_path
    if os.path.exists(completed_path):
        return completed_path
        
    return None

def load_dictionary(dictionary_name):
    """
    Загружает указанный словарь.
    Формат строки: 'eng:rus:score'. Score - опционально.
    Возвращает dict: {'word': {'translation': 'rus', 'score': 0}}
    """
    file_path = get_dictionary_path(dictionary_name)
    if not file_path or not os.path.exists(file_path):
        return None
    
    dictionary = {}
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 2:
                eng = parts[0].lower()
                rus = parts[1]
                score = 0
                if len(parts) > 2:
                    try:
                        score = int(parts[2])
                    except (ValueError, IndexError):
                        score = 0
                dictionary[eng] = {'translation': rus, 'score': score}
    return dictionary

def save_dictionary(dictionary_name, dictionary_data):
    """Сохраняет словарь в файл в формате 'eng:rus:score'."""
    file_path = get_dictionary_path(dictionary_name)
    if not file_path: # Если вдруг файл был удален или перемещен
        flash(f'Не удалось найти путь для сохранения словаря {dictionary_name}', 'error')
        return

    with open(file_path, 'w', encoding='utf-8') as f:
        for eng, data in dictionary_data.items():
            line = f"{eng}:{data['translation']}:{data['score']}\n"
            f.write(line)

# --- Маршруты (Routes) ---

@app.route('/')
def home():
    """Главная страница со списками словарей и формой загрузки."""
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['COMPLETED_FOLDER'], exist_ok=True)
    
    active_files = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], f))]
    completed_files = os.listdir(app.config['COMPLETED_FOLDER'])

    active_dictionaries = ['default.txt'] + [f for f in active_files if allowed_file(f)]
    completed_dictionaries = [f for f in completed_files if allowed_file(f)]
    
    return render_template('home.html', 
                           active_dictionaries=active_dictionaries,
                           completed_dictionaries=completed_dictionaries)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Обрабатывает загрузку файла словаря."""
    if 'file' not in request.files:
        flash('Не могу найти файл')
        return redirect(url_for('home'))
    file = request.files['file']
    if file.filename == '':
        flash('Файл не выбран')
        return redirect(url_for('home'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash(f'Словарь "{filename}" успешно загружен!')
        return redirect(url_for('home'))
    else:
        flash('Разрешены только файлы с расширением .txt')
        return redirect(url_for('home'))

@app.route('/move_to_completed/<string:dictionary_name>')
def move_to_completed(dictionary_name):
    """Перемещает словарь в папку завершенных."""
    if dictionary_name == 'default.txt':
        flash('Словарь по умолчанию нельзя переместить.')
        return redirect(url_for('home'))
        
    src_path = os.path.join(app.config['UPLOAD_FOLDER'], dictionary_name)
    dest_path = os.path.join(app.config['COMPLETED_FOLDER'], dictionary_name)

    if os.path.exists(src_path):
        os.rename(src_path, dest_path)
        flash(f'Словарь "{dictionary_name}" перемещен в завершенные.')
    else:
        flash('Файл не найден.')
    return redirect(url_for('home'))

@app.route('/restore_from_completed/<string:dictionary_name>')
def restore_from_completed(dictionary_name):
    """Восстанавливает словарь из завершенных."""
    src_path = os.path.join(app.config['COMPLETED_FOLDER'], dictionary_name)
    dest_path = os.path.join(app.config['UPLOAD_FOLDER'], dictionary_name)

    if os.path.exists(src_path):
        os.rename(src_path, dest_path)
        flash(f'Словарь "{dictionary_name}" восстановлен.')
    else:
        flash('Файл не найден.')
    return redirect(url_for('home'))

@app.route('/quiz/<string:dictionary_name>')
def quiz(dictionary_name):
    """Страница викторины для выбранного словаря."""
    if 'quiz_dictionaries' not in session:
        session['quiz_dictionaries'] = {}

    if dictionary_name not in session['quiz_dictionaries']:
        full_dictionary = load_dictionary(dictionary_name)
        if not full_dictionary:
            flash(f"Словарь '{dictionary_name}' не найден.")
            return redirect(url_for('home'))
        session['quiz_dictionaries'][dictionary_name] = full_dictionary
        session.modified = True
    
    current_dictionary = session['quiz_dictionaries'][dictionary_name]
    
    word_pool = [word for word, data in current_dictionary.items() if data['score'] < LEARNED_THRESHOLD]

    if not word_pool:
        return redirect(url_for('completed', dictionary_name=dictionary_name))

    word_to_translate = random.choice(word_pool)
    correct_translation = current_dictionary[word_to_translate]['translation']
    
    all_translations = [data['translation'] for data in current_dictionary.values()]
    incorrect_translations = [t for t in all_translations if t != correct_translation]
    
    num_incorrect = min(3, len(incorrect_translations))
    random_incorrect_options = random.sample(incorrect_translations, num_incorrect)

    options = random_incorrect_options + [correct_translation]
    random.shuffle(options)

    return render_template('quiz.html', 
        word_to_translate=word_to_translate.capitalize(), 
        options=options,
        dictionary_name=dictionary_name
    )

@app.route('/check/<string:dictionary_name>')
def check_answer(dictionary_name):
    """Проверяет ответ, обновляет сессию и сохраняет в файл."""
    word = request.args.get('word', '').lower()
    user_answer = request.args.get('answer', '')

    # Проверяем, что словарь все еще в сессии. Если нет - редирект
    if not word or not user_answer or dictionary_name not in session.get('quiz_dictionaries', {}):
        flash('Сессия для данного словаря устарела, начните заново.', 'warning')
        return redirect(url_for('home'))

    current_dictionary = session['quiz_dictionaries'][dictionary_name]
    correct_translation = current_dictionary[word].get('translation')
    is_correct = (user_answer == correct_translation)

    if is_correct:
        current_dictionary[word]['score'] += 1
        session.modified = True
        save_dictionary(dictionary_name, current_dictionary)
    
    options = request.args.getlist('option')
    score = current_dictionary[word]['score']

    return render_template('answer.html',
        word_to_translate=word.capitalize(),
        options=options,
        user_answer=user_answer,
        correct_answer=correct_translation,
        is_correct=is_correct,
        score=score,
        dictionary_name=dictionary_name
    )

@app.route('/completed/<string:dictionary_name>')
def completed(dictionary_name):
    """Страница завершения для конкретного словаря."""
    return render_template('completed.html', dictionary_name=dictionary_name)

@app.route('/reset_scores/<string:dictionary_name>')
def reset_scores(dictionary_name):
    """Сбрасывает счет в файле и в сессии."""
    full_dictionary = load_dictionary(dictionary_name)
    if full_dictionary:
        for word in full_dictionary:
            full_dictionary[word]['score'] = 0
        save_dictionary(dictionary_name, full_dictionary)
        
        if 'quiz_dictionaries' in session and dictionary_name in session['quiz_dictionaries']:
            del session['quiz_dictionaries'][dictionary_name]
            session.modified = True
        flash(f'Счет для словаря "{dictionary_name}" сброшен.')
    else:
        flash(f'Не удалось найти словарь "{dictionary_name}".')
        
    return redirect(url_for('home'))

@app.route('/delete/<string:dictionary_name>')
def delete_dictionary(dictionary_name):
    """Удаляет загруженный словарь из любой папки."""
    if dictionary_name == 'default.txt':
        flash('Словарь по умолчанию нельзя удалить.')
        return redirect(url_for('home'))

    file_path = get_dictionary_path(dictionary_name)
    if file_path and os.path.exists(file_path):
        os.remove(file_path)
        if 'quiz_dictionaries' in session and dictionary_name in session['quiz_dictionaries']:
            del session['quiz_dictionaries'][dictionary_name]
            session.modified = True
        flash(f'Словарь "{dictionary_name}" удален.')
    else:
        flash(f'Не удалось найти словарь "{dictionary_name}" для удаления.')
    
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5001)
