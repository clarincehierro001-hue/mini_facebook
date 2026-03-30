from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# ---------------- MODELS ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500))
    user_id = db.Column(db.Integer)

# ---------------- LOGIN ----------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- ROUTES ----------------
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = User(username=request.form['username'],
                    password=request.form['password'])
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.password == request.form['password']:
            login_user(user)
            return redirect(url_for('feed'))
    return render_template('login.html')

@app.route('/feed', methods=['GET', 'POST'])
@login_required
def feed():
    if request.method == 'POST':
        post = Post(content=request.form['content'], user_id=current_user.id)
        db.session.add(post)
        db.session.commit()

    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('feed.html', posts=posts, user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------------- RUN ----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)