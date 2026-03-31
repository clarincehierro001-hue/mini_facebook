import os
import re
from datetime import timedelta

from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import UniqueConstraint

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))

# ---------------- CONFIG ----------------
def get_database_uri():
    db_url = os.environ.get("DATABASE_URL", "sqlite:///db.sqlite3")
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    return db_url


app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-this-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = get_database_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

is_production = os.environ.get("RENDER") is not None or os.environ.get("FLASK_ENV") == "production"

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = is_production
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SECURE"] = is_production
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=7)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

REACTION_TYPES = ("like", "love", "laugh")


# ---------------- MODELS ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref="posts")

    reactions = db.relationship(
        "Reaction",
        backref="post",
        cascade="all, delete-orphan",
        lazy=True
    )

    def reaction_summary(self):
        summary = {reaction: 0 for reaction in REACTION_TYPES}
        for reaction in self.reactions:
            if reaction.reaction_type in summary:
                summary[reaction.reaction_type] += 1
        return summary


class Reaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reaction_type = db.Column(db.String(10), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)

    user = db.relationship("User", backref="reactions")

    __table_args__ = (
        UniqueConstraint("user_id", "post_id", name="unique_user_post_reaction"),
    )


# ---------------- HELPERS ----------------
def normalize_username(username):
    return username.strip().lower()


def valid_username(username):
    return re.fullmatch(r"[a-z0-9_]{3,30}", username) is not None


def load_posts_with_reactions():
    posts = Post.query.order_by(Post.id.desc()).all()
    post_items = []

    for post in posts:
        post_items.append({
            "id": post.id,
            "content": post.content,
            "user": post.user.username,
            "reactions": post.reaction_summary()
        })

    return post_items


# ---------------- LOGIN ----------------
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


# ---------------- ROUTES ----------------
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("feed"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("register.html", error="All fields are required")

        if not valid_username(username):
            return render_template(
                "register.html",
                error="Username must be 3-30 characters and contain only letters, numbers, and underscores",
            )

        if len(password) < 8:
            return render_template(
                "register.html",
                error="Password must be at least 8 characters"
            )

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template("register.html", error="Username already taken")

        user = User(username=username)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user, remember=remember)
            return redirect(url_for("feed"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/feed", methods=["GET", "POST"])
@login_required
def feed():
    if request.method == "POST":
        content = request.form.get("content", "").strip()

        if not content:
            return render_template(
                "feed.html",
                posts=load_posts_with_reactions(),
                error="Post cannot be empty"
            )

        if len(content) > 200:
            return render_template(
                "feed.html",
                posts=load_posts_with_reactions(),
                error="Post must be 200 characters or fewer"
            )

        post = Post(content=content, user=current_user)
        db.session.add(post)
        db.session.commit()

        return redirect(url_for("feed"))

    return render_template("feed.html", posts=load_posts_with_reactions())


@app.route("/messages")
@login_required
def messages():
    return jsonify(load_posts_with_reactions())


@app.route("/react/<int:post_id>", methods=["POST"])
@login_required
def react(post_id):
    data = request.get_json(silent=True) or {}
    reaction_type = str(data.get("reaction", "")).strip().lower()

    if reaction_type not in REACTION_TYPES:
        return jsonify({"success": False, "error": "Invalid reaction"}), 400

    post = db.session.get(Post, post_id)
    if not post:
        return jsonify({"success": False, "error": "Post not found"}), 404

    existing_reaction = Reaction.query.filter_by(
        user_id=current_user.id,
        post_id=post.id
    ).first()

    if existing_reaction:
        if existing_reaction.reaction_type == reaction_type:
            db.session.delete(existing_reaction)
            db.session.commit()
            return jsonify({
                "success": True,
                "action": "removed",
                "reactions": post.reaction_summary()
            })

        existing_reaction.reaction_type = reaction_type
        db.session.commit()
        return jsonify({
            "success": True,
            "action": "updated",
            "reactions": post.reaction_summary()
        })

    new_reaction = Reaction(
        user_id=current_user.id,
        post_id=post.id,
        reaction_type=reaction_type
    )
    db.session.add(new_reaction)
    db.session.commit()

    return jsonify({
        "success": True,
        "action": "added",
        "reactions": post.reaction_summary()
    })


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ---------------- STARTUP ----------------
with app.app_context():
    db.create_all()


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=not is_production)