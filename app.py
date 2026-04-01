import os
import re
import secrets
from datetime import datetime, timedelta
import traceback

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify,
    session,
    abort,
    flash,
)
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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload, selectinload


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))

import logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Dummy in-memory storage (replace with a database)
users = ["anelo", "aleon", "george"]
private_messages = []  # List of dicts: {from_user, to_user, content, timestamp, id}

message_id_counter = 1

# ---------------- CONFIG ----------------
def get_user_messages(user1, user2):
    """Return messages between two users, sorted by timestamp."""
    msgs = [msg for msg in private_messages
            if (msg['from_user'] == user1 and msg['to_user'] == user2)
            or (msg['from_user'] == user2 and msg['to_user'] == user1)]
    return sorted(msgs, key=lambda x: x['timestamp'])

def get_database_uri():
    db_url = os.environ.get("DATABASE_URL", "sqlite:///db.sqlite3")
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    return db_url


is_production = (
    os.environ.get("RENDER") is not None
    or os.environ.get("FLASK_ENV") == "production"
)

secret_key = os.environ.get("SECRET_KEY")
if is_production and not secret_key:
    raise RuntimeError("SECRET_KEY environment variable is required in production")

app.config["SECRET_KEY"] = secret_key or "dev-secret-key-change-this-in-production"
app.config["SQLALCHEMY_DATABASE_URI"] = get_database_uri()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # 1 MB request cap

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = is_production
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SECURE"] = is_production
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=7)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message_category = "info"
login_manager.init_app(app)

REACTION_TYPES = ("like", "love", "laugh")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref="posts", lazy="joined")

    reactions = db.relationship(
        "Reaction",
        backref="post",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="Reaction.id",
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

    user = db.relationship("User", backref="reactions", lazy="joined")

    __table_args__ = (
        UniqueConstraint("user_id", "post_id", name="unique_user_post_reaction"),
    )


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref="chat_messages", lazy="joined")


# ---------------- HELPERS ----------------
def normalize_username(username):
    return (username or "").strip().lower()


def valid_username(username):
    return re.fullmatch(r"[a-z0-9_]{3,30}", username) is not None


def get_or_create_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_or_create_csrf_token}


def validate_csrf():
    session_token = session.get("_csrf_token", "")
    form_token = request.form.get("csrf_token", "")
    header_token = request.headers.get("X-CSRFToken", "")
    json_token = ""

    if request.is_json:
        data = request.get_json(silent=True) or {}
        json_token = str(data.get("csrf_token", ""))

    request_token = form_token or header_token or json_token

    if not session_token or not request_token:
        abort(400, description="Missing CSRF token")

    if not secrets.compare_digest(session_token, request_token):
        abort(400, description="Invalid CSRF token")


@app.before_request
def protect_from_csrf():
    if request.method not in SAFE_METHODS:
        validate_csrf()


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def get_posts_query():
    return (
        Post.query.options(
            joinedload(Post.user),
            selectinload(Post.reactions),
        )
        .order_by(Post.id.desc())
    )


def load_posts_with_reactions():
    posts = get_posts_query().all()
    post_items = []
    current_user_id = current_user.id if current_user.is_authenticated else None

    for post in posts:
        current_user_reaction = None
        reactions_summary = {reaction: 0 for reaction in REACTION_TYPES}

        for reaction in post.reactions:
            if reaction.reaction_type in reactions_summary:
                reactions_summary[reaction.reaction_type] += 1
            if current_user_id is not None and reaction.user_id == current_user_id:
                current_user_reaction = reaction.reaction_type

        post_items.append(
            {
                "id": post.id,
                "content": post.content,
                "user": post.user.username,
                "reactions": reactions_summary,
                "current_user_reaction": current_user_reaction,
            }
        )

    return post_items


def load_chat_messages(limit=100):
    messages = (
        ChatMessage.query.options(joinedload(ChatMessage.user))
        .order_by(ChatMessage.id.asc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": msg.id,
            "content": msg.content,
            "user": msg.user.username,
            "created_at": msg.created_at.isoformat(),
        }
        for msg in messages
    ]


def render_feed(error=None):
    return render_template(
        "feed.html",
        posts=load_posts_with_reactions(),
        error=error,
    )


# ---------------- LOGIN ----------------
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


@login_manager.unauthorized_handler
def unauthorized():
    flash("Please log in to continue.", "info")
    return redirect(url_for("login"))


# ---------------- ROUTES ----------------
# PRIVATE CHAT STORAGE (replace with DB)
private_messages = []
message_id = 1

def get_private_messages(user1, user2):
    return sorted([
        m for m in private_messages
        if (m["from"] == user1 and m["to"] == user2) or
           (m["from"] == user2 and m["to"] == user1)
    ], key=lambda x: x["id"])


@app.route("/chat/private/<username>")
def get_private_chat(username):
    current_user = session.get("username")
    msgs = get_private_messages(current_user, username)
    return jsonify(msgs)


@app.route("/chat/private/send/<username>", methods=["POST"])
def send_private_chat(username):
    global message_id
    current_user = session.get("username")

    content = request.form.get("content", "").strip()
    if not content:
        return jsonify({"success": False})

    msg = {
        "id": message_id,
        "from": current_user,
        "to": username,
        "content": content
    }
    message_id += 1
    private_messages.append(msg)

    return jsonify({"success": True})

@app.route("/private/<username>")
def private_chat(username):
    current_user = session.get("username", "george")  # Replace with your auth
    if username not in users or username == current_user:
        return "Invalid user", 404
    messages = get_user_messages(current_user, username)
    return render_template("private_chat.html", chat_user=username, messages=messages, current_user=current_user)

@app.route("/private/<username>/send", methods=["POST"])
def send_private_message(username):
    global message_id_counter
    current_user = session.get("username", "aleon")
    if username not in users or username == current_user:
        return jsonify({"success": False, "error": "Invalid user"}), 400

    content = request.form.get("content", "").strip()
    if not content:
        return jsonify({"success": False, "error": "Empty message"}), 400

    msg = {
        "id": message_id_counter,
        "from_user": current_user,
        "to_user": username,
        "content": content,
        "timestamp": datetime.utcnow()
    }
    message_id_counter += 1
    private_messages.append(msg)
    return jsonify({"success": True, "message": msg})

@app.route("/private/<username>/messages")
def fetch_private_messages(username):
    current_user = session.get("username", "anelo")
    if username not in users or username == current_user:
        return jsonify([])
    msgs = get_user_messages(current_user, username)
    return jsonify(msgs)

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("feed"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("feed"))

    if request.method == "POST":
        username = normalize_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            return render_template(
                "register.html",
                error="All fields are required",
            )

        if not valid_username(username):
            return render_template(
                "register.html",
                error="Username must be 3-30 characters and contain only letters, numbers, and underscores",
            )

        if len(password) < 8:
            return render_template(
                "register.html",
                error="Password must be at least 8 characters",
            )

        user = User(username=username)
        user.set_password(password)

        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return render_template(
                "register.html",
                error="Username already taken",
            )

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("feed"))

    if request.method == "POST":
        try:
            username = normalize_username(request.form.get("username", ""))
            password = request.form.get("password", "")

            if not username or not password:
                return render_template("login.html", error="All fields are required")

            user = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                remember = request.form.get("remember") == "on"
                login_user(user, remember=remember)
                flash("Logged in successfully.", "success")
                return redirect(url_for("feed"))

            return render_template("login.html", error="Invalid username or password"), 401

        except Exception as e:
            db.session.rollback()
            print("LOGIN ERROR:", str(e))
            traceback.print_exc()
            return render_template("login.html", error="Server error during login"), 500

    return render_template("login.html")


@app.route("/feed", methods=["GET", "POST"])
@login_required
def feed():
    if request.method == "POST":
        content = request.form.get("content", "").strip()

        if not content:
            return render_feed(error="Post cannot be empty")

        if len(content) > 200:
            return render_feed(error="Post must be 200 characters or fewer")

        post = Post(content=content, user=current_user)

        try:
            db.session.add(post)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return render_feed(error="Unable to create post right now. Please try again.")

        # supports fetch() posting from feed.js
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": True}), 201

        flash("Post created.", "success")
        return redirect(url_for("feed"))

    return render_feed()


@app.route("/messages")
@login_required
def messages():
    return jsonify(load_posts_with_reactions())


@app.route("/chat/messages")
@login_required
def chat_messages():
    return jsonify(load_chat_messages())


@app.route("/chat/send", methods=["POST"])
@login_required
def chat_send():
    content = request.form.get("content", "").strip()

    if not content:
        return jsonify({"success": False, "error": "Message cannot be empty"}), 400

    if len(content) > 300:
        return jsonify({"success": False, "error": "Message must be 300 characters or fewer"}), 400

    message = ChatMessage(content=content, user=current_user)

    try:
        db.session.add(message)
        db.session.commit()
        return jsonify({"success": True}), 201
    except Exception:
        db.session.rollback()
        return jsonify({"success": False, "error": "Unable to send message"}), 500


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
        post_id=post.id,
    ).first()

    try:
        if existing_reaction:
            if existing_reaction.reaction_type == reaction_type:
                db.session.delete(existing_reaction)
                db.session.commit()
                db.session.refresh(post)
                return jsonify(
                    {
                        "success": True,
                        "action": "removed",
                        "reactions": post.reaction_summary(),
                    }
                )

            existing_reaction.reaction_type = reaction_type
            db.session.commit()
            db.session.refresh(post)
            return jsonify(
                {
                    "success": True,
                    "action": "updated",
                    "reactions": post.reaction_summary(),
                }
            )

        new_reaction = Reaction(
            user_id=current_user.id,
            post_id=post.id,
            reaction_type=reaction_type,
        )
        db.session.add(new_reaction)
        db.session.commit()
        db.session.refresh(post)

        return jsonify(
            {
                "success": True,
                "action": "added",
                "reactions": post.reaction_summary(),
            }
        )

    except IntegrityError:
        db.session.rollback()
        return jsonify(
            {
                "success": False,
                "error": "Could not save reaction",
            }
        ), 409

    except Exception:
        db.session.rollback()
        return jsonify(
            {
                "success": False,
                "error": "Something went wrong",
            }
        ), 500


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.pop("_csrf_token", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/test-db")
def test_db():
    try:
        return {
            "users": User.query.count(),
            "posts": Post.query.count(),
            "reactions": Reaction.query.count(),
            "chat_messages": ChatMessage.query.count(),
        }
    except Exception as e:
        app.logger.exception("TEST_DB ERROR")
        return {"error": str(e)}, 500


# ---------------- ERROR HANDLERS ----------------
@app.errorhandler(400)
def bad_request(error):
    description = getattr(error, "description", "Bad request")

    if request.path.startswith("/react/") or request.path.startswith("/chat/"):
        return jsonify({"success": False, "error": description}), 400

    if current_user.is_authenticated:
        return render_feed(error=description), 400

    if request.path == url_for("register"):
        return render_template("register.html", error=description), 400

    return render_template("login.html", error=description), 400


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/react/") or request.path.startswith("/chat/"):
        return jsonify({"success": False, "error": "Not found"}), 404

    if current_user.is_authenticated:
        return render_feed(error="Page not found"), 404

    return render_template("login.html", error="Page not found"), 404


@app.errorhandler(413)
def request_too_large(error):
    if current_user.is_authenticated:
        return render_feed(error="Request too large"), 413
    return render_template("login.html", error="Request too large"), 413


# ---------------- STARTUP ----------------
with app.app_context():
    db.create_all()


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=not is_production)
