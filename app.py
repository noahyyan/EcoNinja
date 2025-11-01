from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get("ECONINJA_SECRET", "econinja_secret_key_change_this")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///econinja.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ------------------------
# Database models
# ------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    student_id = db.Column(db.String(50), unique=True, nullable=True)  # school ID
    role = db.Column(db.String(20), default="student")  # 'student' or 'admin'
    points = db.Column(db.Integer, default=0)

class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    trash_type = db.Column(db.String(80))
    weight_kg = db.Column(db.Float, nullable=True)
    points_awarded = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Reward(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    cost = db.Column(db.Integer)
    stock = db.Column(db.Integer, default=1)

class Redemption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    reward_id = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ------------------------
# Helpers
# ------------------------
# --- Points Calculation Function ---
def calc_points(trash_type, weight):
    """
    Calculates points based on trash type and weight.
    Lighter materials are worth more per kg.
    """
    multipliers = {
        "plastic": 80.0,
        "paper": 60.0,
        "glass": 40.0,
        "metal": 30.0,
        "organic": 20.0,
        "other": 10.0
    }

    # Get multiplier based on trash type
    multiplier = multipliers.get(trash_type.lower(), multipliers["other"])
    pts = round(weight * multiplier, 2)

    # Optional bonus for recyclables
    if trash_type.lower() in ["plastic", "paper"]:
        pts = round(pts * 1.1, 2)  # +10% bonus

    return pts


def logged_in_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return User.query.get(uid)

# ------------------------
# Routes - Auth
# ------------------------
@app.route("/")
def index():
    if session.get("user_id"):
        user = User.query.get(session["user_id"])
        if user.role == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("student_dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        student_id = request.form["student_id"].strip()

        if not username or not password or not student_id:
            flash("Please fill all fields.")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.")
            return redirect(url_for("register"))
        if User.query.filter_by(student_id=student_id).first():
            flash("Student ID already registered.")
            return redirect(url_for("register"))

        hashed = generate_password_hash(password, method="pbkdf2:sha256")
        u = User(username=username, password=hashed, student_id=student_id, role="student", points=0)
        db.session.add(u)
        db.session.commit()
        flash("Registered! Please login.")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            flash("Logged in.")
            return redirect(url_for("index"))
        flash("Invalid credentials.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Logged out.")
    return redirect(url_for("login"))

# ------------------------
# Student views
# ------------------------
@app.route("/student/dashboard")
def student_dashboard():
    user = logged_in_user()
    if not user or user.role != "student":
        return redirect(url_for("login"))
    recent = Record.query.filter_by(user_id=user.id).order_by(Record.timestamp.desc()).limit(5).all()
    rank = None
    students = User.query.filter_by(role="student").order_by(User.points.desc()).all()
    for idx, s in enumerate(students, start=1):
        if s.id == user.id:
            rank = idx
            break
    return render_template("student_dashboard.html", user=user, recent=recent, rank=rank)

@app.route("/student/records")
def student_records():
    user = logged_in_user()
    if not user or user.role != "student":
        return redirect(url_for("login"))
    records = Record.query.filter_by(user_id=user.id).order_by(Record.timestamp.desc()).all()
    return render_template("student_records.html", user=user, records=records)

@app.route("/student/redeem", methods=["GET", "POST"])
def student_redeem():
    user = logged_in_user()
    if not user or user.role != "student":
        return redirect(url_for("login"))
    rewards = Reward.query.all()
    if request.method == "POST":
        rid = int(request.form["reward_id"])
        reward = Reward.query.get(rid)
        if not reward:
            flash("Reward not found.")
            return redirect(url_for("student_redeem"))
        if reward.stock <= 0:
            flash("This item is out of stock.")
            return redirect(url_for("student_redeem"))
        if user.points < reward.cost:
            flash("Not enough points.")
            return redirect(url_for("student_redeem"))
        user.points -= reward.cost
        reward.stock -= 1
        r = Redemption(user_id=user.id, reward_id=reward.id)
        db.session.add(r)
        db.session.commit()
        flash(f"Redeemed {reward.name}!")
        return redirect(url_for("student_redeem"))
    return render_template("student_redeem.html", user=user, rewards=rewards)

@app.route("/leaderboard")
def leaderboard():
    students = User.query.filter_by(role="student").order_by(User.points.desc()).limit(50).all()
    return render_template("leaderboard.html", students=students)

# ------------------------
# Machine view (tablet)
# ------------------------
@app.route("/machine", methods=["GET", "POST"])
def machine():
    if request.method == "POST":
        student_id = request.form.get("student_id").strip()
        trash_type = request.form.get("trash_type").strip().lower()
        weight = float(request.form.get("weight") or 0)
        user = User.query.filter_by(student_id=student_id).first()
        if not user:
            flash("Student ID not found.")
            return redirect(url_for("machine"))
        pts = calc_points(trash_type, weight)
        rec = Record(user_id=user.id, trash_type=trash_type, weight_kg=weight, points_awarded=pts)
        user.points += pts
        db.session.add(rec)
        db.session.commit()
        flash(f"Added: {trash_type} {weight}kg — +{pts} pts to {user.username}")
        return redirect(url_for("machine"))
    trash_options = ["Plastic", "Paper", "Metal", "Glass", "Organic", "Other"]
    return render_template("machine.html", trash_options=trash_options)

@app.route("/api/add_record", methods=["POST"])
def api_add_record():
    data = request.get_json(force=True)
    student_id = data.get("student_id")
    trash_type = (data.get("trash_type") or "other").lower()
    weight = float(data.get("weight") or 0)
    user = User.query.filter_by(student_id=student_id).first()
    if not user:
        return jsonify({"ok": False, "error": "student not found"}), 404
    pts = calc_points(trash_type, weight)
    rec = Record(user_id=user.id, trash_type=trash_type, weight_kg=weight, points_awarded=pts)
    user.points += pts
    db.session.add(rec)
    db.session.commit()
    return jsonify({"ok": True, "awarded": pts, "new_points": user.points})

# ------------------------
# Admin views
# ------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        user = User.query.filter_by(username=username, role="admin").first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            flash("Admin logged in.")
            return redirect(url_for("admin_dashboard"))
        flash("Invalid admin credentials.")
    return render_template("admin_login.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    user = logged_in_user()
    if not user or user.role != "admin":
        return redirect(url_for("admin_login"))
    total_students = User.query.filter_by(role="student").count()
    total_records = Record.query.count()
    total_points = sum([s.points for s in User.query.filter_by(role="student").all()])
    return render_template("admin_dashboard.html",
                           admin=user,
                           total_students=total_students,
                           total_records=total_records,
                           total_points=total_points)

@app.route("/admin/students")
def admin_students():
    user = logged_in_user()
    if not user or user.role != "admin":
        return redirect(url_for("admin_login"))
    students = User.query.filter_by(role="student").all()
    return render_template("admin_students.html", students=students)

@app.route("/admin/delete_student/<int:sid>", methods=["POST"])
def admin_delete_student(sid):
    user = logged_in_user()
    if not user or user.role != "admin":
        return redirect(url_for("admin_login"))
    s = User.query.get(sid)
    if s:
        Record.query.filter_by(user_id=s.id).delete()
        db.session.delete(s)
        db.session.commit()
        flash("Student deleted.")
    return redirect(url_for("admin_students"))

@app.route("/admin/rewards", methods=["GET", "POST"])
def admin_rewards():
    user = logged_in_user()
    if not user or user.role != "admin":
        return redirect(url_for("admin_login"))
    if request.method == "POST":
        name = request.form["name"].strip()
        cost = int(request.form["cost"])
        stock = int(request.form["stock"])
        r = Reward(name=name, cost=cost, stock=stock)
        db.session.add(r)
        db.session.commit()
        flash("Reward added.")
        return redirect(url_for("admin_rewards"))
    rewards = Reward.query.all()
    return render_template("admin_rewards.html", rewards=rewards)

@app.route("/admin/delete_reward/<int:rid>", methods=["POST"])
def admin_delete_reward(rid):
    user = logged_in_user()
    if not user or user.role != "admin":
        return redirect(url_for("admin_login"))
    r = Reward.query.get(rid)
    if r:
        db.session.delete(r)
        db.session.commit()
        flash("Reward deleted.")
    return redirect(url_for("admin_rewards"))

# ------------------------
# Initialization + default admin
# ------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            admin_pw = generate_password_hash("admin123", method="pbkdf2:sha256")
            admin = User(username="admin", password=admin_pw, role="admin")
            db.session.add(admin)
            sample_rewards = [
                Reward(name="Notebook", cost=100, stock=200),
                Reward(name="Stationery Pack", cost=200, stock=50),
                Reward(name="Eco Water Bottle", cost=500, stock=15),
                Reward(name="Fidget Spinner", cost=150, stock=20)
            ]
            db.session.add_all(sample_rewards)
            db.session.commit()
    app.run(debug=True)
