import os
import datetime as dt
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, abort, jsonify, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, func, UniqueConstraint

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "122360356"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
WEEKDAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "e9e88fc4019945639c3be48c2bdd242bc4bfc1791a4738aba143f65cab3b22c3"
)

# -----------------------------
# MySQL (Railway) configuration
# -----------------------------

MYSQL_URI = (
    f"mysql+pymysql://{os.environ['MYSQLUSER']}:"
    f"{os.environ['MYSQLPASSWORD']}@"
    f"{os.environ['MYSQLHOST']}:"
    f"{os.environ['MYSQLPORT']}/"
    f"{os.environ['MYSQLDATABASE']}"
)

app.config["SQLALCHEMY_DATABASE_URI"] = MYSQL_URI

# REQUIRED because you use __bind_key__
app.config["SQLALCHEMY_BINDS"] = {
    "users": MYSQL_URI,
    "businesses": MYSQL_URI,
}

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -----------------------------
# Models
# -----------------------------

class User(db.Model):
    __bind_key__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    verified = db.Column(db.Boolean, nullable=False, server_default="0")


class Business(db.Model):
    __bind_key__ = "businesses"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    verified = db.Column(db.Boolean, nullable=False, server_default="0")


class Post(db.Model):
    __bind_key__ = "businesses"
    id = db.Column(db.Integer, primary_key=True)
    vendor_name = db.Column(db.String(200), nullable=False)
    date = db.Column(db.Date, nullable=False)
    opening_time = db.Column(db.Time)
    closing_time = db.Column(db.Time)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))
    business_id = db.Column(db.Integer, db.ForeignKey("business.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=func.current_timestamp())


class DailySpecial(db.Model):
    __bind_key__ = "businesses"
    id = db.Column(db.Integer, primary_key=True)
    special_name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    weekday = db.Column(db.Integer, nullable=False)  # 0-6
    vendor_name = db.Column(db.String(200), nullable=False)
    business_id = db.Column(db.Integer, db.ForeignKey("business.id"), nullable=False)


# SQLalchemy UNIQUE Constraints
class VendorRating(db.Model):
    __bind_key__ = "users"
    __tablename__ = "vendor_rating"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    business_id = db.Column(db.Integer, nullable=False, index=True)
    score = db.Column(db.Integer, nullable=False)  # 1..5
    created_at = db.Column(db.DateTime, nullable=False, server_default=func.current_timestamp())
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )

    __table_args__ = (
        UniqueConstraint("user_id", "business_id", name="uq_user_business_rating"),
    )

# -----------------------------
# Create ALL tables safely
# -----------------------------
with app.app_context():
    db.create_all()

# -----------------------------
# Auth helpers
# -----------------------------

def login_user(kind, obj=None):
    if kind == "admin":
        session["auth"] = {"kind": "admin", "username": ADMIN_USERNAME}
        return

    if kind == "guest":
        session["auth"] = {"kind": "guest"}
        session.pop("verified", None)
        return

    session["auth"] = {
        "kind": kind,
        "id": obj.id,
        "username": obj.username,
        "email": obj.email,
    }
    session["verified"] = bool(getattr(obj, "verified", False))


def current_user():
    data = session.get("auth") or {}
    kind = data.get("kind")
    if kind == "personal":
        return kind, db.session.get(User, data.get("id"))
    if kind == "business":
        return kind, db.session.get(Business, data.get("id"))
    if kind == "admin":
        return kind, None
    if kind == "guest":
        return kind, None
    return None, None


def require(kind=None, admin=False):
    def decorator(view):
        @wraps(view)
        def wrapper(*a, **kw):
            auth = session.get("auth")
            if not auth:
                flash("Please sign in first.", "warn")
                return redirect(url_for("register"))

            if admin and auth.get("kind") != "admin":
                flash("Admin access required.", "err")
                return redirect(url_for("register"))

            if kind and auth.get("kind") != kind:
                if auth.get("kind") == "business":
                    return redirect(url_for("b_dashboard"))
                if auth.get("kind") == "personal":
                    return redirect(url_for("dashboard"))
                if auth.get("kind") == "admin":
                    return redirect(url_for("admin_page"))
                if auth.get("kind") == "guest":
                    return redirect(url_for("guest"))
            return view(*a, **kw)
        return wrapper
    return decorator


MODELS = {"personal": User, "business": Business}


def unique_identity_taken(email, username):
    return (
        User.query.filter((User.email == email) | (User.username == username)).first()
        or Business.query.filter((Business.email == email) | (Business.username == username)).first()
    )

# =============================
# ROUTES (UNCHANGED)
# =============================

#IS3313 assingment 2
@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        acc = request.form.get("account_type")
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")

        if not all([acc, email, username, password]):
            abort(400, "Missing fields.")

        if unique_identity_taken(email, username):
            flash("Email or username already in use.", "err")
            return redirect(url_for("register"))

        ph = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)

        if acc == "personal":
            db.session.add(User(email=email, username=username, password_hash=ph))
        elif acc == "business":
            db.session.add(Business(email=email, username=username, password_hash=ph))
        else:
            abort(400, "Invalid account type.")

        db.session.commit()
        flash("Account created. You can now sign in.", "ok")
        return redirect(url_for("register"))

    return render_template("register.html")

@app.post("/login")
def login():
    ident = request.form.get("identifier", "").strip()
    password = request.form.get("login_password", "").strip()

    if not ident or not password:
        flash("Missing login fields.", "err")
        return redirect(url_for("register"))

    if ident.lower() == ADMIN_USERNAME.lower() and password == ADMIN_PASSWORD:
        login_user("admin")
        return redirect(url_for("admin_page"))

    u = User.query.filter(or_(User.email == ident, User.username == ident)).first()
    b = Business.query.filter(or_(Business.email == ident, Business.username == ident)).first()

    if u and b:
        flash("Identifier exists in both account types.", "err")
        return redirect(url_for("register"))

    obj, kind = (u, "personal") if u else ((b, "business") if b else (None, None))
    if not obj:
        flash("Account not found.", "err")
        return redirect(url_for("register"))

    if not check_password_hash(obj.password_hash, password):
        flash("Incorrect password.", "err")
        return redirect(url_for("register"))

    login_user(kind, obj)
    return redirect(url_for("b_dashboard" if kind == "business" else "dashboard"))



@app.get("/guest")
def guest():
    login_user("guest")

    selected_category = request.args.get("category", "all")
    sort_by = request.args.get("sort", "rating_desc")

    rating_rows = (
        db.session.query(
            VendorRating.business_id,
            func.avg(VendorRating.score).label("avg_score"),
            func.count(VendorRating.id).label("num_ratings"),
        )
        .group_by(VendorRating.business_id)
        .all()
    )

    avg_by_business = {
        r.business_id: {"avg": float(r.avg_score), "count": int(r.num_ratings)}
        for r in rating_rows
        if r.avg_score is not None
    }

    q = Post.query
    if selected_category != "all":
        q = q.filter(Post.category == selected_category)
    posts = q.all()

    def vendor_avg_for_post(p):
        stats = avg_by_business.get(p.business_id)
        return stats["avg"] if stats else None

    if sort_by == "rating_asc":
        def post_key(p):
            avg = vendor_avg_for_post(p)
            avg_sort = avg if avg is not None else 999999
            created = p.created_at or dt.datetime.min
            return (avg_sort, created)
        posts.sort(key=post_key, reverse=False)

    elif sort_by == "newest":
        posts.sort(
            key=lambda p: (p.date.toordinal() if p.date else 0, p.created_at or dt.datetime.min),
            reverse=True
        )
    else:
        def post_key(p):
            avg = vendor_avg_for_post(p)
            avg_sort = avg if avg is not None else -1
            created = p.created_at or dt.datetime.min
            return (avg_sort, created)
        posts.sort(key=post_key, reverse=True)

    raw_cats = db.session.query(Post.category).distinct().all()
    categories = sorted({c[0] for c in raw_cats if c[0]})

    businesses = Business.query.all()

    def business_avg(biz):
        s = avg_by_business.get(biz.id)
        return s["avg"] if s else None

    if sort_by == "rating_asc":
        businesses.sort(key=lambda b: business_avg(b) if business_avg(b) is not None else 999999)
    elif sort_by == "newest":
        businesses.sort(key=lambda b: b.username.lower())
    else:
        businesses.sort(key=lambda b: business_avg(b) if business_avg(b) is not None else -1, reverse=True)

    return render_template(
        "guest.html",
        posts=posts,
        categories=categories,
        selected_category=selected_category,
        sort_by=sort_by,
        businesses=businesses,
        avg_by_business=avg_by_business,
    )


@app.post("/logout")
def logout():
    session.clear()
    flash("Signed out.", "ok")
    return redirect(url_for("register"))


# Digital Ocean - How To Query Tables and Paginate Data in Flask-SQLAlchemy
@app.get("/dashboard")
@require(kind="personal")
def dashboard():
    _, user = current_user()

    selected_category = request.args.get("category", "all")
    sort_by = request.args.get("sort", "rating_desc")

    rating_rows = (
        db.session.query(
            VendorRating.business_id,
            func.avg(VendorRating.score).label("avg_score"),
            func.count(VendorRating.id).label("num_ratings"),
        )
        .group_by(VendorRating.business_id)
        .all()
    )

    avg_by_business = {
        r.business_id: {"avg": float(r.avg_score), "count": int(r.num_ratings)}
        for r in rating_rows
        if r.avg_score is not None
    }

    q = Post.query
    if selected_category != "all":
        q = q.filter(Post.category == selected_category)
    posts = q.all()

    def vendor_avg_for_post(p):
        stats = avg_by_business.get(p.business_id)
        return stats["avg"] if stats else None

    if sort_by == "rating_asc":
        def post_key(p):
            avg = vendor_avg_for_post(p)
            avg_sort = avg if avg is not None else 999999
            created = p.created_at or dt.datetime.min
            return (avg_sort, created)
        posts.sort(key=post_key, reverse=False)

    elif sort_by == "newest":
        posts.sort(
            key=lambda p: (p.date.toordinal() if p.date else 0, p.created_at or dt.datetime.min),
            reverse=True
        )
    else:
        def post_key(p):
            avg = vendor_avg_for_post(p)
            avg_sort = avg if avg is not None else -1
            created = p.created_at or dt.datetime.min
            return (avg_sort, created)
        posts.sort(key=post_key, reverse=True)

    raw_cats = db.session.query(Post.category).distinct().all()
    categories = sorted({c[0] for c in raw_cats if c[0]})

    businesses = Business.query.all()

    def business_avg(biz):
        s = avg_by_business.get(biz.id)
        return s["avg"] if s else None

    if sort_by == "rating_asc":
        businesses.sort(key=lambda b: business_avg(b) if business_avg(b) is not None else 999999)
    elif sort_by == "newest":
        businesses.sort(key=lambda b: b.username.lower())
    else:
        businesses.sort(key=lambda b: business_avg(b) if business_avg(b) is not None else -1, reverse=True)

    my_ratings = VendorRating.query.filter_by(user_id=user.id).all()
    my_rating_by_business = {r.business_id: r.score for r in my_ratings}

    return render_template(
        "dashboard.html",
        user=user,
        posts=posts,
        categories=categories,
        selected_category=selected_category,
        sort_by=sort_by,
        businesses=businesses,
        avg_by_business=avg_by_business,
        my_rating_by_business=my_rating_by_business,
    )

#Python Flask Tutuorial 8
@app.post("/rate/<int:business_id>")
@require(kind="personal")
def rate_vendor(business_id):
    _, user = current_user()

    b = db.session.get(Business, business_id)
    if not b:
        flash("Business not found.", "err")
        return redirect(url_for("dashboard"))

    score_str = (request.form.get("score") or "").strip()
    try:
        score = int(score_str)
    except ValueError:
        flash("Rating must be a number from 1 to 5.", "err")
        return redirect(request.referrer or url_for("dashboard"))

    if score < 1 or score > 5:
        flash("Rating must be between 1 and 5.", "err")
        return redirect(request.referrer or url_for("dashboard"))

    existing = VendorRating.query.filter_by(user_id=user.id, business_id=business_id).first()
    if existing:
        existing.score = score
        flash(f"Updated your rating for {b.username} to {score}/5.", "ok")
    else:
        db.session.add(VendorRating(user_id=user.id, business_id=business_id, score=score))
        flash(f"Rated {b.username} {score}/5.", "ok")

    db.session.commit()
    return redirect(request.referrer or url_for("dashboard"))


@app.get("/daily-specials")
@require(kind="personal")
def daily_specials():
    _, user = current_user()

    specials_by_day = [[] for _ in range(7)]
    for s in DailySpecial.query.order_by(DailySpecial.weekday, DailySpecial.vendor_name).all():
        if 0 <= s.weekday <= 6:
            specials_by_day[s.weekday].append(s)

    return render_template(
        "daily_specials.html",
        user=user,
        weekday_names=WEEKDAY_NAMES,
        week_indices=list(range(7)),
        specials_by_day=specials_by_day,
    )


@app.get("/b.dashboard")
@require(kind="business")
def b_dashboard():
    _, business = current_user()

    my_posts = (
        Post.query.filter_by(business_id=business.id)
        .order_by(Post.date.desc(), Post.created_at.desc())
        .all()
    )

    my_specials = (
        DailySpecial.query
        .filter_by(business_id=business.id)
        .order_by(DailySpecial.weekday.asc())
        .all()
    )

    return render_template(
        "b_dashboard.html",
        business=business,
        my_posts=my_posts,
        my_specials=my_specials,
        weekday_names=WEEKDAY_NAMES,
    )

#IS3312 Project Phase 1
@app.post("/b/post")
@require(kind="business")
def create_post():
    _, business = current_user()

    v = request.form.get("vendor_name", "").strip()
    ds = request.form.get("date", "").strip()
    os_ = request.form.get("opening_time", "").strip()
    cs = request.form.get("closing_time", "").strip()
    dsc = request.form.get("description", "").strip()
    category = (request.form.get("category", "") or "Other").strip()

    if not all([v, ds, os_, cs, dsc]):
        flash("All fields required.", "err")
        return redirect(url_for("b_dashboard"))

    try:
        d = dt.date.fromisoformat(ds)
        ot = dt.time.fromisoformat(os_)
        ct = dt.time.fromisoformat(cs)
    except ValueError:
        flash("Invalid date/time format.", "err")
        return redirect(url_for("b_dashboard"))

    db.session.add(
        Post(
            vendor_name=v,
            date=d,
            opening_time=ot,
            closing_time=ct,
            description=dsc,
            category=category,
            business_id=business.id,
        )
    )
    db.session.commit()
    flash("Post created.", "ok")
    return redirect(url_for("b_dashboard"))


@app.post("/b/special")
@require(kind="business")
def create_or_update_special():
    _, business = current_user()

    name = request.form.get("special_name", "").strip()
    desc = request.form.get("special_description", "").strip()
    weekday_str = request.form.get("weekday", "").strip()

    if not all([name, desc, weekday_str]):
        flash("All special fields are required.", "err")
        return redirect(url_for("b_dashboard"))

    try:
        weekday = int(weekday_str)
        assert 0 <= weekday <= 6
    except (ValueError, AssertionError):
        flash("Weekday must be between 0 (Monday) and 6 (Sunday).", "err")
        return redirect(url_for("b_dashboard"))

    existing = DailySpecial.query.filter_by(business_id=business.id, weekday=weekday).first()
    if existing:
        existing.special_name = name
        existing.description = desc
        existing.vendor_name = business.username
    else:
        db.session.add(
            DailySpecial(
                special_name=name,
                description=desc,
                weekday=weekday,
                vendor_name=business.username,
                business_id=business.id,
            )
        )

    db.session.commit()
    flash("Daily special saved.", "ok")
    return redirect(url_for("b_dashboard"))


@app.get("/admin")
@require(admin=True)
def admin_page():
    return render_template(
        "admin.html",
        users=User.query.order_by(User.id.desc()).all(),
        businesses=Business.query.order_by(Business.id.desc()).all(),
        posts=Post.query.order_by(Post.created_at.desc()).all(),
    )

@app.post("/admin/post/<int:post_id>/delete")
@require(admin=True)
def admin_delete_post(post_id):
    p = db.session.get(Post, post_id) or abort(404)
    db.session.delete(p)
    db.session.commit()
    flash("Post deleted.", "ok")
    return redirect(url_for("admin_page"))


@app.post("/delete/<kind>/<int:item_id>")
@require(admin=True)
def delete(kind, item_id):
    Model = MODELS.get(kind)
    obj = db.session.get(Model, item_id) if Model else None
    if not obj:
        abort(404)
    db.session.delete(obj)
    db.session.commit()
    flash("Deleted.", "ok")
    return redirect(url_for("admin_page"))


@app.post("/verify/<kind>/<int:item_id>")
@require(admin=True)
def verify(kind, item_id):
    Model = MODELS.get(kind)
    obj = db.session.get(Model, item_id) if Model else None
    if not obj:
        abort(404)
    obj.verified = True
    db.session.commit()
    flash("Verified.", "ok")
    return redirect(url_for("admin_page"))


@app.get("/debug/dbinfo")
def dbinfo():
    return jsonify({
        "project_dir": BASE_DIR,
        "users_count": User.query.count(),
        "businesses_count": Business.query.count(),
        "posts_count": Post.query.count(),
        "specials_count": DailySpecial.query.count(),
        "ratings_count": VendorRating.query.count(),
        "note": "Using MySQL (users_db, businesses_db) via SQLAlchemy binds.",
    })


if __name__ == "__main__":
    app.run(debug=True)
