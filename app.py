from datetime import UTC, datetime
from pathlib import Path
from typing import Optional

import click
from flask import Flask, abort, redirect, render_template, request, url_for
from flask import flash
from flask.cli import with_appcontext
from flask_login import (LoginManager, current_user, login_required,
                         login_user, logout_user)
from sqlalchemy import func

from agent.rule_agent import RuleBasedAgent
from config import Config
from database import db
from models import FoundItem, LostItem, MatchResult, User
from services import MatchService


ITEM_CATEGORIES = [
    "证件",
    "电子产品",
    "书本资料",
    "衣物配件",
    "钥匙",
    "生活用品",
    "其他",
]


app = Flask(__name__)
app.config.from_object(Config)


def _ensure_sqlite_dir(database_uri: str) -> None:
    if not database_uri.startswith("sqlite:///"):
        return
    raw_path = database_uri.replace("sqlite:///", "", 1)
    db_path = Path(raw_path)
    if not db_path.is_absolute():
        db_path = Path(app.root_path) / db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)


_ensure_sqlite_dir(app.config["SQLALCHEMY_DATABASE_URI"])

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "请先登录以继续。"
login_manager.login_message_category = "warning"
login_manager.init_app(app)

with app.app_context():
    db.create_all()

match_service = MatchService(db.session)
agent = RuleBasedAgent(match_service)


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    if not user_id:
        return None
    return db.session.get(User, int(user_id))


def _parse_datetime(value: Optional[str]) -> datetime:
    if not value:
        return datetime.now(UTC)
    # HTML datetime-local input uses format YYYY-MM-DDTHH:MM
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M").replace(tzinfo=UTC)
    except ValueError:
        return datetime.now(UTC)


@app.get("/")
def index():
    # Get all items for display (everyone sees the full list)
    all_lost_items = match_service.all_lost_items()
    all_found_items = match_service.all_found_items()
    
    # Get user's own items if authenticated
    my_lost_items = []
    my_found_items = []
    if current_user.is_authenticated:
        my_lost_items = match_service.all_lost_items(current_user.id, include_all=False)
        my_found_items = match_service.all_found_items(current_user.id, include_all=False)
    
    # Determine which matches to show (user's matches or recent)
    if current_user.is_authenticated:
        matches = match_service.matches_for_user(current_user.id)
    else:
        matches = match_service.recent_matches()

    return render_template(
        "index.html",
        categories=ITEM_CATEGORIES,
        all_lost_items=all_lost_items,
        all_found_items=all_found_items,
        my_lost_items=my_lost_items,
        my_found_items=my_found_items,
        matches=matches,
    )


@app.get("/lost/<int:lost_id>")
def view_lost_item(lost_id: int):
    item = db.session.get(LostItem, lost_id)
    if item is None:
        flash("失物信息不存在。", "warning")
        return redirect(url_for("index"))
    
    is_owner = current_user.is_authenticated and item.user_id == current_user.id
    item_matches = match_service.matches_for_lost(lost_id) if is_owner else []
    
    return render_template(
        "item_detail.html",
        item=item,
        item_type="lost",
        is_owner=is_owner,
        item_matches=item_matches,
    )


@app.get("/found/<int:found_id>")
def view_found_item(found_id: int):
    item = db.session.get(FoundItem, found_id)
    if item is None:
        flash("招领信息不存在。", "warning")
        return redirect(url_for("index"))
    
    is_owner = current_user.is_authenticated and item.user_id == current_user.id
    item_matches = match_service.matches_for_found(found_id) if is_owner else []
    
    return render_template(
        "item_detail.html",
        item=item,
        item_type="found",
        is_owner=is_owner,
        item_matches=item_matches,
    )


@app.post("/lost/<int:lost_id>/match")
@login_required
def trigger_lost_match(lost_id: int):
    if not match_service.owns_lost_item(lost_id, current_user.id):
        abort(403)
    item = db.session.get(LostItem, lost_id)
    if item is None:
        flash("失物信息不存在。", "warning")
        return redirect(url_for("index"))
    agent.handle_new_lost(item)
    flash("智能体已触发匹配，结果已更新。", "success")
    return redirect(url_for("view_lost_item", lost_id=lost_id))


@app.post("/found/<int:found_id>/match")
@login_required
def trigger_found_match(found_id: int):
    if not match_service.owns_found_item(found_id, current_user.id):
        abort(403)
    item = db.session.get(FoundItem, found_id)
    if item is None:
        flash("招领信息不存在。", "warning")
        return redirect(url_for("index"))
    agent.handle_new_found(item)
    flash("智能体已触发匹配，结果已更新。", "success")
    return redirect(url_for("view_found_item", found_id=found_id))


@app.route("/lost/new", methods=["GET", "POST"])
@login_required
def create_lost_item():
    if request.method == "GET":
        return render_template("lost_form.html", categories=ITEM_CATEGORIES)

    category = request.form.get("category", "").strip()
    description = request.form.get("description", "").strip()
    location = request.form.get("location", "").strip()
    occurred_at = _parse_datetime(request.form.get("occurred_at"))
    reporter_name = request.form.get("reporter_name", "").strip() or None
    contact_info = request.form.get("contact_info", "").strip() or None

    if not category or not description or not location:
        flash("请填写完整的失物信息。", "danger")
        return redirect(url_for("index"))

    if contact_info is None and current_user.is_authenticated:
        contact_info = current_user.username

    lost_item = LostItem(
        category=category,
        description=description,
        location=location,
        occurred_at=occurred_at,
        reporter_name=reporter_name,
        contact_info=contact_info,
        owner=current_user,
    )
    db.session.add(lost_item)
    db.session.commit()

    agent.handle_new_lost(lost_item)
    flash("失物信息已提交，智能体推荐已更新。", "success")
    return redirect(url_for("index", lost_id=lost_item.id))


@app.route("/found/new", methods=["GET", "POST"])
@login_required
def create_found_item():
    if request.method == "GET":
        return render_template("found_form.html", categories=ITEM_CATEGORIES)

    category = request.form.get("category", "").strip()
    description = request.form.get("description", "").strip()
    location = request.form.get("location", "").strip()
    occurred_at = _parse_datetime(request.form.get("occurred_at"))
    reporter_name = request.form.get("reporter_name", "").strip() or None
    contact_info = request.form.get("contact_info", "").strip() or None

    if not category or not description or not location:
        flash("请填写完整的招领信息。", "danger")
        return redirect(url_for("index"))

    if contact_info is None and current_user.is_authenticated:
        contact_info = current_user.username

    found_item = FoundItem(
        category=category,
        description=description,
        location=location,
        occurred_at=occurred_at,
        reporter_name=reporter_name,
        contact_info=contact_info,
        owner=current_user,
    )
    db.session.add(found_item)
    db.session.commit()

    agent.handle_new_found(found_item)
    flash("招领信息已提交，智能体推荐已更新。", "success")
    return redirect(url_for("index", found_id=found_item.id))


@app.post("/lost/<int:lost_id>/delete")
@login_required
def delete_lost_item(lost_id: int):
    if not current_user.is_admin:
        abort(403)
    item = db.session.get(LostItem, lost_id)
    if item is None:
        flash("失物信息不存在。", "warning")
        return redirect(url_for("index"))
    match_service.delete_lost_item(lost_id)
    flash("失物信息已删除。", "info")
    return redirect(url_for("index"))


@app.post("/found/<int:found_id>/delete")
@login_required
def delete_found_item(found_id: int):
    if not current_user.is_admin:
        abort(403)
    item = db.session.get(FoundItem, found_id)
    if item is None:
        flash("招领信息不存在。", "warning")
        return redirect(url_for("index"))
    match_service.delete_found_item(found_id)
    flash("招领信息已删除。", "info")
    return redirect(url_for("index"))


@app.post("/matches/<int:match_id>/complete")
@login_required
def complete_match(match_id: int):
    match = db.session.get(MatchResult, match_id)
    if match is None:
        flash("未找到匹配记录。", "warning")
        return redirect(url_for("index"))
    allowed_user_ids = {match.lost_item.user_id, match.found_item.user_id}
    if current_user.id not in allowed_user_ids:
        abort(403)
    match_service.mark_match_completed(match_id)
    flash("匹配已确认完成。", "success")
    return redirect(url_for("index", match_id=match.id))


@app.route("/auth/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not password:
            flash("用户名和密码均为必填项。", "danger")
            return render_template("auth_register.html", username=username)
        if password != confirm:
            flash("两次输入的密码不一致。", "danger")
            return render_template("auth_register.html", username=username)
        if db.session.scalar(db.select(User).filter_by(username=username)):
            flash("该用户名已被注册。", "danger")
            return render_template("auth_register.html")

        user = User(username=username)
        user.set_password(password)
        # First registered account becomes administrator for later management tasks.
        existing_users = db.session.scalar(db.select(func.count()).select_from(User))
        if existing_users == 0:
            user.is_admin = True
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash("注册成功，已自动登录。", "success")
        return redirect(url_for("index"))

    return render_template("auth_register.html")


@app.route("/auth/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user: Optional[User] = db.session.scalar(db.select(User).filter_by(username=username))
        if user is None or not user.check_password(password):
            flash("用户名或密码错误。", "danger")
            return render_template("auth_login.html", username=username)

        login_user(user)
        flash("登录成功。", "success")
        next_url = request.args.get("next")
        return redirect(next_url or url_for("index"))

    return render_template("auth_login.html")


@app.post("/auth/logout")
@login_required
def logout():
    logout_user()
    flash("您已退出登录。", "info")
    return redirect(url_for("login"))


@app.cli.command("promote-admin")
@click.argument("username")
@with_appcontext
def promote_admin(username: str) -> None:
    user: Optional[User] = db.session.scalar(db.select(User).filter_by(username=username))
    if user is None:
        click.echo(f"未找到用户：{username}", err=True)
        raise SystemExit(1)
    if user.is_admin:
        click.echo(f"用户 {username} 已是管理员。")
        return
    user.is_admin = True
    db.session.commit()
    click.echo(f"用户 {username} 已被设为管理员。")


if __name__ == "__main__":
    app.run(debug=True)
