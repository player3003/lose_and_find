from datetime import UTC, datetime

from flask import Flask

import app as main_app_module
from agent.rule_agent import RuleBasedAgent
from config import Config
from database import db
from models import FoundItem, LostItem, MatchLevel, MatchResult, User
from services import MatchService


class TestConfig(Config):
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    TESTING = True


def create_test_app():
    app = Flask(__name__)
    app.config.from_object(TestConfig)
    db.init_app(app)
    with app.app_context():
        db.create_all()
    return app


def create_client_with_fresh_db():
    flask_app = main_app_module.app
    flask_app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SECRET_KEY="test-secret",
    )
    with flask_app.app_context():
        db.session.remove()
        db.engine.dispose()
        db.drop_all()
        db.create_all()
    return flask_app.test_client()


def test_high_match_rule():
    app = create_test_app()
    with app.app_context():
        service = MatchService(db.session)
        agent = RuleBasedAgent(service)

        lost_user = User(username="lost_user")
        lost_user.set_password("password123")
        found_user = User(username="found_user")
        found_user.set_password("password123")
        db.session.add_all([lost_user, found_user])
        db.session.commit()

        found = FoundItem(
            category="电子产品",
            description="黑色联想笔记本电脑，外壳有蓝色贴纸",
            location="图书馆三楼",
            occurred_at=datetime(2023, 5, 1, 10, 0, tzinfo=UTC),
            owner=found_user,
        )
        db.session.add(found)
        db.session.commit()

        lost = LostItem(
            category="电子产品",
            description="联想黑色电脑，贴蓝色贴纸",
            location="图书馆三楼",
            occurred_at=datetime(2023, 5, 2, 9, 0, tzinfo=UTC),
            owner=lost_user,
        )
        db.session.add(lost)
        db.session.commit()

        matches = agent.handle_new_lost(lost)
        assert matches
        assert matches[0].level == MatchLevel.HIGH
        assert matches[0].score >= 90
        assert matches[0].is_completed is False


def test_medium_match_rule():
    app = create_test_app()
    with app.app_context():
        service = MatchService(db.session)
        agent = RuleBasedAgent(service)

        lost_user = User(username="lost_owner")
        lost_user.set_password("password123")
        found_user = User(username="found_owner")
        found_user.set_password("password123")
        db.session.add_all([lost_user, found_user])
        db.session.commit()

        found = FoundItem(
            category="证件",
            description="校园卡 张三",
            location="食堂",
            occurred_at=datetime(2023, 6, 1, 12, 0, tzinfo=UTC),
            owner=found_user,
        )
        db.session.add(found)
        db.session.commit()

        lost = LostItem(
            category="证件",
            description="学生校园卡 名字张三",
            location="操场",
            occurred_at=datetime(2023, 6, 3, 8, 0, tzinfo=UTC),
            owner=lost_user,
        )
        db.session.add(lost)
        db.session.commit()

        matches = agent.handle_new_lost(lost)
        assert matches
        assert matches[0].level == MatchLevel.MEDIUM

def test_low_match_rule():
    app = create_test_app()
    with app.app_context():
        service = MatchService(db.session)
        agent = RuleBasedAgent(service)

        lost_user = User(username="cup_owner")
        lost_user.set_password("password123")
        found_user = User(username="cup_finder")
        found_user.set_password("password123")
        db.session.add_all([lost_user, found_user])
        db.session.commit()

        found = FoundItem(
            category="其他",
            description="银色保温杯上有星星图案",
            location="操场",
            occurred_at=datetime(2023, 7, 1, 12, 0, tzinfo=UTC),
            owner=found_user,
        )
        db.session.add(found)
        db.session.commit()

        lost = LostItem(
            category="生活用品",
            description="保温杯 星星装饰",
            location="教学楼",
            occurred_at=datetime(2023, 7, 10, 9, 0, tzinfo=UTC),
            owner=lost_user,
        )
        db.session.add(lost)
        db.session.commit()

        matches = agent.handle_new_lost(lost)
        assert matches
        assert matches[0].level == MatchLevel.LOW


def test_mark_match_completed_prevents_future_updates():
    app = create_test_app()
    with app.app_context():
        service = MatchService(db.session)
        agent = RuleBasedAgent(service)

        lost_user = User(username="phone_owner")
        lost_user.set_password("password123")
        found_user = User(username="phone_finder")
        found_user.set_password("password123")
        db.session.add_all([lost_user, found_user])
        db.session.commit()

        found = FoundItem(
            category="电子产品",
            description="黑色手机",
            location="图书馆",
            occurred_at=datetime(2023, 8, 1, 12, 0, tzinfo=UTC),
            owner=found_user,
        )
        lost = LostItem(
            category="电子产品",
            description="黑色手机",
            location="图书馆",
            occurred_at=datetime(2023, 8, 2, 9, 0, tzinfo=UTC),
            owner=lost_user,
        )
        db.session.add_all([found, lost])
        db.session.commit()

        matches = agent.handle_new_lost(lost)
        match = matches[0]
        assert match.is_completed is False

        service.mark_match_completed(match.id)
        match = db.session.get(MatchResult, match.id)
        assert match.is_completed is True
        completed_at = match.completed_at

        # Trigger agent update again; completed match should stay unchanged
        match = agent.handle_new_lost(lost)[0]
        assert match.is_completed is True
        assert match.completed_at == completed_at


def test_delete_lost_item_cascades_matches():
    app = create_test_app()
    with app.app_context():
        service = MatchService(db.session)
        agent = RuleBasedAgent(service)

        lost_user = User(username="card_owner")
        lost_user.set_password("password123")
        found_user = User(username="card_finder")
        found_user.set_password("password123")
        db.session.add_all([lost_user, found_user])
        db.session.commit()

        found = FoundItem(
            category="证件",
            description="学生证 李四",
            location="食堂",
            occurred_at=datetime(2023, 9, 1, 8, 0, tzinfo=UTC),
            owner=found_user,
        )
        lost = LostItem(
            category="证件",
            description="学生证 李四",
            location="食堂",
            occurred_at=datetime(2023, 9, 1, 9, 0, tzinfo=UTC),
            owner=lost_user,
        )
        db.session.add_all([found, lost])
        db.session.commit()

        agent.handle_new_lost(lost)
        assert MatchResult.query.count() == 1

        service.delete_lost_item(lost.id)
        assert LostItem.query.count() == 0
        assert MatchResult.query.count() == 0


def test_login_required_for_lost_submission():
    client = create_client_with_fresh_db()

    resp = client.post(
        "/lost",
        data={
            "category": "证件",
            "description": "校园卡",
            "location": "图书馆",
            "occurred_at": "2024-01-01T10:00",
        },
    )
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]

    client.post(
        "/auth/register",
        data={
            "username": "alice",
            "password": "password123",
            "confirm": "password123",
        },
        follow_redirects=True,
    )

    resp = client.post(
        "/lost",
        data={
            "category": "证件",
            "description": "校园卡",
            "location": "图书馆",
            "occurred_at": "2024-01-01T10:00",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302


def test_match_completion_requires_owner_permission():
    client = create_client_with_fresh_db()

    client.post(
        "/auth/register",
        data={
            "username": "owner1",
            "password": "password123",
            "confirm": "password123",
        },
        follow_redirects=True,
    )

    client.post(
        "/lost",
        data={
            "category": "电子产品",
            "description": "平板电脑",
            "location": "教室",
            "occurred_at": "2024-02-01T09:00",
        },
        follow_redirects=True,
    )

    client.post("/auth/logout", follow_redirects=True)

    client.post(
        "/auth/register",
        data={
            "username": "owner2",
            "password": "password123",
            "confirm": "password123",
        },
        follow_redirects=True,
    )

    client.post(
        "/found",
        data={
            "category": "电子产品",
            "description": "黑色平板电脑",
            "location": "教室",
            "occurred_at": "2024-02-01T10:00",
        },
        follow_redirects=True,
    )

    with main_app_module.app.app_context():
        match = db.session.scalar(db.select(MatchResult))
        assert match is not None
        match_id = match.id

    client.post("/auth/logout", follow_redirects=True)

    client.post(
        "/auth/register",
        data={
            "username": "outsider",
            "password": "password123",
            "confirm": "password123",
        },
        follow_redirects=True,
    )

    resp = client.post(f"/matches/{match_id}/complete")
    assert resp.status_code == 403

    client.post("/auth/logout", follow_redirects=True)

    client.post(
        "/auth/login",
        data={"username": "owner1", "password": "password123"},
        follow_redirects=True,
    )

    resp = client.post(f"/matches/{match_id}/complete", follow_redirects=False)
    assert resp.status_code == 302

    with main_app_module.app.app_context():
        match = db.session.get(MatchResult, match_id)
        assert match.is_completed is True
