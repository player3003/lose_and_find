from datetime import UTC, datetime

from database import db


def _now_utc():
    return datetime.now(UTC)


class LostItem(db.Model):
    __tablename__ = "lost_items"

    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(128), nullable=False)
    occurred_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now_utc)
    reporter_name = db.Column(db.String(64), nullable=True)
    contact_info = db.Column(db.String(128), nullable=True)
    image_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now_utc)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    matches = db.relationship(
        "MatchResult",
        back_populates="lost_item",
        cascade="all, delete-orphan"
    )

    owner = db.relationship("User", back_populates="lost_items")

    def __repr__(self) -> str:
        return f"<LostItem {self.category} {self.description[:15]}>"


class FoundItem(db.Model):
    __tablename__ = "found_items"

    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(128), nullable=False)
    occurred_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now_utc)
    reporter_name = db.Column(db.String(64), nullable=True)
    contact_info = db.Column(db.String(128), nullable=True)
    image_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now_utc)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    matches = db.relationship(
        "MatchResult",
        back_populates="found_item",
        cascade="all, delete-orphan"
    )

    owner = db.relationship("User", back_populates="found_items")

    def __repr__(self) -> str:
        return f"<FoundItem {self.category} {self.description[:15]}>"
