from models.settings import db
from datetime import datetime


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String)

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship("User")

    topic_id = db.Column(db.Integer, db.ForeignKey('topics.id'))
    topic = db.relationship("Topic")

    created = db.Column(db.DateTime, default=datetime.utcnow)


@classmethod
def create(cls, text, author, topic):
    comment = cls(text=text, author=author, topic=topic)
    db.add(comment)
    db.commit()

    return comment