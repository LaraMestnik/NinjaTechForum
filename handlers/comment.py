from flask import render_template, request, redirect, url_for, Blueprint

from models.settings import db
from models.topic import Topic
from models.user import User
from models.comment import Comment

from utils.redis_helper import create_csrf_token, validate_csrf

comment_handlers = Blueprint("comment", __name__)


@comment_handlers.route("/topic/<topic_id>/create-comment", methods=['POST'])
def comment_create(topic_id):
    session_token = request.cookies.get('session_token')
    user = db.query(User).filter_by(session_token=session_token).first()

    if not user:
        return redirect(url_for('auth.login'))

    csrf = request.form.get("csrf")

    if validate_csrf(csrf, user.username):
        text = request.form.get("text")

        topic = db.query(Topic).get(int(topic_id))

        comment = Comment.create(topic=topic, text=text, author=user)

        return redirect(url_for('topic.topic_details', topic_id=topic_id, csrf_token=create_csrf_token(user.username)))
    else:
        return "Csrf token is not valid!"


@comment_handlers.route("/comment/<comment_id>/edit", methods=['GET','POST'])
def comment_edit(comment_id):
    comment = db.query(Comment).get(int(comment_id))

    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()

    if not user:
        return redirect(url_for("auth.login"))
    elif comment.author.id != user.id:
        return "You can only edit your own comments!"

    if request.method == 'GET':
        csrf_token = create_csrf_token(username=user.username)
        return render_template("comment/comment_edit.html", comment=comment, csrf_token=csrf_token)
    elif request.method == 'POST':
        text = request.form.get("text")

        csrf = request.form.get("csrf")

        if validate_csrf(csrf, user.username):
            comment.text = text
            db.add(comment)
            db.commit()
            return redirect(url_for('topic.topic_details', topic_id=comment.topic.id))
        else:
            return "CSRF tokens don's match"


@comment_handlers.route("/comment/<comment_id>/delete", methods=['POST'])
def comment_delete(comment_id):
    comment = db.query(Comment).get(int(comment_id))

    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()

    if not user:
        return redirect(url_for('auth.login'))
    elif comment.author.id != user.id:
        return 'You can only delete your own comments!'

    csrf = request.form.get("csrf")

    if validate_csrf(csrf, user.username):
        topic_id = comment.topic.id

        db.delete(comment)
        db.commit()
        return redirect(url_for('topic.topic_details', topic_id=topic_id))
    else:
        return "CSRF tokens don't match!"