from flask import Blueprint, render_template, request, redirect, url_for

from models.settings import db
from models.user import User
from models.topic import Topic
from models.comment import Comment

from utils.redis_helper import create_csrf_token, validate_csrf

topic_handlers = Blueprint('topic', __name__)


@topic_handlers.route("/")
def index():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()

    topics = db.query(Topic).all()

    return render_template('topic/index.html', user=user, topics=topics)


@topic_handlers.route('/create-topic', methods=['GET', 'POST'])
def topic_create():
    session_token = request.cookies.get('session_token')
    user = db.query(User).filter_by(session_token=session_token).first()

    if not user:
        return redirect(url_for('login'))

    if request.method == 'GET':
        csrf_token = create_csrf_token(user.username)

        return render_template('topic/topic_create.html', user=user, csrf_token=csrf_token)

    elif request.method == 'POST':
        csrf = request.form.get("csrf")

        if validate_csrf(csrf, user.username):
            title = request.form.get('title')
            text = request.form.get('text')

            topic = Topic.create(title=title, text=text, author=user)

            return redirect(url_for('index'))
        else:
            return 'CSRF token is not valid!'


@topic_handlers.route('/topic/<topic_id>', methods=['GET'])
def topic_details(topic_id):
    topic = db.query(Topic).get(int(topic_id))

    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()

    comments = db.query(Comment).filter_by(topic=topic).all()

    return render_template('topic/topic_details.html', topic=topic, user=user, csrf_token=create_csrf_token(user.username), comments=comments)


@topic_handlers.route("/topic/<topic_id>/edit", methods=['GET', 'POST'])
def topic_edit(topic_id):
    topic = db.query(Topic).get(int(topic_id))

    if request.method == 'GET':
        return render_template("topic/topic_edit.html", topic=topic)

    elif request.method == 'POST':
        title = request.form.get('title')
        text = request.form.get('text')

        session_token = request.cookies.get('session_token')
        user = db.query(User).filter_by(session_token=session_token).first()

        if not user:
            return redirect(url_for('login'))
        elif topic.author.id != user.id:
            return 'You are not the author!'
        else:
            topic.title = title
            topic.text = text
            db.add(topic)
            db.commit()

            return redirect(url_for('topic.topic_details', topic_id=topic_id))


@topic_handlers.route("/topic/<topic_id>/delete", methods=['GET', 'POST'])
def topic_delete(topic_id):
    topic = db.query(Topic).get(int(topic_id))

    if request.method == 'GET':
        return render_template('topic/topic_delete.html', topic=topic)

    elif request.method == 'POST':
        session_token = request.cookies.get('session_token')
        user = db.query(User).filter_by(session_token=session_token).first()

        if not user:
            return redirect(url_for('auth.login'))
        elif topic.author_id != user.id:
            return 'You are not the author!'
        else:
            db.delete(topic)
            db.commit()
            return redirect(url_for('topic.index'))