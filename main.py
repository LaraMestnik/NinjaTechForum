from flask import Flask, render_template, request, redirect, url_for, make_response
import hashlib
import uuid

from models.settings import db
from models.user import User
from models.topic import Topic

app = Flask(__name__)
db.create_all()


@app.route("/")
def index():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()

    topics = db.query(Topic).all()

    return render_template('index.html', user=user, topics=topics)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        repeat = request.form.get("repeat")

        if password != repeat:
            return "Passwords don't match! Try again."

        user = User(username=username, password_hash=hashlib.sha256(password.encode()).hexdigest(), session_token=str(uuid.uuid4()))
        db.add(user)
        db.commit()

        response = make_response(redirect(url_for('index')))
        response.set_cookie("session_token", user.session_token, httponly=True, samesite='Strict')

        return response


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        user = db.query(User).filter_by(username=username).first()

        if not user:
            return 'This user does not exist'
        else:
            if password_hash == user.password_hash:
                user.session_token = str(uuid.uuid4())
                db.add(user)
                db.commit()

                response = make_response(redirect(url_for('index')))
                response.set_cookie('session_token', user.session_token, httponly=True, samesite='Strict')

                return response
            else:
                return 'Your password is incorrect!'


@app.route('/create-topic', methods=['GET', 'POST'])
def topic_create():
    if request.method == 'GET':
        return render_template('topic_create.html')

    elif request.method == 'POST':
        title = request.form.get('title')
        text = request.form.get('text')

        session_token = request.cookies.get('session_token')
        user = db.query(User).filter_by(session_token=session_token).first()

        if not user:
            return redirect(url_for('login '))

        topic = Topic.create(title=title, text=text, author=user)

        return redirect(url_for('index'))


@app.route('/topic/<topic_id>', methods=['GET'])
def topic_details(topic_id):
    topic = db.query(Topic).get(int(topic_id))

    return render_template('topic_details.html', topic=topic)


if __name__ == '__main__':
    app.run(debug=True)

