import hashlib
import uuid
from flask import render_template, request, redirect, url_for, make_response, Blueprint

from models.user import User
from models.settings import db

auth_handlers = Blueprint("auth", __name__)


@auth_handlers.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("auth/signup.html")

    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        repeat = request.form.get("repeat")

        if password != repeat:
            return "Passwords don't match! Try again."

        user = User(username=username, password_hash=hashlib.sha256(password.encode()).hexdigest(), session_token=str(uuid.uuid4()))
        db.add(user)
        db.commit()

        response = make_response(redirect(url_for('topic.index')))
        response.set_cookie("session_token", user.session_token, httponly=True, samesite='Strict')

        return response


@auth_handlers.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('auth/login.html')

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

                response = make_response(redirect(url_for('topic.index')))
                response.set_cookie('session_token', user.session_token, httponly=True, samesite='Strict')

                return response
            else:
                return 'Your password is incorrect!'


@auth_handlers.route("/logout")
def logout():
    session_token = request.cookies.get('session_token')
    user = db.query(User).filter_by(session_token=session_token).first()

    user.session_token = ""
    db.add(user)
    db.commit()

    return redirect(url_for('topic.index'))



