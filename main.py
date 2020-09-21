from flask import Flask

from models.settings import db


from handlers.auth import auth_handlers
from handlers.topic import topic_handlers
from handlers.comment import comment_handlers

app = Flask(__name__)
app.register_blueprint(auth_handlers)
app.register_blueprint(topic_handlers)
app.register_blueprint(comment_handlers)
db.create_all()

if __name__ == '__main__':
    app.run(debug=True)

