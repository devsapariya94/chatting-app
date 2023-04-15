from flask import Flask, render_template, request, session, redirect, url_for, flash
import werkzeug
import werkzeug.serving
import werkzeug._reloader

werkzeug.serving.run_with_reloader = werkzeug._reloader.run_with_reloader
from flask_socketio import SocketIO
from flask_session import Session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import os
from os import environ as env
from sqlalchemy.sql import func
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv, find_dotenv
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vnkdjnfjknfl1232#'
socketio = SocketIO(app)
login_manager = LoginManager(app)


DB_NAME = "database.db"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///{}".format(DB_NAME)
db = SQLAlchemy(app)
# db.init_app(app)



ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(80))
    email = db.Column(db.String(80), nullable=False)
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())


class Message (db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(1000), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)


class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())
    messages = db.relationship('Message', backref='room', lazy=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


if not os.path.exists(DB_NAME):
    with app.app_context():
        db.create_all()
    print('Created Database!')

@login_manager.user_loader
def load_user(user_id):
    # Return the User object for the given user_id
    return User.query.get(int(user_id))


@app.route('/room')
def room():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    rooms = db.session.query(Room.name, Room.id)\
        .all()  
    print(rooms)
    return render_template('room.html', rooms=rooms)

@app.route('/create_room', methods=['GET', 'POST'])
def create_room():
    if request.method == 'POST':
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        name = request.form['room_name']
        creator_id = current_user.id
        new_room = Room(name=name, creator_id=creator_id)
        db.session.add(new_room)
        db.session.commit()
        return redirect(url_for('room'))
    return redirect(location=url_for('room'))

# @app.route('/chat')
# def chat():
#     if not current_user.is_authenticated:
       
#         return redirect(url_for('login'))
#     # send the messages and the username to the template
#     messages = db.session.query(Message.message, User.username, Message.id)\
#         .join(User, User.id == Message.user_id)\
#         .order_by(Message.date_created)\
#         .all()
#     print(messages)

#     return render_template('chat.html', messages=messages, username=current_user.username)


@app.route('/chat/<int:room_id>')
def chat(room_id):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    # send the messages and the username to the template
    messages = db.session.query(Message.message, User.username, Message.id)\
        .join(User, User.id == Message.user_id)\
        .filter(Message.room_id == room_id)\
        .order_by(Message.date_created)\
        .all()
    print(messages)

    return render_template('chat.html', messages=messages, username=current_user.username, room_id=room_id)

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         print(username, password)
#         new_user = User(username=username, password=password)
#         db.session.add(new_user)
#         db.session.commit()
#         return redirect(url_for('login'))
#     return render_template('signup.html')


# @app.route('/')
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         print(username, password)
#         user = User.query.filter_by(username=username).first()
#         if user and user.password == password:
#             print('Logged in successfully!')
#             login_user(user, remember=True)
#             return redirect(url_for('room'))
#         else:
#             flash('Invalid Credentials')
#             return redirect(url_for('login'))

#     if current_user.is_authenticated:
#         return redirect(url_for('room'))
#     return render_template('login.html')

# @app.route('/logout')
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('login'))

def messageReceived(methods=['GET', 'POST']):
    print('message was received!!!')


@app.route('/delete', methods=['GET', 'POST'])
def delete():
    if request.method == 'POST':
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        print(11111111111111111111111111111111111111111111111)
        data = request.get_json()
        print(data)
        id = data['id']
        message = Message.query.filter_by(id=id).first()
        db.session.delete(message)
        db.session.commit()
        socketio.emit('refresh chat')
    return render_template('chat.html')



@app.route('/save', methods=['GET', 'POST'])
def save():
    if request.method == 'POST':
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        data = request.get_json()
        message = data['message']
        room_id = data['room_id']
        user_id = current_user.id
        new_message = Message(message=message, user_id=user_id, room_id=room_id)
        db.session.add(new_message)
        db.session.commit()
        
        return str(new_message.id)
    return render_template('room.html')


@socketio.on('my event')
def handle_my_custom_event(json, methods=['GET', 'POST']):
    print('received my event: ' + str(json))
    socketio.emit('my response', json, callback=messageReceived)


@app.route("/callback", methods=["GET", "POST"])
def callback():
    if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            new_user = User(username=username, email=email)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('room'))
    token = oauth.auth0.authorize_access_token()
    a =json.dumps(token, indent=4)
    userinfo = token['userinfo']
    user = User.query.filter_by(email=userinfo['email']).first()
    if user is None:
        
        email = userinfo['email']
        return render_template('signup.html', email=email)
    login_user(user)
    return redirect(url_for('room'))

@app.route("/")
@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

if __name__ == '__main__':
    socketio.run(app, debug=True)
