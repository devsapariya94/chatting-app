from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_socketio import SocketIO
from flask_session import Session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import os
from sqlalchemy.sql import func

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vnkdjnfjknfl1232#'
socketio = SocketIO(app)
login_manager = LoginManager(app)

db = SQLAlchemy(app)
DB_NAME = "database.db"
app.config["SECRET_KEY"]="helloworld"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///{}".format(DB_NAME)
db.init_app(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())


class Message (db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(1000), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())


if not os.path.exists(DB_NAME):
    db.create_all(app=app)
    print('Created Database!')

@login_manager.user_loader
def load_user(user_id):
    # Return the User object for the given user_id
    return User.query.get(int(user_id))


@app.route('/chat')
def chat():
    if not current_user.is_authenticated:
       
        return redirect(url_for('login'))
    # send the messages and the username to the template
    messages = db.session.query(Message.message, User.username, Message.id)\
        .join(User, User.id == Message.user_id)\
        .order_by(Message.date_created)\
        .all()
    print(messages)

    return render_template('chat.html', messages=messages, username=current_user.username)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(username, password)
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(username, password)
        user = User.query.filter_by(username=username).first()
        print(user)
        print(user.password)
        if user and user.password == password:
            print('Logged in successfully!')
            login_user(user, remember=True)
            return redirect(url_for('chat'))
        else:
            flash('Invalid Credentials')
            return redirect(url_for('login'))

    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

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
        user_id = current_user.id
        new_message = Message(message=message, user_id=user_id)
        db.session.add(new_message)
        db.session.commit()
        json = {'message': message, 'username': current_user.username, 'id': new_message.id}
        socketio.emit('my event', json, callback=messageReceived)
        return str(new_message.id)
    return render_template('chat.html')


@socketio.on('my event')
def handle_my_custom_event(json, methods=['GET', 'POST']):
    print('received my event: ' + str(json))
    socketio.emit('my response', json, callback=messageReceived)





if __name__ == '__main__':
    socketio.run(app, debug=True)
