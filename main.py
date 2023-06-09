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
from sqlalchemy.sql import func
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vnkdjnfjknfl1232#'
socketio = SocketIO(app)
login_manager = LoginManager(app)

DB_NAME = "database.db"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///{}".format(DB_NAME)
db = SQLAlchemy(app)



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
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)


class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())
    messages = db.relationship('Message', backref='room', lazy=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class UserRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)


class RoomJoinRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)


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
    rooms = db.session.query(Room.name, Room.id, User.username)\
        .join(User, User.id == Room.creator_id)\
        .filter(Room.id.notin_(db.session.query(UserRoom.room_id).filter(UserRoom.user_id == current_user.id)))\
        .all()
    
    
    requests = db.session.query(RoomJoinRequest.user_id, RoomJoinRequest.room_id)\
        .all()
    current_userid  = current_user.id
    return render_template('room.html', rooms=rooms, requests=requests, current_userid=current_userid)

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
        new_user_room = UserRoom(user_id=creator_id, room_id=new_room.id)
        db.session.add(new_user_room)
        db.session.commit()
        return redirect('/chat/{}'.format(new_room.id))
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
    #chaeck if user is in room
    if db.session.query(UserRoom).filter(UserRoom.user_id == current_user.id, UserRoom.room_id == room_id).count() == 0:
        return redirect(url_for('room'))
    messages = db.session.query(Message.message, User.username, Message.id)\
        .join(User, User.id == Message.user_id)\
        .filter(Message.room_id == room_id)\
        .order_by(Message.date_created)\
        .all()
    print(messages)

    return render_template('chat.html', messages=messages, username=current_user.username, room_id=room_id)

@app.route('/myroom', methods=['GET', 'POST'])

def myroom():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    user = current_user
    rooms = db.session.query(Room.name, Room.id)\
        .join(UserRoom, UserRoom.room_id == Room.id)\
        .filter(UserRoom.user_id == user.id)\
        .all()
    print(rooms)
    return render_template('myroom.html', rooms=rooms)



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        # encrypt password using sha256

        if User.query.filter_by(username=username).first():
            print('Username already exists!')
            flash(message='Username already exists!', category='error')
            return redirect(url_for('signup'))
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()

        print(username, password)
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        login_user(user=new_user, remember=True)
        return redirect(url_for('room'))
    return render_template('register.html')

@app.route('/join_room/<int:room_id>', methods=['GET', 'POST'])
def join_room(room_id):
    if current_user.is_authenticated:
        userid = current_user.id
        roomid = room_id
        print(userid, roomid)
        new_join_request = RoomJoinRequest(user_id=current_user.id, room_id=room_id)
        print(new_join_request)
        db.session.add(new_join_request)
        db.session.commit()
        print('Join request sent!')
        flash(message='Join request sent!', category='success')
        return redirect('/room')
    else:
        return redirect(url_for('login'))

@app.route('/recive_request/<int:room_id>/<int:user_id>', methods=['GET', 'POST'])
def recive_request(room_id,user_id):
    if current_user.is_authenticated:
        userid = user_id
        roomid = room_id
        print(userid, roomid)
        #check if user is creator of room
        if db.session.query(Room).filter(Room.id == roomid, Room.creator_id == current_user.id).count() == 0:
            return redirect(url_for('room'))
        #check if user is already in room
        if db.session.query(UserRoom).filter(UserRoom.user_id == userid, UserRoom.room_id == roomid).count() == 0:
            new_user_room = UserRoom(user_id=userid, room_id=roomid)
            db.session.add(new_user_room)
            db.session.commit()

            db.session.query(RoomJoinRequest).filter(RoomJoinRequest.user_id == userid, RoomJoinRequest.room_id == roomid).delete()
            db.session.commit()
            print('User added to room!')
            flash(message='User added to room!', category='success')
        else:
            print('User already in room!')
            flash(message='User already in room!', category='success')
        return redirect(url_for('manage_requests'))
    else:
        return redirect(url_for('login'))

@app.route('/decline_request/<int:room_id>/<int:user_id>', methods=['GET', 'POST'])
def decline_request(room_id, user_id):
    if current_user.is_authenticated:
        userid = user_id
        roomid = room_id
        print(userid, roomid)

        if db.session.query(Room).filter(Room.id == roomid, Room.creator_id == current_user.id).count() == 0:
            return redirect(url_for('room'))
        if db.session.query(RoomJoinRequest).filter(RoomJoinRequest.user_id == userid, RoomJoinRequest.room_id == roomid).count() == 0:
            print('User not in room!')
            flash(message='User not in room!', category='success')
        else:
            db.session.query(RoomJoinRequest).filter(RoomJoinRequest.user_id == userid, RoomJoinRequest.room_id == roomid).delete()
            db.session.commit()
            print('User declined!')
            flash(message='User declined!', category='success')
        return redirect(url_for('manage_requests'))
    else:
        return redirect(url_for('login'))

@app.route('/manage_requests', methods=['GET', 'POST'])
@login_required
def manage_requests():
    user_id = current_user.id
    requests = db.session.query(Room.name, User.username, Room.id, User.id)\
        .join(RoomJoinRequest, RoomJoinRequest.room_id == Room.id)\
        .join(User, User.id == RoomJoinRequest.user_id)\
        .filter(Room.creator_id == user_id)\
        .all()
    return render_template('manage_request.html', requests=requests)


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(username, password)
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            print('Logged in successfully!')
            login_user(user, remember=True)
            return redirect(url_for('myroom'))
        else:
            flash('Invalid Credentials')
            return redirect(url_for('login'))

    if current_user.is_authenticated:
        return redirect(url_for('myroom'))
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





if __name__ == '__main__':
    socketio.run(app, debug=True)
