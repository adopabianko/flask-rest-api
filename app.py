from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from raven.contrib.flask import Sentry

app = Flask(__name__)
sentry = Sentry(app, dsn='https://4a3e69ff66e040d3aea744105a05349b:ac9989367b0649b6994ea80bde1edc8c@sentry.io/1263246')

app.config['SECRET_KEY'] = 'asdasd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database/todo.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    users = User.query.all()

    output = []
    sdfaasd = ''
    sdfdsa = ''

    for user in users:
        user_data = {}

        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify(
        {
            'status': 'ok',
            'message': 'List users',
            'data': output
        }
    )

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify(
            {
                'status': 'error',
                'message': 'No user found!',
                'data': None
            }
        )

    user_data = {}

    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify(
        {
            'status': 'ok',
            'message': 'User',
            'data': user_data
        }
    )

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()


    return jsonify(
        {
            'status': 'ok',
            'message': 'Data successfully saved',
            'data': None
        }
    )

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify(
            {
                'status': 'error',
                'message': 'No user found!',
                'data': None
            }
        )
    user.admin = True
    db.session.commit()

    return jsonify(
        {
            'status': 'ok',
            'message': 'Data successfully updated',
            'data': None
        }
    )

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify(
            {
                'status': 'error',
                'message': 'No user found!',
                'data': None
            }
        )

    db.session.delete(user)
    db.session.commit()

    return jsonify(
        {
            'status': 'ok',
            'message': 'Data successfully deleted',
            'data': None
        }
    )

@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

if __name__ == '__main__':
    app.run(debug=True)
