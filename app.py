#!/usr/bin/env python3
import os
import random
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt
from flask_restful import Api, Resource
from flask_cors import CORS
from models import db, Redflags, Intervention, User, bcrypt

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI') #'sqlite:///app.db' 
app.config["JWT_SECRET_KEY"] = "your_jwt_secret_key"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["SECRET_KEY"] = "your_secret_key"

app.json.compact = False
jwt = JWTManager(app)

migrate = Migrate(app, db)
db.init_app(app)
bcrypt.init_app(app)
api = Api(app)

@app.route("/")
def index():
    return "<h1>IReporter App Server</h1>"

class Login(Resource):
    def post(self):
        request_json = request.get_json()
        email = request_json.get('email', None)
        password = request_json.get('password', None)

        user = User.query.filter_by(email=email).first()

        if user and user.authenticate(password):
            access_token = create_access_token(identity=user.id)
            return {"access_token": access_token}
        else:
            return {"message": "Invalid email or password"}, 401

class CheckSession(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        if current_user:
            intervention = [interv.to_dict(only=('id', 'intervention', 'description', 'geolocation', 'image', 'video', 'date_added', 'status')) for interv in current_user.interventions]
            redflags = [redflgs.to_dict(only=('id', 'redflag', 'description', 'geolocation', 'image', 'video', 'date_added', 'status')) for redflgs in current_user.redflags]
            return {
                "id": current_user.id,
                "name": current_user.name,
                "email": current_user.email,
                "intervention": intervention,
                "redflags": redflags
            }, 200
        else:
            return {"error": "User not found"}, 404

BLACKLIST = set()
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, decrypted_token):
    return decrypted_token['jti'] in BLACKLIST

class Logout(Resource):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        BLACKLIST.add(jti)
        return {"success": "Successfully logged out"}, 200

class Users(Resource):
    def get(self):
        users = User.query.all()
        return [user.to_dict(only=('id', 'name', 'email', 'role')) for user in users], 200

    def post(self):
        data = request.get_json()
        password = data['password']
        user_role = 'user'
        try:
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(
                name=data['name'],
                email=data['email'],
                role=user_role
            )
            new_user._password_hash = password_hash
            db.session.add(new_user)
            db.session.commit()
            return {"success": "User created successfully!"}, 201
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400

class RedflagsResource(Resource):
    def get(self):
        redflag = Redflags.query.all()
        return [redflg.to_dict() for redflg in redflag], 200
    
class IntervensionsResource(Resource):
    def get(self):
        intervention = Intervention.query.all()
        return [inter.to_dict() for inter in intervention], 200

api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(Users, '/users')
api.add_resource(RedflagsResource, '/redflags')
api.add_resource(IntervensionsResource, '/interventions')

if __name__ == "__main__":
    app.run(debug=False)