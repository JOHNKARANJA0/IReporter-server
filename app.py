#!/usr/bin/env python3
import os
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt
from flask_restful import Api, Resource
from flask_cors import CORS
from models import db, Redflags, Intervention, User, bcrypt

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]}})

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db' #os.environ.get('DATABASE_URI')
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
        user = User.query.get(current_user_id)
        if user:
            intervention = [interv.to_dict(only=('id', 'intervention', 'description', 'geolocation', 'image', 'video', 'date_added', 'status')) for interv in user.interventions]
            redflags = [redflgs.to_dict(only=('id', 'redflag', 'description', 'geolocation', 'image', 'video', 'date_added', 'status')) for redflgs in user.redflags]
            return {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
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
        return [user.to_dict() for user in users], 200

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

class RedflagResource(Resource):
    def get(self):
        redflag = Redflags.query.all()
        return [redflg.to_dict() for redflg in redflag], 200
    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()
        data = request.get_json()
        try:
            new_redflag = Redflags(
                redflag=data['redflag'],
                description=data['description'],
                geolocation=data.get('geolocation'),
                image=data.get('image'),
                video=data.get('video'),
                user_id=current_user['id']
            )
            db.session.add(new_redflag)
            db.session.commit()
            return new_redflag.to_dict(), 201
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400

    @jwt_required()
    def patch(self, redflag_id):
        current_user = get_jwt_identity()
        redflag = Redflags.query.get(redflag_id)
        if redflag and redflag.user_id == current_user['id'] and redflag.status == 'draft':
            data = request.get_json()
            redflag.redflag = data.get('redflag', redflag.redflag)
            redflag.description = data.get('description', redflag.description)
            redflag.geolocation = data.get('geolocation', redflag.geolocation)
            redflag.image = data.get('image', redflag.image)
            redflag.video = data.get('video', redflag.video)
            db.session.commit()
            return redflag.to_dict(), 200
        else:
            return {"error": "Not allowed to update"}, 403

    @jwt_required()
    def delete(self, redflag_id):
        current_user = get_jwt_identity()
        redflag = Redflags.query.get(redflag_id)
        if redflag and redflag.user_id == current_user['id'] and redflag.status == 'draft':
            db.session.delete(redflag)
            db.session.commit()
            return {"message": "Redflag deleted successfully"}, 200
        else:
            return {"error": "Not allowed to delete"}, 403

class InterventionResource(Resource):
    def get(self):
        intervention = Intervention.query.all()
        return [inter.to_dict() for inter in intervention], 200
    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()
        data = request.get_json()
        try:
            new_intervention = Intervention(
                intervention=data['intervention'],
                description=data['description'],
                geolocation=data.get('geolocation'),
                image=data.get('image'),
                video=data.get('video'),
                user_id=current_user['id']
            )
            db.session.add(new_intervention)
            db.session.commit()
            return new_intervention.to_dict(), 201
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400

    @jwt_required()
    def patch(self, intervention_id):
        current_user = get_jwt_identity()
        intervention = Intervention.query.get(intervention_id)
        if intervention and intervention.user_id == current_user['id'] and intervention.status == 'draft':
            data = request.get_json()
            intervention.intervention = data.get('intervention', intervention.intervention)
            intervention.description = data.get('description', intervention.description)
            intervention.geolocation = data.get('geolocation', intervention.geolocation)
            intervention.image = data.get('image', intervention.image)
            intervention.video = data.get('video', intervention.video)
            db.session.commit()
            return intervention.to_dict(), 200
        else:
            return {"error": "Not allowed to update"}, 403

    @jwt_required()
    def delete(self, intervention_id):
        current_user = get_jwt_identity()
        intervention = Intervention.query.get(intervention_id)
        if intervention and intervention.user_id == current_user['id'] and intervention.status == 'draft':
            db.session.delete(intervention)
            db.session.commit()
            return {"message": "Intervention deleted successfully"}, 200
        else:
            return {"error": "Not allowed to delete"}, 403

class AdminStatusUpdateResource(Resource):
    @jwt_required()
    def patch(self, entity_type, entity_id):
        # Fetch the user ID from the JWT token
        current_user_id = get_jwt_identity()

        # Query the user object using the ID
        user = User.query.get(current_user_id)
        
        # Ensure the user is an admin
        if user is None or user.role != 'admin':
            return {"error": "Admin access required"}, 403

        data = request.get_json()
        new_status = data.get('status')
        
        if entity_type == 'redflag':
            entity = Redflags.query.get(entity_id)
        elif entity_type == 'intervention':
            entity = Intervention.query.get(entity_id)
        else:
            return {"error": "Invalid entity type"}, 400
        
        if entity:
            entity.status = new_status
            db.session.commit()
            return entity.to_dict(), 200
        else:
            return {"error": "Entity not found"}, 404

api.add_resource(Login, '/login')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Logout, '/logout')
api.add_resource(Users, '/users')
api.add_resource(RedflagResource, '/redflags', '/redflags/<int:redflag_id>')
api.add_resource(InterventionResource, '/interventions', '/interventions/<int:intervention_id>')
api.add_resource(AdminStatusUpdateResource, '/admin/<string:entity_type>/<int:entity_id>/status')

if __name__ == '__main__':
    app.run(port=5555, debug=True)