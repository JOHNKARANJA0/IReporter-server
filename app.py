#!/usr/bin/env python3
import os
from datetime import timedelta
import cloudinary
from cloudinary.uploader import upload as cloudinary_upload
import pyotp
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt
from flask_restful import Api, Resource
from flask_cors import CORS
from models import db, Redflags, Intervention, User, bcrypt
from utils import generate_totp_secret, generate_totp_token, send_email

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]}})

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')   #'sqlite:///app.db' 
app.config["JWT_SECRET_KEY"] = "your_jwt_secret_key"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["SECRET_KEY"] = "your_secret_key"

app.json.compact = False
jwt = JWTManager(app)       

migrate = Migrate(app, db)
db.init_app(app)
bcrypt.init_app(app)
api = Api(app)

cloudinary.config(
    cloud_name=os.environ.get('CLOUD_NAME'),
    api_key=os.environ.get('API_KEY'),
    api_secret=os.environ.get('API_SECRET')
)

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
            user.is_online = True
            db.session.commit()
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
            user.is_active = True
            db.session.commit()
            intervention = [interv.to_dict(only=('id', 'intervention', 'description', 'geolocation', 'image', 'video', 'date_added', 'status')) for interv in user.interventions]
            redflags = [redflgs.to_dict(only=('id', 'redflag', 'description', 'geolocation', 'image', 'video', 'date_added', 'status')) for redflgs in user.redflags]
            return {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "image": user.image,
                "role": user.role,
                "intervention": intervention,
                "redflags": redflags,
                "token_verified": user.token_verified,
                "is_active": user.is_active
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
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if user:
            user.is_active = False
            db.session.commit()
        jti = get_jwt()["jti"]
        BLACKLIST.add(jti)
        return {"success": "Successfully logged out"}, 200

class Users(Resource):
    def get(self):
        users = User.query.all()
        return [user.to_dict(only=('id', 'name', 'email', 'role', 'interventions','redflags', 'token_verified', 'is_active')) for user in users], 200

    def post(self):
        data = request.get_json()
        password = data['password']
        user_role = 'user'
        try:
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            totp_secret = generate_totp_secret()
            totp_token = generate_totp_token(totp_secret)
            new_user = User(
                name=data['name'],
                email=data['email'],
                role=user_role,
                _password_hash=password_hash,
                token=totp_secret
            )
            db.session.add(new_user)
            db.session.commit()
            # Send the token to user's email
            email_sent = send_email(
                to_email=data['email'],
                subject="Your Verification Token",
                body=f"""Hello, {data['name']}.\n Welcome to the Ireporter app.\nYour verification token is: {totp_token}. \n\nThank you,\nIReporter Team"""
            )
            if email_sent:
                return {"success": "User created successfully! Verification token sent to email.", "user": new_user.to_dict()}, 201
            else:
                return {"success": "User created successfully! Failed to send verification token.", "user": new_user.to_dict()}, 201
        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400
    @jwt_required()
    def patch(self):
        current_user = get_jwt_identity()
        user = User.query.get(current_user)

        if user:
            data = request.form
            image = request.files.get('image')

            try:
                if image:
                    upload_result = cloudinary_upload(image, resource_type="image", transformation=[
                        {"width": 200, "height": 200, "crop": "fill", "gravity": "auto"},
                        {"fetch_format": "auto", "quality": "auto"}
                    ])
                    user.image = upload_result['secure_url']
                if 'name' in data:
                    user.name = data['name']
                if 'email' in data:
                    user.email = data['email']
                if 'password' in data:
                    old_password = data.get('old_password')
                    new_password = data.get('password')
                    if not user.authenticate(old_password):
                        return {"error": "Incorrect current password"}, 400
                    user.password_hash = new_password

                db.session.commit()
                return {"message": "User profile updated successfully"}, 200
            except Exception as e:
                db.session.rollback()
                return {"errors": [str(e)]}, 400
        else:
            return {"error": "User not found"}, 404
class VerifyToken(Resource):
    def post(self):
        data = request.get_json()
        email = data['email']
        token_from_request = data['token']

        user = User.query.filter_by(email=email).first()

        if user:
            totp = pyotp.TOTP(user.token, interval=200) 

            is_valid = totp.verify(token_from_request, valid_window=1)

            if is_valid:
                user.token_verified = True
                db.session.commit()
                return {"message": "Token verified successfully."}, 200
            else:
                return {"message": "Invalid token or email."}, 400
        else:
            return {"message": "User not found."}, 404
class RedflagResource(Resource):
    def get(self):
        redflag = Redflags.query.all()
        return [redflg.to_dict() for redflg in redflag], 200

    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()
        data = request.form
        image = request.files.get('image')
        video = request.files.get('video')

        try:
            if image:
                image_upload_result = cloudinary_upload(image, resource_type="image", transformation=[
                    {"width": 200, "height": 200, "crop": "fill", "gravity": "auto"},
                    {"fetch_format": "auto", "quality": "auto"}
                ])
                image_url = image_upload_result['secure_url']
            else:
                image_url = None

            if video:
                video_upload_result = cloudinary_upload(video, resource_type="video", transformation=[
                    {"width": 400, "height": 300, "crop": "pad"},
                    {"width": 260, "height": 200, "crop": "crop", "gravity": "north"}
                ])
                video_url = video_upload_result['secure_url']
            else:
                video_url = None

            new_entity = Redflags( 
                redflag=data.get('redflag'), 
                description=data.get('description'),
                geolocation=data.get('geolocation'),
                image=image_url,
                video=video_url,
                user_id=current_user
            )
            
            db.session.add(new_entity)
            db.session.commit()
            return new_entity.to_dict(), 201

        except Exception as e:
            db.session.rollback()
            return {"errors": [str(e)]}, 400

    @jwt_required()
    def patch(self, redflag_id):
        current_user = get_jwt_identity()
        redflag = Redflags.query.get(redflag_id)
        if redflag and redflag.user_id == current_user and redflag.status == 'draft':
            data = request.form
            image = request.files.get('image')
            video = request.files.get('video')

            try:
                if image:
                    upload_result = cloudinary_upload(image, resource_type="image", transformation=[
                        {"width": 200, "height": 200, "crop": "fill", "gravity": "auto"},
                        {"fetch_format": "auto", "quality": "auto"}
                    ])
                    redflag.image = upload_result['secure_url']
                if video:
                    upload_result = cloudinary_upload(video, resource_type="video", transformation=[
                        {"width": 400, "height": 300, "crop": "pad"},
                        {"width": 260, "height": 200, "crop": "crop", "gravity": "north"}
                    ])
                    redflag.video = upload_result['secure_url']
                redflag.redflag = data.get('redflag', redflag.redflag)
                redflag.description = data.get('description', redflag.description)
                redflag.geolocation = data.get('geolocation', redflag.geolocation)
                db.session.commit()
                return redflag.to_dict(), 200
            except Exception as e:
                db.session.rollback()
                return {"errors": [str(e)]}, 400
        else:
            return {"error": "Not allowed to update"}, 403

    @jwt_required()
    def delete(self, redflag_id):
        current_user = get_jwt_identity()
        redflag = Redflags.query.get(redflag_id)
        if redflag and redflag.user_id == current_user and redflag.status == 'draft':
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
        data = request.form
        image = request.files.get('image')
        video = request.files.get('video')

        try:
            if image:
                upload_result = cloudinary_upload(image, resource_type="image", transformation=[
                    {"width": 200, "height": 200, "crop": "fill", "gravity": "auto"},
                    {"fetch_format": "auto", "quality": "auto"}
                ])
                image_url = upload_result['secure_url']
            else:
                image_url = None

            if video:
                upload_result = cloudinary_upload(video, resource_type="video", transformation=[
                    {"width": 400, "height": 300, "crop": "pad"},
                    {"width": 260, "height": 200, "crop": "crop", "gravity": "north"}
                ])
                video_url = upload_result['secure_url']
            else:
                video_url = None

            new_intervention = Intervention(
                intervention=data.get('intervention'),
                description=data.get('description'),
                geolocation=data.get('geolocation'),
                image=image_url,
                video=video_url,
                user_id=current_user
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
        if intervention and intervention.user_id == current_user and intervention.status == 'draft':
            data = request.form
            image = request.files.get('image')
            video = request.files.get('video')

            try:
                if image:
                    upload_result = cloudinary_upload(image, resource_type="image", transformation=[
                    {"width": 200, "height": 200, "crop": "fill", "gravity": "auto"},
                    {"fetch_format": "auto", "quality": "auto"}
                ])
                    intervention.image = upload_result['secure_url']
                if video:
                    upload_result = cloudinary_upload(video, resource_type="video", transformation=[
                        {"width": 400, "height": 300, "crop": "pad"},
                        {"width": 260, "height": 200, "crop": "crop", "gravity": "north"}
                    ])
                    intervention.video = upload_result['secure_url']
                intervention.intervention = data.get('intervention', intervention.intervention)
                intervention.description = data.get('description', intervention.description)
                intervention.geolocation = data.get('geolocation', intervention.geolocation)
                db.session.commit()
                return intervention.to_dict(), 200
            except Exception as e:
                db.session.rollback()
                return {"errors": [str(e)]}, 400
        else:
            return {"error": "Not allowed to update"}, 403

    @jwt_required()
    def delete(self, intervention_id):
        current_user = get_jwt_identity()
        intervention = Intervention.query.get(intervention_id)
        if intervention and intervention.user_id == current_user and intervention.status == 'draft':
            db.session.delete(intervention)
            db.session.commit()
            return {"message": "Intervention deleted successfully"}, 200
        else:
            return {"error": "Not allowed to delete"}, 403

class AdminStatusUpdateResource(Resource):
    @jwt_required()
    def patch(self, entity_type, entity_id):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
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
            old_status = entity.status
            entity.status = new_status
            db.session.commit()
            associated_user = User.query.get(entity.user_id)
            if associated_user:
                if old_status != new_status:
                    email_sent = send_email(
                        to_email=associated_user.email,
                        subject=f"Your {entity_type} status has been updated",
                        body=f"Hello {associated_user.name},\n\nYour {entity_type} with ID {entity_id} has been updated from '{old_status}' to '{new_status}'.\n\nThank you,\nIReporter Team"
                    )
                    if not email_sent:
                        return {"error": "Status updated, but failed to send notification email"}, 200
            
            return entity.to_dict(), 200
        else:
            return {"error": "Entity not found"}, 404
        
class AdminTokenUpdateResource(Resource):
    @jwt_required()
    def patch(self, user_id):
        current_user_id = get_jwt_identity()
        admin_user = User.query.get(current_user_id)
        if admin_user is None or admin_user.role != 'admin':
            return {"error": "Admin access required"}, 403

        user = User.query.get(user_id)
        if user is None:
            return {"error": "User not found"}, 404
        
        data = request.get_json()
        token_verified = data.get('token_verified')

        if token_verified is not None:
            old_status = user.token_verified
            user.token_verified = token_verified
            db.session.commit()
            
            if not token_verified and old_status:  
                email_sent = send_email(
                    to_email=user.email,
                    subject="Account Deactivation Notice",
                    body=f"Hello {user.name},\n\nYour account has been deactivated.\nYou have violated the terms and conditions of IReporter.\nIf you have any querys or you think it was done wrongly reply to this email to contact support.\n\nThank you,\nIReporter Team"
                )
                if not email_sent:
                    return {"error": "Status updated, but failed to send deactivation notification email"}, 200
            
            elif token_verified and not old_status:  
                email_sent = send_email(
                    to_email=user.email,
                    subject="Account Reactivation Notice",
                    body=f"Welcome back {user.name},\n\nYour account has been reactivated.\nPlease ensure that you maintain your usage within our terms and conditions.\n\nThank you,\nIReporter Team"
                )
                if not email_sent:
                    return {"error": "Status updated, but failed to send reactivation notification email"}, 200
            
            return {"message": "User token_verified updated successfully"}, 200
        else:
            return {"error": "No token_verified field provided"}, 400

api.add_resource(Login, '/login')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Logout, '/logout')
api.add_resource(Users, '/users')
api.add_resource(VerifyToken, '/verify_token')
api.add_resource(RedflagResource, '/redflags', '/redflags/<int:redflag_id>')
api.add_resource(InterventionResource, '/interventions', '/interventions/<int:intervention_id>')
api.add_resource(AdminStatusUpdateResource, '/admin/<string:entity_type>/<int:entity_id>/status')
api.add_resource(AdminTokenUpdateResource, '/admin/users/<int:user_id>/update-token')

if __name__ == '__main__':
    app.run(port=5555, debug=True)