#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User, UserSchema

user_schema = UserSchema()


class ClearSession(Resource):

    def delete(self):

        session["page_views"] = None
        session["user_id"] = None

        return {}, 204


class Signup(Resource):
    def post(self):
        data = request.get_json() or {}

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {"error": "Username and password required"}, 400

        # Create and save user with hashed password
        user = User(username=username)
        user.password_hash = password

        db.session.add(user)
        db.session.commit()

        # Log user in via session
        session["user_id"] = user.id

        return user_schema.dump(user), 201


class Login(Resource):
    def post(self):
        data = request.get_json() or {}

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {"error": "Username and password required"}, 400

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session["user_id"] = user.id
            return user_schema.dump(user), 200

        return {"error": "Invalid username or password"}, 401


class Logout(Resource):
    def delete(self):
        # Remove the user_id from the session
        session["user_id"] = None
        return {}, 204


class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            # No authenticated user – empty response, 204 status
            return {}, 204

        user = User.query.get(user_id)

        if not user:
            return {}, 204

        return user_schema.dump(user), 200


api.add_resource(ClearSession, "/clear", endpoint="clear")
api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")

if __name__ == "__main__":
    app.run(port=5555, debug=True)
