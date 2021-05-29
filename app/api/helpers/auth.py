import datetime
from functools import wraps

import flask_login as login
import pytz
from flask_login import current_user
from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt

from app.models import db
from app.models.user import User
from app.models.user_token_blacklist import UserTokenBlackListTime
from app.models.mfa import MFADevice


class AuthManager:
    def __init__(self):
        pass

    @staticmethod
    def init_login(app):
        from flask import redirect, request, url_for

        login_manager = login.LoginManager()
        login_manager.init_app(app)

        # Create user loader function
        @login_manager.user_loader
        def load_user(user_id):
            return db.session.query(User).get(user_id)

        @login_manager.unauthorized_handler
        def unauthorized():
            return redirect(url_for('admin.login_view', next=request.url))

    @staticmethod
    def is_verified_user():
        return current_user.is_verified

    @staticmethod
    def is_accessible():
        return current_user.is_authenticated

    @staticmethod
    def check_auth_admin(username, password):
        # This function is called to check for proper authentication & admin rights
        if username and password:
            user = User.query.filter_by(_email=username).first()
            if user and user.is_correct_password(password) and user.is_admin:
                return True
        return False


def blacklist_token(user):
    blacklist_time = UserTokenBlackListTime.query.filter_by(user_id=user.id).first()
    if blacklist_time:
        blacklist_time.blacklisted_at = datetime.datetime.now(pytz.utc)
    else:
        blacklist_time = UserTokenBlackListTime(user_id=user.id)

    db.session.add(blacklist_time)
    db.session.commit()


def is_token_blacklisted(token):
    blacklist_time = UserTokenBlackListTime.query.filter_by(
        user_id=token['identity']
    ).first()
    if not blacklist_time:
        return False
    return token['iat'] < blacklist_time.blacklisted_at.timestamp()


def jwt_mfa_required(fn):
    """
    Customize jwt_required decorator to require additional MFA verification.
    """

    @wraps(fn)
    def decorator(*args, **kwargs):
        verify_jwt_in_request()
        payload = get_jwt()
        if not payload['mfa_verified']:
            mfa_devices = MFADevice.query.filter_by(user=current_user, activated=True).all()
            if mfa_devices is not None:
                return jsonify(msg='MFA required.'), 403
        return fn(*args, **kwargs)

    return decorator
