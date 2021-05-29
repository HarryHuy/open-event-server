from datetime import timedelta, timezone, datetime
from binascii import hexlify, unhexlify
import random
import string

from sqlalchemy.ext.declarative import AbstractConcreteBase, \
    declared_attr
from sqlalchemy.orm import declarative_mixin
from pyotp import random_hex, TOTP
from pyotp.utils import strings_equal, build_uri
from flask import current_app

from app.models import db
from app.models.base import SoftDeletionModel


def random_rs_code(len=8):
    rand = random.SystemRandom()
    code = rand.choices(string.digits + string.ascii_uppercase, k=len)
    return hexlify(''.join(code).encode('utf-8'))


class MFADevice(AbstractConcreteBase, db.Model):
    """
    Abstract base model for all MFA devices. A device isn't neccessary a real device, 
    it can be an App, Mailbox... or anything that can respond to the challenge.
    
    .. attribute:: activated
        *BooleanField*: A boolean value that tells us whether this device has
        been confirmed as valid. As a rule, after adding a new MFA device, 
        user have to perform a first challenge to confirm that device work.
    """

    id = db.Column(db.Integer, primary_key=True)
    is_default = db.Column(db.Boolean, default=False)
    activated = db.Column(db.Boolean, default=False)

    @declared_attr
    def user_id(cls):
        return db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)

    @declared_attr
    def user(cls):
        return db.relationship("User")

    def verify_token(self, token):
        return False

    # Flask-SQLAlchemy Model class has some underground actions
    # that re-construct the __tablename__ attribute
    # which was eliminated by SQLAlchemy AbstractConcreteBase.
    __tablename__ = None

    @declared_attr
    def __mapper_args__(cls):
        # Config subclasses mapping for polymorphical query.
        return {'polymorphic_identity': cls.__name__,
                'concrete': True} if cls.__name__ != "MFADevice" else {}

    
class SideChannelMFADevice(MFADevice):
    """
    Abstract base model for interactive device like Email MFA, SMS MFA,
    or App pushing verification...

    .. attribute:: token
        *String*: A generated token using to verify the login
        that should be sent to user via a different channel.
    """

    token = None
    valid_until = None

    def generate_token(self):
        pass

    def verify_token(self, token):
        return False

    __tablename__ = None


@declarative_mixin
class ThrottlingMixin:
    """
    Mixin class for models that need throttling behaviour.
    """

    throttling_failure_count = None
    throttling_failure_timestamp = None

    @property
    def throttling_enabled(self):
        return None

    @property
    def throttle_factor(self):
        pass

    def verify_is_allowed(self):
        return None
    
    def throttle_reset(self):
        pass
        
    def throttle_increment(self):
        pass


class TOTPDevice(MFADevice):
    """
    TOTP device model

    .. attribute:: _secret
        *String*: A hex-encoded secret key of 40 bytes minimum that's being shared
        with user to generate the token.

    .. attribute:: _rs_code
        *String*: A code use to remove TOTP verification 
        when user cannot access to their TOTP device.

    .. attribute:: step
        *SmallInteger*: The length of validation step in seconds.

    .. attribute:: digits
        *SmallInteger*: The number of expected digits in a token.

    .. attribute:: valid_window
        *SmallInteger*: The number of allowed validation steps.

    .. attribute:: last_verified
        *Integer*: The validation step of the last success verification.
    """

    _secret = db.Column(db.String(length=40), default=random_hex(40))
    _rs_code = db.Column(db.String(length=16), default=random_rs_code(8))
    step = db.Column(db.SmallInteger, default=30)
    digits = db.Column(db.SmallInteger, default=6)
    valid_window = db.Column(db.SmallInteger, default=1)
    last_verified = db.Column(db.Integer, default=0)

    @property
    def secret(self):
        return unhexlify(self._secret)

    @property
    def rs_code(self):
        return unhexlify(self._rs_code)

    @property
    def config_uri(self):
        params = {
            'secret': self.secret,
            'digits': self.digits,
            'period': self.step,
            'issuer': current_app.config['APP_NAME'],
            'name': self.user.email
        }

        return build_uri(params)

    def verify_token(self, otp):

        totp = TOTP(self.secret, self.digits, interval=self.interval)
        now = datetime.now()
        verified = totp.verify(otp, now, self.valid_window)

        if verified:
            current_step = totp.at(now)
            if current_step < self.last_verified:
                verified = False
            else:
                self.last_verified = current_step
                self.throttle_reset(commit=False)
                db.session.commit()

        if not verified:
            self.throttle_increment(commit=True)

        return verified

    def verify_rs_code(self, rs_code):
        if string_equal(self.rs_code, rs_code):
            return True
        return False
