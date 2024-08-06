#!/usr/bin/env python3
""" Basic auth
"""

import base64
from api.v1.auth.auth import Auth
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """ basic auth class.
    """

    def extract_base64_authorization_header(self, h: str) -> str:
        """ Extracts the Base64 part of the
          Authorization header for Basic
            Authentication.
        """
        if not isinstance(h, str):
            return None
        if not h.startswith("Basic "):
            return None
        return h.split(" ", 1)[1]

    def decode_base64_authorization_header(self, h: str) -> str:
        """ Decodes the Base64 authorization header. """
        if not isinstance(h, str):
            return None
        try:
            base64_bytes = h.encode('utf-8')
            decoded_bytes = base64.b64decode(base64_bytes)
            return decoded_bytes.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(self, h: str) -> (str, str):
        """ Extracts the user email and password
          from the Base64 decoded value. """
        if not isinstance(h, str):
            return None, None
        if ':' not in h:
            return None, None
        return h.split(":", 1)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """ Returns the User instance based on
          email and password. """
        if (not user_email or
                type(user_email) != str or
                not user_pwd or type(user_pwd) != str):
            return
        user = None
        try:
            user = User.search({"email": user_email})
        except Exception:
            return
        if not user:
            return
        for u in user:
            if u.is_valid_password(user_pwd):
                return u

    def current_user(self, request=None) -> TypeVar('User'):
        """ Returns the User instance for a request. """
        header = self.authorization_header(request)
        b64header = self.extract_base64_authorization_header(header)
        decoded = self.decode_base64_authorization_header(b64header)
        user_creds = self.extract_user_credentials(decoded)
        return self.user_object_from_credentials(*user_creds)
