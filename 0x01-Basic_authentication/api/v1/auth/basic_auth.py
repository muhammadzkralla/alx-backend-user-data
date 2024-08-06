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

    def user_object_from_credentials(self,
                                     em: str, pd: str) -> TypeVar('User'):
        """ Returns the User instance based on
          email and password. """
        if not isinstance(em, str) or not isinstance(pd, str):
            return None

        user = User.search(em)
        if not user:
            return None
        user = user[0]  # Assuming search returns a list of User instances
        if not user.is_valid_password(pd):
            return None
        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """ Returns the User instance for a request. """
        if request is None:
            return None

        auth_header = self.authorization_header(request)

        if auth_header is None:
            return None

        base64_auth_header = self.extract_base64_authorization_header(
            auth_header)
        if base64_auth_header is None:
            return None

        decoded_auth_header = self.decode_base64_authorization_header(
            base64_auth_header)
        if decoded_auth_header is None:
            return None

        email, password = self.extract_user_credentials(decoded_auth_header)
        if email is None or password is None:
            return None

        return self.user_object_from_credentials(email, password)
