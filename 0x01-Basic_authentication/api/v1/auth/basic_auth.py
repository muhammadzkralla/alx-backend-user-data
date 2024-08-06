#!/usr/bin/env python3
""" Basic auth
"""

import base64
from api.v1.auth.auth import Auth


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
