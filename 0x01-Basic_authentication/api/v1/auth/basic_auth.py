#!/usr/bin/env python3
""" Basic auth
"""

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
