#!/usr/bin/env python3
""" Auth class
"""

from flask import request


class Auth:
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ require_auth impl
        """
        return False

    def authorization_header(self, request=None) -> str:
        """ authorization_header impl
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ current_user impl
        """
        return None