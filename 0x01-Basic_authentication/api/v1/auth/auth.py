#!/usr/bin/env python3
""" Auth class
"""

from flask import request
from typing import List, TypeVar


class Auth:
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ require_auth impl
        """
        if not path or not excluded_paths or len(excluded_paths) == 0:
            return True

        if path[-1] != '/':
            path = path + '/'

        for excluded_path in excluded_paths:
            if path == excluded_path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """ authorization_header impl
        """
        if request:
            return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """ current_user impl
        """
        return None
