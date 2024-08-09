#!/usr/bin/env python3
""" Auth class
"""

from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """ Auth Class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ require_auth impl
        """
        if not path or not excluded_paths or len(excluded_paths) == 0:
            return True

        if path[-1] != '/':
            path = path + '/'

        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                if path.startswith(excluded_path[:-1]):
                    return False
            else:
                if path == excluded_path:
                    return False

        return True

    def authorization_header(self, request=None) -> str:
        """ authorization_header impl
        """
        if request is None:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """ current_user impl
        """
        return None
    
    def session_cookie(self, request=None):
        """session_cookie impl
        """
        if request is None:
            return None
        
        cookie_name = getenv('SESSION_NAME')

        if not cookie_name:
            return None
        
        return request.cookies.get(cookie_name)
