#!/usr/bin/env python3
""" Session auth
"""

import uuid
from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """ Session Authentication class. """

    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """ Creates a Session ID for a user_id. """
        if user_id is None or not isinstance(user_id, str):
            return None

        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Returns the user_id for a sesion_id. """
        if session_id is None or not isinstance(session_id, str):
            return None

        user_id = self.user_id_by_session_id.get(session_id)

        return user_id

    def current_user(self, request=None):
        """ Returns a User instance based on a cookie value. """
        session_id = self.session_cookie(request)
        if session_id is None:
            return None

        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return None

        return User.get(user_id)

    def destroy_session(self, request=None):
        """ Destroys the user session and logout. """
        if request is None:
            return False

        session_cookie = self.session_cookie(request)
        if not session_cookie:
            return False

        user_id = self.user_id_for_session_id(session_cookie)
        if not user_id:
            return False

        self.user_id_by_session_id.pop(session_cookie, None)

        return True
