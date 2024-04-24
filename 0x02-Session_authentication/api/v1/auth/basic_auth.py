#!/usr/bin/env python3
""""API authentication"""
from flask import request
from api.v1.auth.auth import Auth
from models.user import User
from typing import Tuple, TypeVar


class BasicAuth(Auth):
    """BasicAuth class for API endpoints."""
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Extract base64 authorization header"""
        if authorization_header is None or type(authorization_header) \
           is not str:
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> (str, str):
        """Decode base64 authorization header"""
        if base64_authorization_header is None or \
           type(base64_authorization_header) is not str:
            return None
        try:
            return base64_authorization_header.encode('utf-8').decode('base64')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """Extract user credentials"""
        if decoded_base64_authorization_header is None \
           or type(decoded_base64_authorization_header) is not str:
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        return tuple(decoded_base64_authorization_header.split(':', 1))

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Returns the User instance based on email and password."""
        if not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None

        # Search for the user by email
        user_list = User.search({'email': user_email})

        # If user list is empty, return None
        if len(user_list) == 0:
            return None

        # Check each user in the list for valid password
        for user in user_list:
            if user.is_valid_password(user_pwd):
                return user

        # If no user with matching password found, return None
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Current user"""
        header = self.authorization_header(request)
        base64header = self.extract_base64_authorization_header(header)
        decoded = self.decode_base64_authorization_header(base64header)
        user_credentials = self.extract_user_credentials(decoded)
        return self.user_object_from_credentials(*user_credentials)
