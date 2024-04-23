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
        """User object from credentials"""
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        user = User.search({'email': user_email})
        if user is None or not user.is_valid_password(user_pwd):
            return None
        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """Current user"""
        auth_header = self.authorization_header(request)
        base64_auth_header = self.extract_base64_authorization_header
        (auth_header)
        decoded_auth_header = self.decode_base64_authorization_header
        (base64_auth_header)
        user_credentials = self.extract_user_credentials(decoded_auth_header)
        return self.user_object_from_credentials(*user_credentials)
