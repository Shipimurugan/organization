from django.contrib.auth.models import AnonymousUser
from rest_framework import exceptions
from rest_framework.authentication import get_authorization_header, BaseAuthentication
from rest_framework.permissions import BasePermission
import jwt
import json
import logging
from authentication.models import LoginUser
from cryptography.fernet import Fernet
from organization import settings

# from utils_consts.views import decrypt_token_data

logger = logging.getLogger(__name__)

def decrypt_token_data(data):
    cipher_suite = Fernet(settings.TOKEN_SECRET_KEY)
    decrypted_data = cipher_suite.decrypt(data.encode())
    return decrypted_data.decode()

class JWTAuthentication(BaseAuthentication):
    model = None
    def get_model(self):
        return LoginUser

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'token':
            return None

        if len(auth) == 1:
            msg = 'Invalid token header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Invalid token header'
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1]
            if token == "null":
                msg = 'Null token not allowed'
                raise exceptions.AuthenticationFailed(msg)
        except UnicodeError:
            msg = 'Invalid token header. Token string should not contain invalid characters.'
            raise exceptions.AuthenticationFailed(msg)

        channel = request.META.get('HTTP_X_CHANNEL')
        if channel:
            channel = json.loads(channel)
            logger.info('Channel {}'.format(channel))

        user, token, identifier = self.authenticate_credentials(token)

        if identifier:
            request.organization_id = identifier.get('organization_id')
            request.is_admin = identifier.get('is_admin')
            request.is_super_admin = identifier.get('is_super_admin')
            request.user_id = identifier.get('user_id')
        else:
            return (None)

        return (user, token)

    def authenticate_credentials(self, token):
        model = self.get_model()
        try:
            public_key = open('public_key.pem').read()
            payload = jwt.decode(token, public_key, algorithms=['RS256'])
            payload_data = payload.get('data')
            if not payload_data:
                logger.info('Token has no data')  
                raise exceptions.AuthenticationFailed('Invalid Token')

            token_data = json.loads(decrypt_token_data(payload_data))
            user_id = token_data.get('user_id')
            user = model.objects.get(id=user_id)
            
            if token_data.get('user_id'):
                user_id = token_data.get('user_id')
            if token_data.get('organization_id'):
                organization_id = token_data.get('organization_id')
            if token_data.get('organization_id') and token_data.get('is_super_admin'):
                organization_id = token_data.get('organization_id')
                is_super_admin = token_data.get('is_super_admin')
                return (user, token, {'user_id': user_id,'organization_id':organization_id,'is_super_admin':is_super_admin})
            elif token_data.get('organization_id') and token_data.get('is_admin'):
                is_admin = token_data.get('is_admin')
                organization_id = token_data.get('organization_id')
                return (user, token, {'user_id': user_id,'organization_id':organization_id,'is_admin':is_admin})
            elif token_data.get('organization_id'):
                organization_id = token_data.get('organization_id')
                return (user, token, {'user_id': user_id,'organization_id':organization_id})
            else:
                return (None, None, None)
        except LoginUser.DoesNotExist as le:
            logger.exception('Exception {}'.format(le.args))
            raise exceptions.AuthenticationFailed('You are not authorized to perform this action')

        except jwt.ExpiredSignatureError as se:
            logger.exception('Exception {}'.format(se.args))
            raise exceptions.AuthenticationFailed('Token is expired')

        except jwt.DecodeError or jwt.InvalidTokenError:
            logger.exception('JWT Error')
            raise exceptions.AuthenticationFailed('Invalid Token')

    def authenticate_header(self, request):
        return 'Token'

class IsAuthenticated(BasePermission):
    """
    Allows access only to authenticated users.
    """
    def has_permission(self, request, view):
        if request.user:
            if not isinstance(request.user, AnonymousUser):
                return True
        return False