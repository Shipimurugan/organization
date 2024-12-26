import bcrypt
import json
import logging
import datetime
from authentication.models import LoginUser
from rest_framework import generics, status, permissions
from rest_framework.response import Response
import re
import jwt
from organization import settings
from cryptography.fernet import Fernet
from core.models import Organization

EMAIL_REGEX = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
logger = logging.getLogger(__name__)

def encrypt_token_data(data):
    cipher_suite = Fernet(settings.TOKEN_SECRET_KEY)
    encoded_data = json.dumps(data).encode()
    encrypted_data = cipher_suite.encrypt(encoded_data)
    return encrypted_data.decode()

class LoginUsersView(generics.GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = []
    def post(self, request):
        """
        
        URLs -  http://127.0.0.1:8000/auth/add/user/
        Sample Request
        {
            "user_name": "shipi_007",
            "password": "shipi@12345",
            "is_admin": true,
            "is_super_admin":false,
            "organization":"",
            "phone_number":987655433,
            "email_address":"shipi@gmail.com"
        }
        Sample Response
        {
            "status": "success",
            "message": "User created successfully"
        }
        """
        try:
            data = request.data
            user_name = data.get('user_name')
            password = data.get('password')
            email_address = data.get('email_address')
            phone_number = data.get('phone_number')
            is_admin = data.get('is_admin')
            is_super_admin = data.get('is_super_admin')
            organization = data.get('organization')
            if not (user_name and password and email_address and organization):
                return Response({'status': 'fail', 'message': 'please Enter the required field'}, status=status.HTTP_400_BAD_REQUEST)
            if not len([i for i in [is_admin,is_super_admin] if i==True]) == 1:
                return Response({'status': 'fail', 'message': 'please give the role correctely'}, status=status.HTTP_400_BAD_REQUEST)
            if LoginUser.objects.filter(user_name=user_name,organization=organization).first():
                return Response({'status': 'fail', 'message': 'User Name Already Exist'}, status=status.HTTP_400_BAD_REQUEST)
            if not re.search(EMAIL_REGEX, email_address):
                return Response({'status': 'fail', 'message': 'Please enter correct email'},
                                status=status.HTTP_400_BAD_REQUEST)
            if is_admin:
                if not organization:
                    return Response({'status': 'fail', 'message': 'Please enter organization id'},
                                status=status.HTTP_400_BAD_REQUEST)
            org_data = Organization.objects.filter(id=organization).first()
            if not org_data:
                    return Response({'status': 'fail', 'message': 'Organization id not exist'},
                                status=status.HTTP_400_BAD_REQUEST)
            hashed_passwd = bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt(10)).decode('utf8')
            role = None
            login_details = {
                'user_name':user_name,
                'password':hashed_passwd,
                'email_address':email_address,
                'is_admin': False,
                'is_super_admin':is_super_admin,
                'phone_number':phone_number,
                'organization':org_data,
                'role':role 
            }
            LoginUser.objects.create(**login_details)
            return Response({'status':'success','message':'User Created Successfully'},status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception('Exception {}'.format(e.args))
            return Response({'status': 'fail', 'message': 'Something went wrong. Please try again later.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

class LoginAuthenticationView(generics.GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = []
    def post(self, request):
        """
        URLs -  http://127.0.0.1:8000/auth/login/
        Sample Request
        {
            "user_name": "sethu_001",
            "password": "sethu@12345"
        }
        Sample Response
        {
            "status": "success",
            "message": "Login successful",
            "data": {
                "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoiZ0FBQUFBQmxBMUgtZVBNTjJOOEJIaE5FUTVYSndydFdqSE9QU1ZEMmxSSjZnb0RfcWR0dkpXZXdiQS1ENUNjQUhMVEZuSkgxWWRPNTV0RlJuQmV2VVA5aTFMNFJqUmR3WjExRFNNbjYxZmdrdEU0Wml1UkpreHBzNDhWMVRTbGxzaml6RGNLTWZnTU8iLCJleHAiOjE2OTQ4MDI4MTR9.A06taDQCq-mbJbhKemNExm1PKeNWxzbWZ1UCYhcX4Y1gKtuEb8lVJpTJ5GsDwogxXPlOp7DFqqcoqjpeZIRTBnID4QIwpmdM0vnei5FxSylT6WmLy7CXGPBh2o59qFf7T_ywuhsWOfA8NlSfir9Wf-jXvRYOvAq6YBKC-hmLgnxVHaVPFlU_bcslgKcbZ7_r7djDunjGbegitx2x51KLMVLI8n8oQNu7FzCg3ngTvJyUuUaaDCDu8ohvCuEvCE31mYe7N6ggX9vb56S13K4MdazNuk2OD9xyEiP2jfZ4PEOc9ZZy2AbaJwDJA8rPrEVbPnWNK7m2OtLCXGUS3fnJww",
                "is_admin": true,
                "employee_id": 1
            }
        }
        """
        try:
            data = request.data
            username = data.get('user_name')
            passwd = data.get('password')

            if not username or not passwd:
                return Response({'status': 'fail', 'message': 'Invalid username/password'}, status=status.HTTP_400_BAD_REQUEST)

            user = LoginUser.objects.filter(user_name=username).first()
            if not user:
                return Response({'status': 'fail', 'message': 'Username does not exist'},
                                status=status.HTTP_400_BAD_REQUEST)
            if not bcrypt.checkpw(bytes(passwd, 'utf-8'), bytes(user.password, 'utf-8')):
                return Response({'status': 'fail', 'message': 'Invalid username/password'},
                                status=status.HTTP_400_BAD_REQUEST)
            if user.is_logged_in:
                return Response({'status': 'fail', 'message': 'User Already Logged in'},
                                                status=status.HTTP_400_BAD_REQUEST)
            token_data = {}
            if user.is_admin:
                token_data['is_admin'] = True
            if user.is_super_admin:
                token_data['is_super_admin'] = True
            if user.organization:
                token_data['organization_id'] = user.organization_id
            token_data['user_id'] = user.id
            current_dt = datetime.datetime.now()
            expiry_time = current_dt + datetime.timedelta(minutes=1440)
            encrypted_data = encrypt_token_data(token_data)
            private_key = open('private_key.pem').read()
            token = jwt.encode({'data': encrypted_data, 'exp': expiry_time}, private_key, algorithm='RS256')
            response_data = {'token': token}
            if user.is_admin:
                response_data['is_admin'] = True
            if user.is_super_admin:
                response_data['is_super_admin'] = True
            if user.organization:
                response_data['organization'] = user.organization_id
            response_data['user_id'] = user.id
            user.is_logged_in = True
            user.save()
            return Response({'status': 'success', 'message': 'Login successful', 'data': response_data})
        except LoginUser.DoesNotExist as le:
            logger.exception('Exception {}'.format(le.args))
            return Response({'status': 'fail', 'message': 'Invalid username/password'},
                            status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.exception('Exception {}'.format(e.args))
            return Response({'status': 'fail', 'message': 'Something went wrong. Please try again later'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class LogoutView(generics.GenericAPIView):
    # permission_classes = (permissions.AllowAny,)
    # authentication_classes = []
    def post(self, request, *args, **kwargs):
        """
        """
        data = request.data
        if request.user.is_logged_in == True:
            request.user.is_logged_in = False
            request.user.save()
            return Response({'status': 'success', 'message': 'Logged out successfully'})
        return Response({'status': 'fail', 'message': 'Something went wrong. Please try again later'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)