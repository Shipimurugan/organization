from rest_framework import generics, status, permissions
from rest_framework.response import Response
import logging
from core.models import Organization
from authentication.models import Role,LoginUser
from datetime import datetime
from django.db.models import F
import re
import bcrypt

EMAIL_REGEX = '^\\w+([\\.-]?\\w+)*@\\w+([\\.-]?\\w+)*(\\.\\w{2,3})+$'
logger = logging.getLogger(__name__)

class OrganizationDetail(generics.GenericAPIView):
    """
    URLs - core/add/organization/
    Sample request for edit 
    {   
        "id":1,
        "name":"pharmacy detail",
        "description":"it is a call indestry"
    }
    Sample request for create
    {   
        "name":"pharmacy detail",
        "description":"it is a call indestry"
    }
    """
    def post(self,request):
        try:
            data = request.data
            name = data.get('name')
            id = data.get('id')
            description = data.get('description')
            is_admin = request.is_admin
            is_super_admin = request.is_super_admin
            organization_id = request.organization_id
            if not name or not description :
                return Response({'status': 'fail', 'message': 'Invalid name/description'}, status=status.HTTP_400_BAD_REQUEST)
            if Organization.objects.filter(name=name).first() and not id:
                return Response({'status': 'fail', 'message': 'Organization Name Already Exist'}, status=status.HTTP_400_BAD_REQUEST)
            if not (is_admin or is_super_admin):
                return Response({'status': 'fail', 'message': 'You are not allow to create a organization'},
                                status=status.HTTP_400_BAD_REQUEST)
            if is_admin:
                if id and id != request.user.organization_id:
                    return Response({'status': 'fail', 'message': 'Admin can update only their own organization.'},
                                    status=status.HTTP_400_BAD_REQUEST)
            if id :
                update_organization = Organization.objects.get(id=id)
                update_organization.name = name
                update_organization.description = description
                update_organization.modified_by = request.user.user_name
                update_organization.save()
                return Response({'status':'sucess','message':"Organization updated succesfully"},status=status.HTTP_200_OK)
            else:
                Organization.objects.create(name=name,description=description,created_by=request.user.user_name)
                return Response({'status':'sucess','message':"Organization created succesfully"},status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception('Exception {}'.format(e.args))
            return Response({'status': 'fail', 'message': 'Something went wrong. Please try again later'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    def get(self,request):
        """
        URLS - core/add/organization/?name=cal
        """
        try:
            data = request.GET
            name = data.get('name')
            search_data = {}
            is_admin = request.is_admin
            is_super_admin = request.is_super_admin
            organization_id = request.organization_id
            if name:
                search_data['name__startswith'] = name
            organization_data = Organization.objects.filter(**search_data).values('id','name','description','created_date','modified_date')
            return Response({'status':'success','message':'Organization data','data':organization_data})
        except Organization.DoesNotExist as le:
            logger.exception('Exception {}'.format(le.args))
            return Response({'status': 'fail', 'message': 'Organization data not found'},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception('Exception {}'.format(e.args))
            return Response({'status': 'fail', 'message': 'Something went wrong. Please try again later'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def delete(self,request):
        """
        URLS - /core/add/organization/?id=3
        """
        try:
            data = request.GET
            id = data.get('id')
            is_admin = request.is_admin
            is_super_admin = request.is_super_admin
            organization_id = request.organization_id
            if not id:
                return Response({'status': 'fail', 'message': 'organization ID does not exist'}, status=status.HTTP_400_BAD_REQUEST)
            if not (is_admin or is_super_admin):
                return Response({'status': 'fail', 'message': 'You are not allow to delete a organization'},
                                status=status.HTTP_400_BAD_REQUEST)
            if is_admin and int(id) != request.user.organization_id:
                return Response({'status': 'fail', 'message': 'Admin can delete only their own organization.'},
                                status=status.HTTP_400_BAD_REQUEST)
            del_org = Organization.objects.get(id=id)
            del_org.is_active = False
            del_org.save()
            return Response({'status':'success','message':'Organization Deleted successfully'})
        except Exception as e:
            logger.exception('Exception {}'.format(e.args))
            return Response({'status': 'fail', 'message': 'Something went wrong. Please try again later'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class RoleManagement(generics.GenericAPIView):
    def post(self,request):
        """
        URLs - core/role/
        sample request for edit
        {   
            "id":1,
            "name":"manager",
            "description":"he will all process in companys",
            "organization":1
        }
        sample request for create
        {   
            "name":"manager",
            "description":"he will all process in companys",
            "organization":1
        }
        """
        try:
            data = request.data
            name = data.get('name')
            id = data.get('id')
            description = data.get('description')
            is_admin = request.is_admin
            is_super_admin = request.is_super_admin
            organization_id = request.organization_id
            organization = data.get('organization')
            print(is_super_admin,"?????????",is_admin,"organization_id",organization_id)
            if not name or not description or not organization:
                return Response({'status': 'fail', 'message': 'Invalid name/description/organization'}, status=status.HTTP_400_BAD_REQUEST)
            if Role.objects.filter(name=name,organization=organization).first() and not id:
                return Response({'status': 'fail', 'message': 'Role Already Exist in organization'}, status=status.HTTP_400_BAD_REQUEST)
            if not (is_admin or is_super_admin):
                return Response({'status': 'fail', 'message': 'You are not allow to create a organization'},
                                status=status.HTTP_400_BAD_REQUEST)
            if is_admin:
                if id and id != organization_id:
                    return Response({'status': 'fail', 'message': 'Admin can update only their own organization roles.'},
                                    status=status.HTTP_400_BAD_REQUEST)
            org_data = Organization.objects.filter(id=organization).first()
            if not org_data:
                return Response({'status': 'fail', 'message': 'Please give correct organization'},
                                status=status.HTTP_400_BAD_REQUEST)
            if id :
                update_role = Role.objects.get(id=id)
                update_role.name = name
                update_role.description = description
                update_role.modified_by = request.user.user_name
                update_role.organization = org_data
                update_role.save()
                return Response({'status':'sucess','message':"Role updated succesfully"},status=status.HTTP_200_OK)
            else:
                Role.objects.create(name=name,description=description,created_by=request.user.user_name,organization=org_data)
                return Response({'status':'sucess','message':"Role created succesfully"},status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception('Exception {}'.format(e.args))
            return Response({'status': 'fail', 'message': 'Something went wrong. Please try again later'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def get(self,request):
        """
        URLs - core/role/
        """
        try:
            data = request.GET
            name = data.get('name')
            is_super_admin = request.is_super_admin
            is_admin = request.is_admin
            organization_id = request.organization_id
            search_data = {}
            if name:
                search_data['name__startswith'] = name
            if not is_super_admin:
                search_data['organization'] = request.user.organization
            role_data = Role.objects.filter(is_active=True,**search_data).values('id','name','description','created_date','modified_date',organization_name=F('organization__name'))
            return Response({'status':'success','message':'Role data','data':role_data})
        except Role.DoesNotExist as le:
            logger.exception('Exception {}'.format(le.args))
            return Response({'status': 'fail', 'message': 'Role data not found.'},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception('Exception {}'.format(e.args))
            return Response({'status': 'fail', 'message': 'Something went wrong. Please try again later.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        """
        URLS - core/role/
        """
        try:
            data = request.GET
            id = data.get('id')
            is_admin = request.is_admin
            is_super_admin = request.is_super_admin
            organization_id = request.organization_id
            if not id:
                return Response({'status': 'fail', 'message': 'role ID does not exist'}, status=status.HTTP_400_BAD_REQUEST)
            if not (is_admin or is_super_admin):
                return Response({'status': 'fail', 'message': 'You are not allow to delete a role.'},
                                status=status.HTTP_400_BAD_REQUEST)
            del_org = Role.objects.get(id=id)
            if is_admin and del_org.organization != request.user.organization_id:
                return Response({'status': 'fail', 'message': 'Admin can delete only their own organization role.'},
                                status=status.HTTP_400_BAD_REQUEST)
            del_org.is_active = False
            del_org.save()
            return Response({'status':'success','message':'Organization Deleted successfully'})
        except Exception as e:
            logger.exception('Exception {}'.format(e.args))
            return Response({'status': 'fail', 'message': 'Something went wrong. Please try again later'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class UserManagement(generics.GenericAPIView):
    def post(self,request):
        """
        URLs - core/user/
        for edit
        {
            "id":1,
            "user_name": "shipi_007",
            "password": "shipi@12345",
            "is_admin": true,
            "is_super_admin":false,
            "organization":1,
            "role":"",
            "phone_number":987655433,
            "email_address":"shipi@gmail.com"
        }
        create
        {
            "user_name": "shipi_007",
            "password": "shipi@12345",
            "is_admin": true,
            "is_super_admin":false,
            "organization":1,
            "role":"",
            "phone_number":987655433,
            "email_address":"shipi@gmail.com"
        }
        """
        try:
            data = request.data
            user_name = data.get('user_name')
            id = data.get('id')
            password = data.get('password')
            email_address = data.get('email_address')
            phone_number = data.get('phone_number')
            organization = data.get('organization')
            role = data.get('role')
            admin = data.get('admin')
            super_admin = data.get('super_admin')
            is_admin = request.is_admin
            is_super_admin = request.is_super_admin
            organization_id = request.organization_id
            if not (user_name and password and email_address and organization) and not id:
                return Response({'status': 'fail', 'message': 'please Enter the required field'}, status=status.HTTP_400_BAD_REQUEST)
            if not (user_name and email_address and organization) and id:
                return Response({'status': 'fail', 'message': 'please Enter the required field'}, status=status.HTTP_400_BAD_REQUEST)
            is_manager = False
            if request.user.role:
                if request.user.role.name == "manager":
                    is_manager = True
            log_data = LoginUser.objects.filter(user_name=user_name,organization=organization).first()
            if not id and log_data:
                    return Response({'status': 'fail', 'message': 'User name Already Exist in organization'}, status=status.HTTP_400_BAD_REQUEST) 
            if not re.search(EMAIL_REGEX, email_address):
                return Response({'status': 'fail', 'message': 'Please enter correct email'},
                                status=status.HTTP_400_BAD_REQUEST)
            if not (is_admin or is_super_admin or is_manager):
                return Response({'status': 'fail', 'message': 'You are not allow to delete a role.'},
                                status=status.HTTP_400_BAD_REQUEST)
            if is_admin or is_super_admin:
                if not organization:
                    return Response({'status': 'fail', 'message': 'Please enter organization id'},
                                status=status.HTTP_400_BAD_REQUEST)
            org_data = Organization.objects.filter(id=organization).first()
            if not org_data:
                    return Response({'status': 'fail', 'message': 'Organization id not exist'},
                                status=status.HTTP_400_BAD_REQUEST)
            if role:
                role_data = Role.objects.filter(id=role).first()
                manager = True if role_data.name == "manager" else False
            if is_manager and super_admin:
                return Response({'status': 'fail', 'message': 'Manager should not assign super-admin role'},
                                    status=status.HTTP_400_BAD_REQUEST)
            if is_admin :
                if id and org_data.id != request.user.organization_id:
                    return Response({'status': 'fail', 'message': 'Admin can update only their own organization roles.'},
                                    status=status.HTTP_400_BAD_REQUEST)
            if role:
                role_check = Role.objects.filter(id=role,organization=organization).first()
                if not role_check:
                    return Response({'status': 'fail', 'message': 'Role not exist in the organization'},
                                    status=status.HTTP_400_BAD_REQUEST)
            if id :
                update_login = LoginUser.objects.get(id=id)
                if password:
                    hashed_passwd = bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt(10)).decode('utf8')
                    update_login.password = hashed_passwd
                update_login.user_name = user_name
                update_login.email_address = email_address
                update_login.is_super_admin = super_admin
                update_login.phone_number = phone_number
                update_login.organization = org_data
                update_login.is_admin = admin
                update_login.role = role_data if role else None
                update_login.save()
                return Response({'status':'success','message':'User updated Successfully'},status=status.HTTP_200_OK)
            else:
                hashed_passwd = bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt(10)).decode('utf8')
                login_details = {
                'user_name':user_name,
                'password':hashed_passwd,
                'email_address':email_address,
                'is_admin': admin,
                'is_super_admin':super_admin,
                'phone_number':phone_number,
                'organization':org_data,
                'role':role_data if role else None
                }
                LoginUser.objects.create(**login_details)
                return Response({'status':'success','message':'User created Successfully'},status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception('Exception {}'.format(e.args))
            return Response({'status': 'fail', 'message': 'Something went wrong. Please try again later.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self,request):
        """
        URLs - core/user/
        """
        try:
            data = request.GET
            name = data.get('name')
            search_data = {}
            is_super_admin = request.is_super_admin
            is_admin = request.is_admin
            organization_id = request.organization_id
            if name:
                search_data['user_name__startswith'] = name
            is_manager = False
            if request.user.role:
                if request.user.role.name == "manager":
                    is_manager = True
            if not is_super_admin:
                search_data['organization'] = organization_id
            if not (is_admin or is_super_admin or is_manager):
                search_data['id'] = request.user.id
            user_data = LoginUser.objects.filter(is_active=True,**search_data).values('id','user_name','email_address','phone_number','organization__name','role__name','created_date','modified_date')
            return Response({'status':'success','message':'LoginUser data','data':user_data})
        except LoginUser.DoesNotExist as le:
            logger.exception('Exception {}'.format(le.args))
            return Response({'status': 'fail', 'message': 'LoginUser data not found.'},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception('Exception {}'.format(e.args))
            return Response({'status': 'fail', 'message': 'Something went wrong. Please try again later.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        """
        URLs - core/user/
        """
        try:
            data = request.GET
            id = data.get('id')
            is_admin = request.is_admin
            is_super_admin = request.is_super_admin
            organization_id = request.organization_id
            manager = False
            if request.user.role:
                if request.user.role.name == "manager":
                    manager = True
            if not id:
                return Response({'status': 'fail', 'message': 'User ID does not exist'}, status=status.HTTP_400_BAD_REQUEST)
            if not (is_admin or is_super_admin or manager):
                return Response({'status': 'fail', 'message': 'You are not allow to delete a role.'},
                                status=status.HTTP_400_BAD_REQUEST)
            del_org = LoginUser.objects.filter(id=id).first()
            if not del_org:
                return Response({'status': 'fail', 'message': 'Login user id not exist'},
                                status=status.HTTP_400_BAD_REQUEST)
            if (is_admin or manager) and del_org.organization_id != organization_id:
                return Response({'status': 'fail', 'message': 'Admin/manager can delete only their own organization role.'},
                                status=status.HTTP_400_BAD_REQUEST)
            del_org.is_active = False
            del_org.save()
            return Response({'status':'success','message':'LoginUser Deleted successfully'})
        except Exception as e:
            logger.exception('Exception {}'.format(e.args))
            return Response({'status': 'fail', 'message': 'Something went wrong. Please try again later'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
class AssignRole(generics.GenericAPIView):
    def post(self,request):
        """
        URLs -  http://127.0.0.1:8000/core/assign/
        sample request 
        {
            "user_id":8,
            "admin":false,
            "super_admin":false,
            "role_name":2
        }
        """
        try:
            data = request.data
            is_admin = request.is_admin
            is_super_admin = request.is_super_admin
            role_name = data.get('role_name')
            user_id = data.get('user_id')
            admin = data.get('admin')
            super_admin = data.get('super_admin')
            organization_id = request.organization_id
            print(">>>>>>>>>>>>>>>>>>>>>>>",organization_id)
            manager = False
            if not user_id:
                return Response({'status': 'fail', 'message': 'please Enter the user_id'}, status=status.HTTP_400_BAD_REQUEST)
            if request.user.role:
                if request.user.role.name == "manager":
                    manager = True
            if not (is_admin or is_super_admin or manager):
                return Response({'status': 'fail', 'message': 'You are not allow to delete a role.'},
                                status=status.HTTP_400_BAD_REQUEST)
            if super_admin and manager:
                return Response({'status': 'fail', 'message': 'You are not allow to assign super_admin.'},
                                status=status.HTTP_400_BAD_REQUEST)
            search_data = {}
            if not is_super_admin:
                search_data['organization'] = organization_id
            user_data = LoginUser.objects.filter(id=user_id,**search_data).first()
            if not user_data:
                return Response({'status': 'fail', 'message': 'user Data not found ,please check assigning out your organization'},
                                status=status.HTTP_400_BAD_REQUEST)
            if role_name:
                role_check = Role.objects.filter(id=role_name,organization=user_data.organization).first()
                if not role_check:
                    return Response({'status': 'fail', 'message': 'Role not exist in the organization'},
                                    status=status.HTTP_400_BAD_REQUEST)
            user_data.role = role_check if role_name else None
            user_data.is_super_admin = super_admin
            user_data.is_admin = admin
            user_data.save()
            return Response({'status':'success','message':'Role assigned successfully'})
        except Exception as e:
            logger.exception('Exception {}'.format(e.args))
            return Response({'status': 'fail', 'message': 'Something went wrong. Please try again later'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

