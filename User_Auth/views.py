
from re import A
from django.shortcuts import render, HttpResponse
from rest_framework.views import APIView
from .serializers import UserSerializer
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from jwt import encode,decode, ExpiredSignatureError
import datetime,jwt
from django.contrib.auth.models import User
from django.http import HttpRequest
from django.http import HttpResponse
from rest_framework import viewsets
from rest_framework.decorators import api_view
from django.contrib.auth import get_user_model, logout
from rest_framework import exceptions
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.decorators import api_view , permission_classes
from django.views.decorators.csrf import ensure_csrf_cookie
from .auth import generate_access_token,generate_refresh_token
from django.views.decorators.csrf import csrf_protect
from django.conf import settings

# from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status

@permission_classes([AllowAny])
class RegisterView(APIView):
    
    def post(self, request):
        
        serializer = UserSerializer(data=request.data)
        #print(request.data['password'],request.data['confirm_password'])
        
        # if password and confirm password is blank
        if request.data.get('password') is None or request.data.get('confirm_password') is None:
            return Response({
            'message': 'Please enter a password and confirm it.'
        })

        # if password and confirm password is not same
        if request.data.get('password') != request.data.get('confirm_password'):
            return Response({
            'message': 'Those passwords does not match..'
        })

        serializer.is_valid(raise_exception=True)   
        serializer.save()

        return Response({
            'message': 'Registered successfully'
        })
        
@api_view(['POST'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def login_view(request):
    User = get_user_model()
    username = request.data.get('username')
    password = request.data.get('password')
    response = Response()
    if (username is None) or (password is None):
        raise exceptions.AuthenticationFailed(
            'username and password required')

    user = User.objects.filter(username=username).first()
    if(user is None):
        raise exceptions.AuthenticationFailed('user not found')
    if (not user.check_password(password)):
        raise exceptions.AuthenticationFailed('wrong password')

    serialized_user = UserSerializer(user).data

    access_token = generate_access_token(user)
    refresh_token = generate_refresh_token(user)

    response.set_cookie(key='refreshtoken', value=refresh_token, httponly=True)
    response.data = {
        'access_token': access_token,
        'user': serialized_user,
    }

    return response

@permission_classes([IsAuthenticated])
@api_view(['GET'])        
def user(request):
    refresh_token = request.COOKIES.get('refreshtoken')
    if refresh_token is None:
            raise exceptions.AuthenticationFailed(
            'Authentication credentials were not provided.')
    else:
        user = request.user
        serialized_user = UserSerializer(user).data
        return Response({'user':serialized_user} )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def User_logout(request):
    try:
        
        response = Response()
        response.delete_cookie('refreshtoken')
        response.delete_cookie('csrftoken')
        logout(request)

        response.data={
            'message':'User logged out successfully'
        }
        return response
    except jwt.ExpiredSignatureError:
        raise exceptions.AuthenticationFailed('please login again.')

'''class LogoutView(APIView):
    def post(self, request):        
         response = Response()
         print(response.cookies.get('jwt'))
         response.delete_cookie('jwt') 
         #if cokkie is none unautherize user and if cookie is available then logout

         response.data = {
              'message': 'success'
         }
         return response''' 


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_protect
def refresh_token_view(request):
    User = get_user_model()
    refresh_token = request.COOKIES.get('refreshtoken')
    if refresh_token is None:
        raise exceptions.AuthenticationFailed(
            'Authentication credentials were not provided.')
    try:
        payload = jwt.decode(
            refresh_token, settings.REFRESH_TOKEN_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise exceptions.AuthenticationFailed(
            'expired refresh token, please login again.')

    user = User.objects.filter(id=payload.get('user_id')).first()
    if user is None:
        raise exceptions.AuthenticationFailed('User not found')

    if not user.is_active:
        raise exceptions.AuthenticationFailed('user is inactive')


    access_token = generate_access_token(user)
    return Response({'access_token': access_token})
 
