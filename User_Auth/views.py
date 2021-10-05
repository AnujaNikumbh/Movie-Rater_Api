from django.shortcuts import render, HttpResponse
from rest_framework.views import APIView
from .serializers import UserSerializer
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
import datetime,jwt
from django.contrib.auth.models import User




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
        
class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = Response()
        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }

        return Response({
            'user_name': user.username,
            'email': user.email,
            'token': response.data,
            'message': 'login successfully'
        })


class UserView(APIView):

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user = User.objects.filter(id=payload['id']).first()

        serializer = UserSerializer(user)

        return Response(serializer.data)

class LogoutView(APIView):
    def post(self, request):
        
        response = Response()
        #print(response.cookies.get('jwt'))
        response.delete_cookie('jwt')

        response.data = {
            'message': 'success'
        }
        return response

    

