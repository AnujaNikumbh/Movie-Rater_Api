from django.urls import path
from .views import RegisterView, login_view,User_logout,refresh_token_view,user
from rest_framework.routers import DefaultRouter

urlpatterns = [
    path('register', RegisterView.as_view()),
    #path('login', LoginView.as_view()),
    #path('user', UserView.as_view()),
    path('user',user,name='user'),
    path('logout', User_logout,name='logout'),
    path('login',login_view,name='login'),
    path('refresh_token',refresh_token_view),
    #path('logout', LogoutView.as_view()),

]