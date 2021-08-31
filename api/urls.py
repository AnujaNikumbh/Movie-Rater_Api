from django.contrib import admin
from django.urls import path
from rest_framework import routers
from django.conf.urls import include
from .views import MovieViewset,RatingViewset

router =routers.DefaultRouter()
router.register('movies',MovieViewset)
router.register('ratings',RatingViewset)

urlpatterns = [
    path('', include(router.urls)),
]
