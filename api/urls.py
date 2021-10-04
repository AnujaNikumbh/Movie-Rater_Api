from django.urls import path, include
from rest_framework import routers
from . views import MovieViewset,RatingViewset ,UserViewSet
router = routers.DefaultRouter()
# Register the viewsets
router.register('movies', MovieViewset)
router.register('ratings',RatingViewset)
router.register('users', UserViewSet)

urlpatterns = [
    path('', include(router.urls)),
]