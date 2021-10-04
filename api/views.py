from django.shortcuts import render
from  rest_framework import viewsets,status
from .models import Movie,Rating
from rest_framework.decorators import action
from django.contrib.auth.models import User
from rest_framework.response import Response
from .serializers import MovieSerializers,RatingSerializers ,UserSerializer
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
# Create your views here.


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
class MovieViewset(viewsets.ModelViewSet):
    queryset = Movie.objects.all()
    serializer_class = MovieSerializers
    authentication_classes =(TokenAuthentication,)
    permission_classes = (IsAuthenticated,)     # permission class

    @action(detail='True', methods=['POST'])
    def rate_movie(self,request,pk=None):
        if 'stars' in request.data:

            movie = Movie.objects.get(id=pk)
            stars = request.data['stars']
            user =  request.user



            try:
                rating = Rating.objects.get(user=user.id,movie=movie.id)
                rating.stars = stars
                rating.save()
                serializer = RatingSerializers(rating,many=False)
                response = {'message': 'Rating updated','result':serializer.data}
                return Response(response, status=status.HTTP_200_OK)
            except:
                rating=Rating.objects.create(user=user, movie=movie,stars=stars)
                serializer = RatingSerializers(rating, many=False)
                response = {'message': 'Rating created', 'result': serializer.data}
                return Response(response, status=status.HTTP_200_OK)

        else:
            response = {'message': 'you need to provide stars'}
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

class RatingViewset(viewsets.ModelViewSet):
    queryset = Rating.objects.all()
    serializer_class = RatingSerializers
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)     # permission class


     # Override update method
    def update(self, request, *args, **kwargs):
        response = {'message': 'You cant update rating like that'}
        return Response(response,  status = status.HTTP_400_BAD_REQUEST)

    # Override create method
    def create(self, request, *args, **kwargs):
        response = {'message': 'You cant create rating like that'}
        return Response(response,  status = status.HTTP_400_BAD_REQUEST)    
  



