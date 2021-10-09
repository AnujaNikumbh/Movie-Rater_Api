from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User

#from django.contrib.auth.models import get_user_model
from re import search


class UserSerializer(serializers.ModelSerializer):
    '''email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )'''

    # set custom and Unique validation to username field
    username = serializers.CharField(validators=[
        UniqueValidator(queryset=User.objects.all())
    ])
    
    def validate_username(self, value):
        if len(value) < 9 or len(value) > 16:
            raise ValidationError("Username must be 10 to 15 letters")
        if search('[0-9]', value) is None:
            raise ValidationError("Make sure your user name has a number in it")
        if search('[a-z,A-Z]', value) is None:
            raise ValidationError("Make sure your user name has a letter in it")

        return value

    # Validation for the password
    #password = serializers.CharField()
    
    def validate(self, data):
        # Validation for the password
        SpecialSym = ['$', '@', '#']
        if len(data.get('password')) < 6:
            raise ValidationError('the length of password should be at least 6 char long')

        if len(data.get('password')) > 21:
            raise ValidationError('the length of password should be not be greater than 20')

        if not any(char.isdigit() for char in data.get('password')):
            raise ValidationError('the password should have at least one numeral')

        if not any(char.isupper() for char in data.get('password')):
            raise ValidationError('the password should have at least one uppercase letter')

        if not any(char.islower() for char in data.get('password')):
            raise ValidationError('the password should have at least one lowercase letter')

        if not any(char in SpecialSym for char in data.get('password')):
            raise ValidationError('the password should have at least one of the symbols $@#')
          
    
        return data
    class Meta:
        #model = User
        model= get_user_model()
        
        fields = ['id', 'first_name', 'last_name', 'username', 'email', 'password'
                ]
        extra_kwargs = {   #hide password
            'password': {'write_only': True}
            #'confirm_password': {'write_only': True}
        }

    # create method for the hide the password
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        #pass
        if password is not None:
            instance.set_password(password)
        instance.save()  #save password
        return instance

        

