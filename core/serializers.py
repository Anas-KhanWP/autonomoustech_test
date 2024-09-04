from rest_framework import serializers
from .models import App, Plan, Subscriptions
from django.contrib.auth.models import User

class PlanSerializer(serializers.ModelSerializer):
    """
    Serializer for the Plan model.

    Attributes:
    - model: The model class to serialize.
    - fields: The fields to include in the serialized representation.
    """
    class Meta:
        model = Plan
        fields = ['id', 'name', 'price']

class AppSerializer(serializers.ModelSerializer):
    """
    Serializer for the App model.

    Attributes:
    - model: The model class to serialize.
    - fields: The fields to include in the serialized representation.
    """
    class Meta:
        model = App
        fields = ['id', 'name', 'description', 'user']  # Include 'user' if necessary

class SubscriptionsSerializer(serializers.ModelSerializer):
    """
    Serializer for the Subscriptions model.

    Attributes:
    - plan: A PrimaryKeyRelatedField for the Plan model.
    - model: The model class to serialize.
    - fields: The fields to include in the serialized representation.
    """
    plan = serializers.PrimaryKeyRelatedField(queryset=Plan.objects.all())

    class Meta:
        model = Subscriptions
        fields = ['app', 'plan', 'active']

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model.

    Attributes:
    - model: The model class to serialize.
    - fields: The fields to include in the serialized representation.
    - extra_kwargs: Additional keyword arguments for field configuration.
    """
    class Meta:
        model = User
        fields = ['username', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        """
        Create a new user with the validated data.

        Parameters:
        - validated_data: The validated data to create the user with.

        Returns:
        - The newly created user.
        """
        user = User.objects.create_user(**validated_data)
        return user

class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login.

    Attributes:
    - username: A CharField for the username.
    - password: A CharField for the password, marked as write-only.
    """
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)  # Make password write-only