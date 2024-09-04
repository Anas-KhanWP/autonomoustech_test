from rest_framework import serializers
from .models import App, Plan, Subscriptions
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.utils.translation import gettext_lazy as _

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
    
class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for password reset request.

    Attributes:
    - username: A CharField for the username.

    Methods:
    - validate_username: Validates the username field. Raises ValidationError if the user does not exist.
    """
    username = serializers.CharField()

    def validate_username(self, value):
        """
        Validates the username field. Raises ValidationError if the user does not exist.

        Parameters:
        - value (str): The username to validate.

        Returns:
        - value (str): The validated username.

        Raises:
        - serializers.ValidationError: If the user does not exist.
        """
        try:
            user = User.objects.get(username=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found.")
        return value


class SetNewPasswordSerializer(serializers.Serializer):
    """
    Serializer for setting a new password.

    Attributes:
    - new_password1: A CharField for the new password, marked as write-only.
    - new_password2: A CharField for confirming the new password, marked as write-only.

    Methods:
    - validate: Validates the new password fields. Raises ValidationError if the passwords do not match.
    """
    new_password1 = serializers.CharField(write_only=True)
    new_password2 = serializers.CharField(write_only=True)

    def validate(self, data):
        """
        Validates the new password fields. Raises ValidationError if the passwords do not match.

        Parameters:
        - data (dict): The data to validate.

        Returns:
        - data (dict): The validated data.

        Raises:
        - serializers.ValidationError: If the passwords do not match.
        """
        if data['new_password1'] != data['new_password2']:
            raise serializers.ValidationError("The two password fields didn't match.")
        return data
