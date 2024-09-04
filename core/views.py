from rest_framework import generics
from .models import App, Plan, Subscriptions
from .serializers import AppSerializer, PlanSerializer, SubscriptionsSerializer, UserSerializer, LoginSerializer
from rest_framework import generics
from rest_framework.permissions import AllowAny
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

# App Views
class AppListCreateView(generics.ListCreateAPIView):
    """
    This view provides a list of all Apps and allows creating new Apps.

    Attributes:
    queryset: The queryset of all App objects.
    serializer_class: The serializer class to use for serializing App objects.
    """
    queryset = App.objects.all()
    serializer_class = AppSerializer


class AppRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """
    This view provides detailed information about a specific App, allows updating it, and allows deleting it.

    Attributes:
    queryset: The queryset of all App objects.
    serializer_class: The serializer class to use for serializing App objects.
    """
    queryset = App.objects.all()
    serializer_class = AppSerializer


# Plan Views
class PlanListView(generics.ListAPIView):
    """
    This view provides a list of all Plans.

    Attributes:
    queryset: The queryset of all Plan objects.
    serializer_class: The serializer class to use for serializing Plan objects.
    """
    queryset = Plan.objects.all()
    serializer_class = PlanSerializer


class SubscriptionCreateView(generics.CreateAPIView):
    """
    This view allows creating new Subscriptions.

    Attributes:
    queryset: The queryset of all Subscription objects.
    serializer_class: The serializer class to use for serializing Subscription objects.
    """
    queryset = Subscriptions.objects.all()
    serializer_class = SubscriptionsSerializer


# Subscription Views
class SubscriptionRetrieveUpdateView(generics.RetrieveUpdateAPIView):
    """
    This view provides detailed information about a specific Subscription, allows updating it.

    Attributes:
    queryset: The queryset of all Subscription objects.
    serializer_class: The serializer class to use for serializing Subscription objects.

    Methods:
    get_object: Overrides the default get_object method to use the 'pk' from URL kwargs.
    """
    queryset = Subscriptions.objects.all()
    serializer_class = SubscriptionsSerializer

    def get_object(self):
        # Override get_object to use the 'pk' from URL kwargs
        pk = self.kwargs.get('pk')  # Change this to 'app_id' if you use that in the URL
        return Subscriptions.objects.get(pk=pk)

class RegisterView(generics.CreateAPIView):
    """
    A view for registering new users.

    Attributes:
    queryset: The queryset of all User objects.
    serializer_class: The serializer class to use for serializing User objects.
    permission_classes: The permission classes to apply to this view. In this case, AllowAny allows unauthenticated users to access this view.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]


class LoginAPIView(APIView):
    """
    A view for logging in users.

    Attributes:
    serializer_class: The serializer class to use for serializing login data.
    authentication_classes: The authentication classes to apply to this view. In this case, TokenAuthentication is used to authenticate users using tokens.
    """
    serializer_class = LoginSerializer
    authentication_classes = [TokenAuthentication]

    def post(self, request):
        """
        Handles POST requests for user login.

        Parameters:
        request: The incoming request object containing the user's login credentials.

        Returns:
        A Response object containing the user's token if the login is successful, or an error message if the login fails.
        """
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(username=username, password=password)

            if user is not None:
                # Get or create a token for the user
                token, created = Token.objects.get_or_create(user=user)
                return Response({'token': token.key, 'Success': 'Login Successful'}, status=status.HTTP_200_OK)
            else:
                return Response({'Message': 'Invalid Username or Password'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    """
    A view for logging out users.
    """
    def post(self, request):
        """
        Handles POST requests for user logout.

        Parameters:
        request: The incoming request object.

        Returns:
        A Response object with a status code of 204 (No Content) indicating successful logout.
        """
        logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)