from django.shortcuts import render, redirect, get_object_or_404
from rest_framework import generics
from .models import App, Plan, Subscriptions
from .serializers import AppSerializer, PlanSerializer, SubscriptionsSerializer, UserSerializer, LoginSerializer, PasswordResetRequestSerializer, SetNewPasswordSerializer
from rest_framework import generics
from rest_framework.permissions import AllowAny
from django.views import View
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
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from .forms import AppForm
from pprint import pprint
import requests

# App Views
class AppListCreateHTMLView(View):
    """
    A view for listing all Apps and creating new Apps.
    """

    def get(self, request):
        """
        Renders the list of all Apps.
        """
        apps = App.objects.all()
        return render(request, 'app/app_list.html', {'apps': apps})

    def post(self, request):
        """
        Handles form submission for creating a new App via API.
        """
        form = AppForm(request.POST)
        if form.is_valid():
            # Prepare data for API request, excluding 'user'
            data = {
                'name': form.cleaned_data['name'],
                'description': form.cleaned_data['description'],
                'user': request.user.pk,  # Assuming user is logged in
            }
            pprint(data)
            response = requests.post('http://127.0.0.1:8000/api/auth/apps/', json=data)
            
            if response.status_code == 201:
                print("valid form")
                # Success - redirect to the list view
                return redirect('app/app_list.html')
            else:
                # API error - render with error message
                error = response.json().get('detail', 'Error occurred')
                return render(request, 'app/app_list.html', {'form': form, 'error': error})

        return render(request, 'app/app_list.html', {'form': form, 'error': 'Form is not valid.'})

class AppDetailHTMLView(View):
    """
    A view for viewing, updating, and deleting a specific App.
    """

    def get(self, request, pk):
        """
        Renders the details of a specific App.
        """
        app = get_object_or_404(App, pk=pk)
        return render(request, 'app/app_detail.html', {'app': app})

    def post(self, request, pk):
        """
        Handles form submission for updating or deleting an App.
        """
        app = get_object_or_404(App, pk=pk)
        if 'update' in request.POST:
            form = AppForm(request.POST, instance=app)
            if form.is_valid():
                form.save()
                return redirect('app/app_list')
        elif 'delete' in request.POST:
            app.delete()
            return redirect('app/app_list')
        return render(request, 'app/app_detail.html', {'app': app, 'form': AppForm(instance=app)})


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

class RegisterHTMLView(View):
    """
    A view for rendering the registration page and handling registration form submissions.
    """

    def get(self, request):
        """
        Renders the registration page.
        """
        return render(request, 'registration/register.html')

    def post(self, request):
        """
        Handles registration form submission and interacts with the API endpoint.
        """
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        
        # Call the API endpoint for registration
        response = self.register_api(username, password, email)
        
        if response.status_code == 201:  # 201 Created
            return redirect('api/login')  # Redirect to login page after successful registration
        else:
            return render(request, 'registration/register.html', {'error': response.json().get('non_field_errors')})

    def register_api(self, username, password, email):
        """
        Calls the API endpoint to register the user.
        """
        api_url = 'http://127.0.0.1:8000/api/auth/register/'
        response = requests.post(api_url, json={'username': username, 'password': password, 'email': email})
        return response


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

class LoginView(View):
    """
    A view for rendering the login page and handling login form submissions.
    """

    def get(self, request):
        """
        Renders the login page.
        """
        return render(request, 'registration/login.html')

    def post(self, request):
        """
        Handles login form submission and interacts with the API endpoint.
        """
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # Call the API endpoint for login
        response = self.login_api(username, password)
        
        if response.status_code == 200:
            token = response.json().get('token')
            request.session['token'] = token  # Save token in session
            return redirect('/api/apps/')
        else:
            return render(request, 'login.html', {'error': response.json().get('Message')})

    def login_api(self, username, password):
        """
        Calls the API endpoint to authenticate the user.
        """
        import requests
        
        api_url = 'http://127.0.0.1:8000/api/auth/login/'
        response = requests.post(api_url, json={'username': username, 'password': password})
        return response

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
    
class PasswordResetRequestView(APIView):
    """
    A view for requesting a password reset email.

    Attributes:
    - serializer_class: The serializer class to use for validating the username.

    Methods:
    - post: Handles POST requests for password reset requests.
    """

    def post(self, request):
        """
        Handles POST requests for password reset requests.

        Parameters:
        - request: The incoming request object containing the username.

        Returns:
        - A Response object containing the user's ID and token if the username is valid.
        - A Response object containing the serializer errors if the username is invalid.
        """
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            user = User.objects.get(username=username)
            
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            
            return Response({"uid": uid, "token": token}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordView(APIView):
    """
    A view for setting a new password after a password reset request.

    Attributes:
    - permission_classes: The permission classes to apply to this view. In this case, AllowAny allows unauthenticated users to access this view.
    - serializer_class: The serializer class to use for validating the new password.

    Methods:
    - post: Handles POST requests for setting a new password.
    """
    permission_classes = [AllowAny]
    serializer_class = SetNewPasswordSerializer

    def post(self, request, uidb64, token):
        """
        Handles POST requests for setting a new password.

        Parameters:
        - request: The incoming request object containing the new password.
        - uidb64: The base64-encoded user ID.
        - token: The password reset token.

        Returns:
        - A Response object indicating successful password reset if the token is valid.
        - A Response object containing an error message if the token is invalid.
        - A Response object containing the serializer errors if the new password is invalid.
        """
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                uid = urlsafe_base64_decode(uidb64).decode()
                user = User.objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                return Response({"Error": "Invalid token or user ID."}, status=status.HTTP_400_BAD_REQUEST)

            if user is not None and default_token_generator.check_token(user, token):
                user.set_password(serializer.validated_data['new_password1'])
                user.save()
                return Response({"Success": "Password has been reset successfully."}, status=status.HTTP_200_OK)
            else:
                return Response({"Error": "Invalid token or user ID."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)