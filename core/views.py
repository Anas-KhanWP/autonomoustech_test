from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic import ListView
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
from .forms import AppForm, SubscriptionForm, PasswordResetRequestForm, SetNewPasswordForm
from pprint import pprint
from django.urls import reverse, reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin
from django.conf import settings
from requests.exceptions import RequestException
import requests, json

# App Views

class AppListCreateHTMLView(LoginRequiredMixin, View):
    """
    A view for listing all Apps and creating new Apps.
    """

    def get(self, request):
        """
        Renders the list of all Apps and initializes the form.
        """
        apps = App.objects.all()
        form = AppForm()  # Initialize an empty form
        return render(request, 'app/app_list.html', {'apps': apps, 'form': form})

    def post(self, request):
        """
        Handles form submission for creating a new App via API.
        """
        form = AppForm(request.POST)
        if form.is_valid():
            # Prepare data for API request, including 'user'
            data = {
                'name': form.cleaned_data['name'],
                'description': form.cleaned_data['description'],
                'user': request.user.pk,  # Assuming user is logged in
            }
            pprint(data)

            # Retrieve token from session
            token = request.session.get('token')
            headers = {'Authorization': f'Token {token}'}

            try:
                response = requests.post(f'{settings.API_BASE_URL}/apps/', json=data, headers=headers)
                if response.status_code == 201:
                    # Success - redirect to the list view
                    return redirect('app-list-create-view')
                else:
                    # API error - render with error message
                    error = response.json().get('detail', 'An error occurred while creating the app.')
            except requests.exceptions.RequestException as e:
                error = f'API request failed: {e}'
        else:
            error = 'Form is not valid.'

        # Render the form again with the error message
        apps = App.objects.all()
        return render(request, 'app/app_list.html', {'apps': apps, 'form': form, 'error': error})



class AppDetailHTMLView(LoginRequiredMixin, View):
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
                return redirect('app-list-create-view')
        elif 'delete' in request.POST:
            app.delete()
            return redirect('app-list-create-view')
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
    permission_classes = [IsAuthenticated]


class AppRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """
    This view provides detailed information about a specific App, allows updating it, and allows deleting it.

    Attributes:
    queryset: The queryset of all App objects.
    serializer_class: The serializer class to use for serializing App objects.
    """
    queryset = App.objects.all()
    serializer_class = AppSerializer
    permission_classes = [IsAuthenticated]

class PlanListHTMLView(LoginRequiredMixin, View):
    """
    A view to render a list of plans by calling the REST API.
    """
    template_name = 'plan/plan_list.html'
    
    def get(self, request, *args, **kwargs):
        token = request.session.get('token')  # Retrieve the token from the session
        headers = {'Authorization': f'Token {token}'}  # Include the token in the headers

        try:
            # Call the REST API to get the list of plans with the authentication token
            response = requests.get(f"{settings.API_BASE_URL}/plans/", headers=headers)
            response.raise_for_status()  # Raise an exception for HTTP errors
            plans = response.json()
        except RequestException as e:
            # Handle request errors
            plans = []
            print(f"Error fetching plans: {e}")

        return render(request, self.template_name, {'plans': plans})


# Plan Views
class PlanListView(generics.ListAPIView):
    """
    This view provides a list of all Plans.

    Attributes:
    queryset: The queryset of all Plan objects.
    serializer_class: The serializer class to use for serializing Plan objects.
    """
    queryset = Plan.objects.all()
    print(queryset)
    serializer_class = PlanSerializer
    permission_classes = [IsAuthenticated]


class SubscriptionCreateView(generics.CreateAPIView):
    """
    This view allows creating new Subscriptions.

    Attributes:
    queryset: The queryset of all Subscription objects.
    serializer_class: The serializer class to use for serializing Subscription objects.
    """
    queryset = Subscriptions.objects.all()
    serializer_class = SubscriptionsSerializer
    permission_classes = [IsAuthenticated]

class SubscriptionDetailView(LoginRequiredMixin, View):
    """
    A view to retrieve and update subscription details.
    """

    def get(self, request, pk):
        # Retrieve the subscription object based on primary key
        subscription = get_object_or_404(Subscriptions, pk=pk)
        form = SubscriptionForm(instance=subscription)
        return render(request, 'subscriptions/subscription_detail.html', {
            'form': form,
            'subscription': subscription
        })

    def post(self, request, pk):
        # Retrieve the subscription object based on primary key
        subscription = get_object_or_404(Subscriptions, pk=pk)
        form = SubscriptionForm(request.POST, instance=subscription)

        if form.is_valid():
            form.save()
            return redirect('subscription-detail-view', pk=pk)

        return render(request, 'subscriptions/subscription_detail.html', {
            'form': form,
            'subscription': subscription
        })

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
    permission_classes = [IsAuthenticated]

    def get_object(self):
        # Override get_object to use the 'pk' from URL kwargs
        pk = self.kwargs.get('pk')
        return Subscriptions.objects.get(pk=pk)
    
class SubscriptionListView(LoginRequiredMixin, ListView):
    """
    This view displays a list of all Subscriptions.
    """
    model = Subscriptions
    template_name = 'subscriptions/subscription_list.html'
    context_object_name = 'subscriptions'

class SubscriptionListAPIView(generics.ListAPIView):
    """
    This view provides a list of all Subscriptions.
    """
    queryset = Subscriptions.objects.all()
    serializer_class = SubscriptionsSerializer
    permission_classes = [IsAuthenticated]

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
            return redirect('login-view')  # Redirect to login page after successful registration
        else:
            return render(request, 'registration/register.html', {'error': response.json().get('non_field_errors')})

    def register_api(self, username, password, email):
        """
        Calls the API endpoint to register the user.
        """
        api_url = f'{settings.API_BASE_URL}/register/'
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
        
        # Call the API to authenticate the user
        response = self.login_api(username, password)
        
        if response.status_code == 200:
            try:
                data = response.json()
                token = data.get('token')
                request.session['token'] = token  # Store the token in the session

                # Authenticate the user locally within Django
                user = authenticate(username=username, password=password)

                if user is not None:
                    # Log the user in
                    login(request, user)
                    return redirect('app-list-create-view')  # Redirect to the app list view
                else:
                    return render(request, 'registration/login.html', {'error': 'Authentication failed. Please try again.'})
            except ValueError:
                return render(request, 'registration/login.html', {'error': 'Invalid JSON response from API'})
        else:
            return render(request, 'registration/login.html', {'error': response.text})

    def login_api(self, username, password):
        """
        Calls the API endpoint to authenticate the user.
        """
        api_url = f'{settings.API_BASE_URL}/login/'
        payload = {
            'username': username,
            'password': password
        }
        
        response = requests.post(api_url, json=payload)
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

class LogoutView(LoginRequiredMixin, View):
    """
    A view that triggers the LogoutAPIView to log out the user.
    """
    
    def get(self, request):
        """
        Handle GET requests to logout by triggering the POST request.
        """
        return self.post(request)

    def post(self, request):
        """
        Sends a POST request to the LogoutAPIView to log out the user.
        """
        # Make a POST request to the LogoutAPIView
        response = requests.post(f'{settings.API_BASE_URL}/logout/', cookies=request.COOKIES)
        print(request)

        if response.status_code == 204:
            # Logout successful, redirect to login page or home page
            return redirect('login-view')  # Replace 'login' with your login URL name
        else:
            # Handle any errors or redirect appropriately
            return redirect('login-view')  # Replace 'home' with your home URL name

class LogoutAPIView(APIView):
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
    
class PasswordResetRequestHTMLView(View):
    """
    View for rendering the password reset request form and handling submission.
    """

    def get(self, request):
        form = PasswordResetRequestForm()
        return render(request, 'registration/password_reset_request.html', {'form': form})

    def post(self, request):
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            response = requests.post(f'{settings.API_BASE_URL}/password-reset-request/', data={'username': username})
            if response.status_code == 200:
                data = response.json()
                uid = data['uid']
                token = data['token']
                # Assuming you want to redirect to a confirmation page
                confirm_url = reverse('password-reset-confirm-view', kwargs={'uidb64': uid, 'token': token})
                return redirect(confirm_url)
            else:
                # Handle API error responses
                return render(request, 'registration/password_reset_request.html', {'form': form, 'error': 'Error processing request.'})
        return render(request, 'registration/password_reset_request.html', {'form': form})
    
class SetNewPasswordHTMLView(View):
    """
    View for rendering the set new password form and handling submission.
    """

    def get(self, request, uidb64, token):
        form = SetNewPasswordForm()
        return render(request, 'registration/set_new_password.html', {'form': form, 'uidb64': uidb64, 'token': token})

    def post(self, request, uidb64, token):
        form = SetNewPasswordForm(request.POST)
        if form.is_valid():
            data = {
                'new_password1': form.cleaned_data['new_password1'],
                'new_password2': form.cleaned_data['new_password2'],
            }
            response = requests.post(f'{settings.API_BASE_URL}/password-reset-confirm/{uidb64}/{token}/', data=data)
            if response.status_code == status.HTTP_200_OK:
                return redirect('login-view')
            else:
                # Handle API error
                return render(request, 'registration/set_new_password.html', {'form': form, 'uidb64': uidb64, 'token': token, 'error': response.json()})
        return render(request, 'registration/set_new_password.html', {'form': form, 'uidb64': uidb64, 'token': token})
    
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