from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth.models import User
from .models import Plan, App, Subscriptions
from rest_framework.authtoken.models import Token

class PlanTests(APITestCase):
    def setUp(self):
        """
        This function is used to set up the initial data for testing.

        Parameters:
        None

        Returns:
        None
        
        This function creates three Plan instances in the database:
        - A free plan with name 'FREE' and price 0.00
        - A standard plan with name 'STANDARD' and price 10.00
        - A pro plan with name 'PRO' and price 20.00
        """
        self.plan_free = Plan.objects.create(name=Plan.FREE, price=0.00)
        self.plan_standard = Plan.objects.create(name=Plan.STANDARD, price=10.00)
        self.plan_pro = Plan.objects.create(name=Plan.PRO, price=20.00)
    
    def test_get_plans(self):
        """
        This function tests the retrieval of all available plans.

        Parameters:
        None

        Returns:
        None

        This function sends a GET request to the 'plan-list' endpoint and verifies that:
        - The HTTP status code of the response is 200 (HTTP_200_OK)
        - The number of plans returned in the response data is 6 (3 already added & adding 3 more)
        """
        response = self.client.get(reverse('plan-list'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 6) # 3 Already Added & Adding 3 More! # 3 Already Added & Adding 3 More!

class AppTests(APITestCase):
    def setUp(self):
        """
        This function is used to set up the initial data for testing.

        Parameters:
        None

        Returns:
        None

        This function creates a User instance and an App instance in the database:
        - A User instance with username 'testuser' and password 'password123'
        - An App instance with name 'Test App', description 'A test app', and associated with the created User instance
        """
        self.user = User.objects.create_user(username='testuser', password='password123')
        self.app = App.objects.create(name='Test App', description='A test app', user=self.user)  
          
    def test_create_app(self):
        """
        This function tests the creation of a new App instance.

        Parameters:
        None

        Returns:
        None

        This function sends a POST request to the 'app-list-create' endpoint with the necessary data to create a new App instance.
        It then verifies that:
        - The HTTP status code of the response is 201 (HTTP_201_CREATED)
        - The number of App instances in the database is 2 after the creation
        """
        data = {'name': 'New App', 'description': 'A new app', 'user': self.user.id}
        response = self.client.post(reverse('app-list-create'), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(App.objects.count(), 2)  
          
    def test_get_app(self):
        """
        This function tests the retrieval of a specific App instance.

        Parameters:
        None

        Returns:
        None

        This function sends a GET request to the 'app-detail' endpoint with the primary key of the 'self.app' instance.
        It then verifies that:
        - The HTTP status code of the response is 200 (HTTP_200_OK)
        - The name of the App instance returned in the response data is 'Test App'
        """
        response = self.client.get(reverse('app-detail', kwargs={'pk': self.app.id}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Test App')
        
    def test_delete_app(self):
        """
        This function tests the deletion of a specific App instance.

        Parameters:
        None

        Returns:
        None

        This function sends a DELETE request to the 'app-detail' endpoint with the primary key of the 'self.app' instance.
        It then verifies that:
        - The HTTP status code of the response is 204 (HTTP_204_NO_CONTENT)
        - The number of App instances in the database is 0 after the deletion
        """
        response = self.client.delete(reverse('app-detail', kwargs={'pk': self.app.id}))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(App.objects.count(), 0)
        
class SubscriptionTests(APITestCase):
    """
    This class contains test cases for the Subscription model and its related views.
    """

    def setUp(self):
        """
        This function sets up the initial data for testing.

        Parameters:
        None

        Returns:
        None

        This function creates a User instance, an App instance, and a Plan instance in the database.
        It also ensures a subscription is created for the app if it doesn't already exist.
        """
        self.user = User.objects.create_user(username='testuser', password='password123')
        self.app = App.objects.create(name='Test App', description='A test app', user=self.user)
        self.plan_free = Plan.objects.create(name=Plan.FREE, price=0.00)
        
        # Ensure a subscription is created for the app if it doesn't already exist
        self.subscription, created = Subscriptions.objects.get_or_create(
            app=self.app,
            defaults={'plan': self.plan_free, 'active': True}
        )
    
    def test_get_subscription(self):
        """
        This function tests the retrieval of a specific Subscription instance.

        Parameters:
        None

        Returns:
        None

        This function sends a GET request to the 'subscription-detail' endpoint with the primary key of the 'self.subscription' instance.
        It then verifies that:
        - The HTTP status code of the response is 200 (HTTP_200_OK)
        - The 'app' field of the Subscription instance returned in the response data is equal to the primary key of the 'self.app' instance
        """
        response = self.client.get(reverse('subscription-detail', kwargs={'pk': self.subscription.id}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['app'], self.app.id)

class AuthTests(APITestCase):
    """
    This class contains test cases for user authentication functionalities.
    """

    def setUp(self):
        """
        This function sets up the initial data for testing.

        Parameters:
        None

        Returns:
        None

        This function creates a User instance with username 'testuser' and password 'password123'.
        """
        self.user = User.objects.create_user(username='testuser', password='password123')
    
    def test_register(self):
        """
        This function tests the user registration functionality.

        Parameters:
        None

        Returns:
        None

        This function sends a POST request to the 'register' endpoint with new user data.
        It then verifies that:
        - The HTTP status code of the response is 201 (HTTP_201_CREATED)
        - The number of User instances in the database is 2 after the registration
        """
        data = {'username': 'newuser', 'password': 'newpassword123'}
        response = self.client.post(reverse('register'), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 2)
    
    def test_login(self):
        """
        This function tests the user login functionality.

        Parameters:
        None

        Returns:
        None

        This function sends a POST request to the 'login' endpoint with user credentials.
        It then verifies that:
        - The HTTP status code of the response is 200 (HTTP_200_OK)
        - The response data contains a 'token' field
        """
        data = {'username': 'testuser', 'password': 'password123'}
        response = self.client.post(reverse('login'), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
    
    def test_logout(self):
        """
        This function tests the user logout functionality.

        Parameters:
        None

        Returns:
        None

        This function logs in the user, sends a POST request to the 'logout' endpoint,
        and verifies that the HTTP status code of the response is 204 (HTTP_204_NO_CONTENT).
        """
        self.client.login(username='testuser', password='password123')
        response = self.client.post(reverse('logout'))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)