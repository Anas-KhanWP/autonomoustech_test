from django.urls import path
from .views import AppListCreateView, AppRetrieveUpdateDestroyView, PlanListView, SubscriptionRetrieveUpdateView, RegisterView, LogoutView, SubscriptionCreateView, LoginAPIView

# URL patterns for the application
urlpatterns = [
    path('apps/', AppListCreateView.as_view(), name='app-list-create'), # Endpoint for listing and creating apps
    path('apps/<int:pk>/', AppRetrieveUpdateDestroyView.as_view(), name='app-detail'), # Endpoint for retrieving, updating, and deleting a specific app
    path('plans/', PlanListView.as_view(), name='plan-list'), # Endpoint for listing available plans
    path('subscriptions/create/', SubscriptionCreateView.as_view(), name='subscription-create'), # Endpoint for creating a new subscription
    path('subscriptions/<int:pk>/', SubscriptionRetrieveUpdateView.as_view(), name='subscription-detail'), # Endpoint for retrieving, updating a specific subscription
    path('register/', RegisterView.as_view(), name='register'), # Endpoint for user registration
    path('login/', LoginAPIView.as_view(), name='login'), # Endpoint for user login
    path('logout/', LogoutView.as_view(), name='logout'), # Endpoint for user logout
]