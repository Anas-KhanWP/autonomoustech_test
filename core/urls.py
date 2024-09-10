from django.urls import path
from .views import AppListCreateView, AppRetrieveUpdateDestroyView, PlanListView, SubscriptionRetrieveUpdateView, RegisterView, LogoutView, SubscriptionCreateView, LoginAPIView, PasswordResetRequestView, SetNewPasswordView, LoginView, RegisterHTMLView, AppListCreateHTMLView, AppDetailHTMLView

# URL patterns for the application
urlpatterns = [
    path('login/', LoginView.as_view(), name='login-view'),
    path('auth/login/', LoginAPIView.as_view(), name='login'), # Endpoint for user login
    path('register/', RegisterHTMLView.as_view(), name='register'),
    path('auth/register/', RegisterView.as_view(), name='register'), # Endpoint for user registration
    path('apps/', AppListCreateHTMLView.as_view(), name='app-list-create-view'), 
    path('auth/apps/', AppListCreateView.as_view(), name='app-list-create'), # Endpoint for listing and creating apps
    path('apps/<int:pk>/', AppDetailHTMLView.as_view(), name='app-detail-view'), 
    path('auth/apps/<int:pk>/', AppRetrieveUpdateDestroyView.as_view(), name='app-detail'), # Endpoint for retrieving, updating, and deleting a specific app
    path('auth/plans/', PlanListView.as_view(), name='plan-list'), # Endpoint for listing available plans
    path('auth/subscriptions/create/', SubscriptionCreateView.as_view(), name='subscription-create'), # Endpoint for creating a new subscription
    path('auth/subscriptions/<int:pk>/', SubscriptionRetrieveUpdateView.as_view(), name='subscription-detail'), # Endpoint for retrieving, updating a specific subscription
    path('auth/logout/', LogoutView.as_view(), name='logout'), # Endpoint for user logout
    path('auth/password-reset-request/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('auth/password-reset-confirm/<uidb64>/<token>/', SetNewPasswordView.as_view(), name='password_reset_confirm'),
]