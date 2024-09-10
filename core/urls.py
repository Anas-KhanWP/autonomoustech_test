from django.urls import path
from . import views
# from .views import AppListCreateView, AppRetrieveUpdateDestroyView, PlanListView, SubscriptionRetrieveUpdateView, RegisterView, LogoutView, SubscriptionCreateView, LoginAPIView, PasswordResetRequestView, SetNewPasswordView, LoginView, RegisterHTMLView, AppListCreateHTMLView, AppDetailHTMLView, SubscriptionListAPIView

# URL patterns for the application
urlpatterns = [
    path('login/', views.LoginView.as_view(), name='login-view'),
    path('auth/login/', views.LoginAPIView.as_view(), name='login'), # Endpoint for user login
    path('register/', views.RegisterHTMLView.as_view(), name='register'),
    path('auth/register/', views.RegisterView.as_view(), name='register'), # Endpoint for user registration
    path('apps/', views.AppListCreateHTMLView.as_view(), name='app-list-create-view'), 
    path('auth/apps/', views.AppListCreateView.as_view(), name='app-list-create'), # Endpoint for listing and creating apps
    path('apps/<int:pk>/', views.AppDetailHTMLView.as_view(), name='app-detail-view'), 
    path('auth/apps/<int:pk>/', views.AppRetrieveUpdateDestroyView.as_view(), name='app-detail'), # Endpoint for retrieving, updating, and deleting a specific app
    path('plans/', views.PlanListHTMLView.as_view(), name='plan-list-view'),
    path('auth/plans/', views.PlanListView.as_view(), name='plan-list'), # Endpoint for listing available plans
    path('subscriptions/', views.SubscriptionListView.as_view(), name='subscription-list-view'),
    path('auth/subscriptions/', views.SubscriptionListAPIView.as_view(), name='subscription-list'),
    path('auth/subscriptions/create/', views.SubscriptionCreateView.as_view(), name='subscription-create'), # Endpoint for creating a new subscription
    path('subscriptions/<int:pk>/', views.SubscriptionDetailView.as_view(), name='subscription-detail-view'),
    path('auth/subscriptions/<int:pk>/', views.SubscriptionRetrieveUpdateView.as_view(), name='subscription-detail'), # Endpoint for retrieving, updating a specific subscription
    path('auth/logout/', views.LogoutView.as_view(), name='logout'), # Endpoint for user logout
    path('auth/password-reset-request/', views.PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password-reset-request/', views.PasswordResetRequestHTMLView.as_view(), name='password_reset_request_view'),
    path('password-reset-confirm/<uidb64>/<token>/', views.SetNewPasswordHTMLView.as_view(), name='password-reset-confirm-view'),
    path('auth/password-reset-confirm/<uidb64>/<token>/', views.SetNewPasswordView.as_view(), name='password_reset_confirm'),
]