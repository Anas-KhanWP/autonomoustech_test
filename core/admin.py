from django.contrib import admin
from .models import Plan, App, Subscriptions

@admin.register(Plan)
class PlanAdmin(admin.ModelAdmin):
    """
    Django admin model for managing Plans.

    Attributes:
    list_display: Fields to display in the list view.
    search_fields: Fields to search in the admin interface.
    """
    list_display = ('name', 'price')
    search_fields = ('name',)

@admin.register(App)
class AppAdmin(admin.ModelAdmin):
    """
    Django admin model for managing Apps.

    Attributes:
    list_display: Fields to display in the list view.
    search_fields: Fields to search in the admin interface.
    list_filter: Fields to filter in the list view.
    """
    list_display = ('name', 'description', 'user')
    search_fields = ('name', 'description')
    list_filter = ('user',)

@admin.register(Subscriptions)
class SubscriptionAdmin(admin.ModelAdmin):
    """
    Django admin model for managing Subscriptions.

    Attributes:
    list_display: Fields to display in the list view.
    search_fields: Fields to search in the admin interface.
    list_filter: Fields to filter in the list view.
    """
    list_display = ('app', 'plan', 'active')
    search_fields = ('app__name', 'plan__name')
    list_filter = ('active',)