from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save, post_migrate
from django.dispatch import receiver

class Plan(models.Model):
    """
    This class represents a subscription plan for an application.

    Attributes:
    FREE: A constant representing the free plan.
    STANDARD: A constant representing the standard plan.
    PRO: A constant representing the pro plan.
    PLAN_CHOICES: A list of tuples containing the plan choices and their descriptions.

    name: A CharField representing the name of the plan. It has a maximum length of 20 characters and can only be one of the PLAN_CHOICES.
    price: A DecimalField representing the price of the plan. It has a maximum of 5 digits and 2 decimal places.

    Methods:
    __str__: Returns a string representation of the plan.
    """

    FREE = 'Free'
    STANDARD = 'Standard'
    PRO = 'Pro'
    PLAN_CHOICES = [
        (FREE, 'Free Plan'),
        (STANDARD, 'Standard Plan'),
        (PRO, 'Pro Plan'),
    ]
    
    name = models.CharField(max_length=20, choices=PLAN_CHOICES, default=FREE)
    price = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)

    def __str__(self):
        return self.name
    
class App(models.Model):
    """
    This class represents an application in the system.

    Attributes:
    name: A CharField representing the name of the application. It has a maximum length of 255 characters.
    description: A TextField representing a brief description of the application.
    user: A ForeignKey to the User model, representing the user who owns the application. It is set to CASCADE on deletion.

    Methods:
    __str__: Returns a string representation of the application.
    """

    name = models.CharField(max_length=255)
    description = models.TextField()
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
    
def get_default_plan():
    return Plan.objects.get(name=Plan.FREE) 

def get_default_plan():
    return Plan.objects.get(name=Plan.FREE)

class Subscriptions(models.Model):
    """
    This class represents a subscription relationship between an application and a plan.

    Attributes:
    app: A OneToOneField to the App model, representing the application being subscribed. It is set to CASCADE on deletion.
    plan: A ForeignKey to the Plan model, representing the subscription plan. It is set to SET_NULL on deletion and can be NULL.
    active: A BooleanField indicating whether the subscription is currently active. It defaults to True.

    Methods:
    __str__: Returns a string representation of the subscription in the format "app_name - plan_name".
    """

    app = models.OneToOneField(App, on_delete=models.CASCADE, unique=True)
    plan = models.ForeignKey(Plan, on_delete=models.SET_NULL, null=True)
    active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.app.name} - {self.plan.name}"

@receiver(post_save, sender=App)
def create_subscriptions(sender, instance, created, **kwargs):
    """
    This function creates a subscription for a new application. If the application is newly created,
    it assigns a free plan to it.

    Parameters:
    sender (class): The model class sending the signal. In this case, it is the App model.
    instance (App): The instance of the App model that triggered the signal.
    created (bool): A boolean indicating whether the instance was created. True if the instance is new, False otherwise.
    kwargs (dict): Additional keyword arguments passed to the signal handler.

    Returns:
    None
    """
    if created:
        free_plan, created = Plan.objects.get_or_create(name=Plan.FREE, defaults={'price': 0.00})
        Subscriptions.objects.get_or_create(
            app=instance,
            plan=free_plan,
            defaults={'active': True}
        )

@receiver(post_migrate)
def create_default_plans(sender, **kwargs):
    """
    This function creates default subscription plans when the Django application is migrated.
    It checks if the sender's name matches the specified app name and creates three default plans:
    Free, Standard, and Pro.

    Parameters:
    sender (class): The model class sending the signal. In this case, it is the Django migration system.
    kwargs (dict): Additional keyword arguments passed to the signal handler.

    Returns:
    None
    """
    if sender.name == 'core':  # Replace 'your_app_name' with your actual app name
        plans = [
            Plan(name=Plan.FREE, price=0.00),
            Plan(name=Plan.STANDARD, price=10.00),
            Plan(name=Plan.PRO, price=20.00),
        ]
        for plan in plans:
            Plan.objects.get_or_create(name=plan.name, defaults={'price': plan.price})
