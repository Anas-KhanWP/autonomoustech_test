from django import forms
from .models import App, Subscriptions
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

class AppForm(forms.ModelForm):
    class Meta:
        model = App
        fields = ['name', 'description']  # Add fields as needed

class SubscriptionForm(forms.ModelForm):
    class Meta:
        model = Subscriptions
        fields = ['plan', 'active']  # Include only editable fields

class PasswordResetRequestForm(forms.Form):
    username = forms.CharField(max_length=150, label='Username')

class SetNewPasswordForm(forms.Form):
    new_password1 = forms.CharField(widget=forms.PasswordInput, label='New Password')
    new_password2 = forms.CharField(widget=forms.PasswordInput, label='Confirm New Password')

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("new_password1")
        password2 = cleaned_data.get("new_password2")

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords do not match.")

