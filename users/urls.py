from django.urls import path
from .views import *
from . import views

app_name = "users"

urlpatterns = [
    path("login/", CustomLoginView.as_view(), name="login"),
    path("register/", RegisterView.as_view(), name="register"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("account-details/", AccountDetailsView.as_view(), name="account_details"),
    path(
        "edit-account-details/",
        EditAccountDetailsView.as_view(),
        name="edit_account_details",
    ),
    path(
        "update-account-details/",
        UpdateAccountDetailsView.as_view(),
        name="update_account_details",
    ),
    path("logout/", CustomLogoutView.as_view(), name="logout"),

    path("password-reset/", PasswordResetRequestView.as_view(), name="password_reset_request"),
    path(
        "password-reset/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
]
