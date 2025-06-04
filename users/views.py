import logging
from typing import Optional, Dict, Any

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import LoginView, LogoutView
from django.http import HttpResponse, HttpRequest
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.views import View
from django.views.generic import CreateView, TemplateView, UpdateView, FormView
from django.contrib.auth import login, logout
from django.urls import reverse_lazy
from django.shortcuts import redirect, render

from users.forms import (
    CustomUserCreationForm,
    CustomUserLoginForm,
    CustomUserUpdateForm,
)
from users.models import CustomUser

from users.forms import PasswordResetRequestForm, PasswordResetConfirmForm
from users.tasks import send_welcome_email, send_password_reset_email

logger = logging.getLogger(__name__)


class RegisterView(CreateView):
    form_class = CustomUserCreationForm
    template_name = "users/register.html"
    success_url = reverse_lazy("users:profile")

    def form_valid(self, form):
        """Вызывается когда form.is_valid() возвращает True"""
        user = form.save()
        login(self.request, user, backend="django.contrib.auth.backends.ModelBackend")
        send_welcome_email.delay(user.email, user.first_name)
        logger.info(f"Welcome email task queued for {user.email}")
        return redirect("users:profile")

    def form_invalid(self, form):
        """Вызывается когда form.is_valid() возвращает False"""
        return self.render_to_response(self.get_context_data(form=form))


class CustomLoginView(LoginView):
    form_class = CustomUserLoginForm
    template_name = "users/login.html"
    success_url = reverse_lazy("users:profile")

    def form_valid(self, form):
        """Переопределяем для кастомного backend"""
        user = form.get_user()
        login(self.request, user, backend="django.contrib.auth.backends.ModelBackend")
        return redirect("users:profile")


class ProfileView(LoginRequiredMixin, TemplateView):
    template_name = "users/profile.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["user"] = self.request.user
        return context


class AccountDetailsView(LoginRequiredMixin, TemplateView):
    template_name = "users/partials/account_details.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Получаем пользователя из базы (хотя можно использовать self.request.user)
        user = CustomUser.objects.get(id=self.request.user.id)
        context["user"] = user
        return context


class EditAccountDetailsView(LoginRequiredMixin, TemplateView):
    template_name = "users/partials/edit_account_details.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["user"] = self.request.user
        context["form"] = CustomUserUpdateForm(instance=self.request.user)
        return context


class UpdateAccountDetailsView(LoginRequiredMixin, UpdateView):
    form_class = CustomUserUpdateForm
    template_name = "users/partials/edit_account_details.html"
    success_url = reverse_lazy("users:account_details")

    def get_object(self, queryset=None):
        return self.request.user

    def form_valid(self, form):
        """Обработка валидной формы"""
        user = form.save(commit=False)
        user.clean()
        user.save()
        # Возвращаем рендер шаблона account_details вместо редиректа
        return render(
            self.request, "users/partials/account_details.html", {"user": user}
        )

    def form_invalid(self, form):
        """Обработка невалидной формы"""
        return render(
            self.request,
            "users/partials/edit_account_details.html",
            {"user": self.request.user, "form": form},
        )

    def get(self, request, *args, **kwargs):
        """Обработка GET запросов - показываем детали аккаунта"""
        return render(
            request, "users/partials/account_details.html", {"user": request.user}
        )


class CustomLogoutView(View):
    def get(self, request):
        logout(request)
        return redirect("users:register")

    def post(self, request):
        logout(request)
        return redirect("users:register")


"""""" ""


class PasswordResetRequestView(FormView):
    """
    Класс-представление для запроса сброса пароля.

    Обрабатывает форму запроса сброса пароля, проверяет существование пользователя
    и отправляет email с инструкциями для сброса пароля.
    """

    template_name: str = "users/password_reset_request.html"
    form_class = PasswordResetRequestForm
    success_url: str = reverse_lazy("password_reset_done")

    def form_valid(self, form: PasswordResetRequestForm) -> HttpResponse:
        """
        Обработка валидной формы запроса сброса пароля.

        Args:
            form: Валидная форма с email пользователя

        Returns:
            HttpResponse: Ответ с страницей подтверждения или текущей страницей
        """
        email: str = form.cleaned_data["email"]
        user: Optional[CustomUser] = CustomUser.objects.filter(email=email).first()

        if user:
            logger.info(
                f"Attempting to send password reset email to {email} for user ID {user.pk}"
            )
            send_password_reset_email.delay(email, user.pk)
            messages.success(
                self.request,
                "Password reset email has been queued. Please check your inbox or spam folder.",
            )
            return render(self.request, "users/password_reset_done.html")
        else:
            messages.warning(self.request, "No account found with this email.")
            return self.form_invalid(form)

    def form_invalid(self, form: PasswordResetRequestForm) -> HttpResponse:
        """
        Обработка невалидной формы.

        Args:
            form: Невалидная форма

        Returns:
            HttpResponse: Ответ с формой и ошибками
        """
        if not form.errors:
            messages.error(self.request, "Please enter a valid email address.")
        return super().form_invalid(form)


class PasswordResetConfirmView(FormView):
    """
    Класс-представление для подтверждения сброса пароля.

    Обрабатывает токен сброса пароля и форму установки нового пароля.
    Проверяет валидность токена и устанавливает новый пароль пользователю.
    """

    template_name: str = "users/password_reset_confirm.html"
    form_class = PasswordResetConfirmForm
    success_url: str = reverse_lazy("password_reset_complete")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.user: Optional[CustomUser] = None
        self.validlink: bool = False

    def dispatch(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        """
        Проверка валидности токена перед обработкой запроса.

        Args:
            request: HTTP запрос
            *args: Позиционные аргументы (uidb64, token)
            **kwargs: Именованные аргументы

        Returns:
            HttpResponse: Ответ представления
        """
        uidb64: str = kwargs.get("uidb64", "")
        token: str = kwargs.get("token", "")

        self.user, self.validlink = self._validate_token(uidb64, token)

        return super().dispatch(request, *args, **kwargs)

    def _validate_token(
        self, uidb64: str, token: str
    ) -> tuple[Optional[CustomUser], bool]:
        """
        Валидация токена сброса пароля.

        Args:
            uidb64: Закодированный ID пользователя
            token: Токен сброса пароля

        Returns:
            tuple: Кортеж (пользователь, валидность_ссылки)
        """
        try:
            uid: str = force_str(urlsafe_base64_decode(uidb64))
            user: CustomUser = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            logger.warning(
                f"Invalid uidb64 or user not found for token validation: {uidb64}"
            )
            return None, False

        if user is not None and default_token_generator.check_token(user, token):
            logger.info(f"Valid password reset token for user ID {user.pk}")
            return user, True
        else:
            logger.warning(f"Invalid token for user ID {user.pk if user else 'None'}")
            return user, False

    def get_context_data(self, **kwargs) -> Dict[str, Any]:
        """
        Добавление дополнительного контекста в шаблон.

        Args:
            **kwargs: Дополнительные параметры контекста

        Returns:
            Dict[str, Any]: Контекст для шаблона
        """
        context: Dict[str, Any] = super().get_context_data(**kwargs)
        context["validlink"] = self.validlink
        return context

    def get(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        """
        Обработка GET запроса.

        Args:
            request: HTTP запрос
            *args: Позиционные аргументы
            **kwargs: Именованные аргументы

        Returns:
            HttpResponse: Ответ с формой или сообщением о невалидной ссылке
        """
        if not self.validlink:
            return render(request, self.template_name, {"validlink": False})

        return super().get(request, *args, **kwargs)

    def post(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        """
        Обработка POST запроса.

        Args:
            request: HTTP запрос
            *args: Позиционные аргументы
            **kwargs: Именованные аргументы

        Returns:
            HttpResponse: Ответ с результатом обработки формы
        """
        if not self.validlink:
            return render(request, self.template_name, {"validlink": False})

        return super().post(request, *args, **kwargs)

    def form_valid(self, form: PasswordResetConfirmForm) -> HttpResponse:
        """
        Обработка валидной формы установки нового пароля.

        Args:
            form: Валидная форма с новым паролем

        Returns:
            HttpResponse: Ответ с страницей успешного завершения
        """
        if self.user and self.validlink:
            new_password: str = form.cleaned_data["new_password1"]
            self.user.set_password(new_password)
            self.user.save()

            logger.info(f"Password successfully reset for user ID {self.user.pk}")
            messages.success(self.request, "Your password has been reset successfully.")

            return render(self.request, "users/password_reset_complete.html")
        else:
            logger.error("Attempt to reset password with invalid user or token")
            return render(self.request, self.template_name, {"validlink": False})

    def form_invalid(self, form: PasswordResetConfirmForm) -> HttpResponse:
        """
        Обработка невалидной формы.

        Args:
            form: Невалидная форма

        Returns:
            HttpResponse: Ответ с формой и ошибками
        """
        logger.warning(
            f"Invalid password reset form submission for user ID {self.user.pk if self.user else 'None'}"
        )
        return super().form_invalid(form)
