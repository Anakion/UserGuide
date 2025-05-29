from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.views import View
from django.views.generic import CreateView, TemplateView, UpdateView
from django.contrib.auth import login, logout
from django.urls import reverse_lazy
from django.shortcuts import redirect, render

from users.forms import (
    CustomUserCreationForm,
    CustomUserLoginForm,
    CustomUserUpdateForm,
)
from users.models import CustomUser


class RegisterView(CreateView):
    form_class = CustomUserCreationForm
    template_name = "users/register.html"
    success_url = reverse_lazy("users:profile")

    def form_valid(self, form):
        """Вызывается когда form.is_valid() возвращает True"""
        user = form.save()
        login(self.request, user, backend="django.contrib.auth.backends.ModelBackend")
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
