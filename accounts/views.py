"""Views autentikasi.

Mengimplementasikan:
- Login: pesan error generik (BA-05/CWE-204), CSRF protected (CWE-352)
- Logout: invalidate session (BA-03/CWE-613)
- Register: dengan password validators dan PBKDF2 hashing (BA-01).
"""

from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods, require_POST

from .forms import RegisterForm, StrictLoginForm


@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.user.is_authenticated:
        return redirect("hospital_app:dashboard")

    # request= dilewatkan agar django-axes bisa melihat IP & username.
    form = StrictLoginForm(request, data=request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.get_user()
        login(request, user)
        # Rotasi session ID setelah login (mitigasi session fixation).
        request.session.cycle_key()
        return redirect("hospital_app:dashboard")

    return render(request, "accounts/login.html", {"form": form})


@require_POST
def logout_view(request):
    """Logout via POST (CSRF protected) - flush() menghapus session sepenuhnya."""
    logout(request)
    request.session.flush()  # Pastikan session token tidak bisa dipakai lagi.
    messages.info(request, "Anda telah logout.")
    return redirect("accounts:login")


@require_http_methods(["GET", "POST"])
def register_view(request):
    if request.user.is_authenticated:
        return redirect("hospital_app:dashboard")

    form = RegisterForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        # Eksplisit pilih ModelBackend - axes adalah backend "guard", bukan
        # authenticator sungguhan. Tanpa argumen ini, Django raise ValueError
        # karena ada >1 AUTHENTICATION_BACKENDS.
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        request.session.cycle_key()
        messages.success(request, "Pendaftaran berhasil. Selamat datang!")
        return redirect("hospital_app:dashboard")

    return render(request, "accounts/register.html", {"form": form})


@login_required
def profile_view(request):
    return render(request, "accounts/profile.html", {"user_obj": request.user})
