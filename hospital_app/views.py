from django.contrib.auth.decorators import login_required
from django.shortcuts import render


def landing(request):
    return render(request, "hospital_app/landing.html")


@login_required
def dashboard(request):
    return render(request, "hospital_app/dashboard.html")


def csrf_failure(request, reason=""):
    """Custom 403 page untuk CSRF failure (TC-CSRF-02 / CWE-352)."""
    return render(request, "403_csrf.html", {"reason": reason}, status=403)
