"""Decorator permission untuk role-based access control (least privilege).

Mendukung BA-04 (CWE-306) - akses halaman terproteksi tanpa login -
dan kebijakan least privilege per role.
"""

from functools import wraps

from django.contrib.auth.decorators import login_required
from django.shortcuts import render


def role_required(*allowed_roles: str):
    """Hanya user dengan role tertentu yang boleh mengakses view."""

    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapped(request, *args, **kwargs):
            user = request.user
            if user.is_superuser or user.role in allowed_roles:
                return view_func(request, *args, **kwargs)
            # Render 403 langsung (tidak via handler403 yang hanya aktif saat
            # DEBUG=False) - jadi UX konsisten antara development & production.
            return render(request, "403.html", {
                "exception": "Role Anda tidak diizinkan mengakses halaman ini.",
            }, status=403)

        return wrapped

    return decorator
