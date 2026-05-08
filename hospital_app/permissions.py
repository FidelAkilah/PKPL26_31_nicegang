"""Decorator permission untuk role-based access control (least privilege).

Mendukung BA-04 (CWE-306) - akses halaman terproteksi tanpa login -
dan kebijakan least privilege per role.
"""

from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied


def role_required(*allowed_roles: str):
    """Hanya user dengan role tertentu yang boleh mengakses view."""

    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapped(request, *args, **kwargs):
            user = request.user
            if user.is_superuser or user.role in allowed_roles:
                return view_func(request, *args, **kwargs)
            raise PermissionDenied("Akses ditolak: role Anda tidak diizinkan.")

        return wrapped

    return decorator
