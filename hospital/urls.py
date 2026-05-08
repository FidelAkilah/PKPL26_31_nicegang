from django.contrib import admin
from django.shortcuts import redirect
from django.urls import include, path

# Custom error handler untuk PermissionDenied (raised oleh @role_required).
handler403 = "hospital_app.views.permission_denied"

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("accounts.urls")),
    path("", include("hospital_app.urls")),
    # Alias - URL name harus namespaced.
    path("home/", lambda r: redirect("hospital_app:dashboard")),
]
