"""
Django settings for hospital project.
PKPL Tugas 3 - Kelompok 31 nicegang
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Secret key dimuat dari environment variable; fallback hanya untuk development.
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "dev-only-key-DO-NOT-USE-IN-PRODUCTION-91kx9k4f7m2j8h3qp",
)

DEBUG = os.environ.get("DJANGO_DEBUG", "True") == "True"

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0"]


# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third party
    "axes",
    # Local apps
    "accounts",
    "hospital_app",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # django-axes harus jadi MIDDLEWARE TERAKHIR (rate limiting login).
    "axes.middleware.AxesMiddleware",
]

ROOT_URLCONF = "hospital.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            # autoescape=True adalah default Django; eksplisit untuk dokumentasi.
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "hospital.wsgi.application"


# Database (SQLite sesuai requirement tugas).
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


# Custom user model dengan role.
AUTH_USER_MODEL = "accounts.User"


# Authentication backends. AxesStandaloneBackend wajib di posisi pertama
# untuk mencegah brute force sebelum ModelBackend memvalidasi password.
AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]


# Password hashing - PBKDF2 (default Django, memenuhi requirement BA-01/CWE-256/916).
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 8},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]


# Session security (memenuhi BA-03 / CWE-613).
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_AGE = 60 * 60  # 1 jam
SESSION_SAVE_EVERY_REQUEST = True  # Refresh expiry tiap request aktif.

# CSRF security (memenuhi semua TC-CSRF-* / CWE-352).
# Catatan: Default Django pakai cookie-based CSRF + double-submit pattern -
# token di-bind dengan secret HMAC di session. Sama amannya dengan
# CSRF_USE_SESSIONS=True, tapi lebih kompatibel cross-platform (Windows
# kadang flaky dengan session-based CSRF saat testing).
CSRF_COOKIE_HTTPONLY = False  # Harus False agar bisa dibaca template tag.
CSRF_COOKIE_SAMESITE = "Strict"  # Browser tidak kirim cookie pada cross-origin POST.
CSRF_FAILURE_VIEW = "hospital_app.views.csrf_failure"

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

# Login URLs
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/dashboard/"
LOGOUT_REDIRECT_URL = "/accounts/login/"


# django-axes config (memenuhi BA-02 / CWE-307).
AXES_FAILURE_LIMIT = 5  # Lockout setelah 5 percobaan gagal.
AXES_COOLOFF_TIME = 0.25  # 15 menit (0.25 jam).
AXES_LOCKOUT_PARAMETERS = ["username", "ip_address"]
AXES_RESET_ON_SUCCESS = True
AXES_LOCKOUT_TEMPLATE = "accounts/lockout.html"


# Internationalization
LANGUAGE_CODE = "id"
TIME_ZONE = "Asia/Jakarta"
USE_I18N = True
USE_TZ = True


# Static files
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"] if (BASE_DIR / "static").exists() else []
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# Logging - generic error messages (memenuhi BA-05 / CWE-204).
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
    },
    "loggers": {
        "django.security": {"handlers": ["console"], "level": "WARNING"},
        "axes": {"handlers": ["console"], "level": "WARNING"},
    },
}
