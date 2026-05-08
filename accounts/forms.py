"""Forms untuk autentikasi.

Mengimplementasikan validasi input ketat sebagai mitigasi:
- CWE-89 (SQL Injection): pakai ORM + validasi format username/email
- CWE-79/94 (XSS/Code Injection): allowlist regex pada username & full_name
- CWE-256/916 (Password): hashing default Django (PBKDF2) + validator panjang.
"""

from __future__ import annotations

import re

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.core.exceptions import ValidationError

from .models import Role, User

# Allowlist: huruf, angka, underscore, dot, dash. Panjang 3-30.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
# Allowlist: huruf, spasi, dot, koma, dash. Panjang 1-120.
_NAME_RE = re.compile(r"^[A-Za-zÀ-ɏ\s.,'-]{1,120}$")


class RegisterForm(UserCreationForm):
    full_name = forms.CharField(
        max_length=120,
        required=True,
        help_text="Nama lengkap (huruf, spasi, dan tanda baca dasar saja).",
    )
    role = forms.ChoiceField(
        choices=[
            (Role.PASIEN, "Pasien"),
            (Role.DOKTER, "Dokter"),
            (Role.APOTEKER, "Apoteker"),
        ],
        initial=Role.PASIEN,
    )
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "full_name", "email", "role", "password1", "password2")

    def clean_username(self) -> str:
        value = self.cleaned_data["username"]
        if not _USERNAME_RE.match(value):
            raise ValidationError(
                "Username hanya boleh huruf, angka, underscore, titik, atau dash (3-30 karakter)."
            )
        return value

    def clean_full_name(self) -> str:
        value = self.cleaned_data["full_name"].strip()
        if not _NAME_RE.match(value):
            raise ValidationError(
                "Nama hanya boleh huruf, spasi, dan tanda baca dasar (',.-)."
            )
        return value

    def save(self, commit: bool = True) -> User:
        # NOTE: UserCreationForm.save() sudah memanggil set_password() yang
        # melakukan hashing PBKDF2 - password TIDAK PERNAH disimpan plaintext.
        user = super().save(commit=False)
        user.role = self.cleaned_data["role"]
        user.full_name = self.cleaned_data["full_name"]
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


class StrictLoginForm(AuthenticationForm):
    """Login form dengan pesan error generik (BA-05 / CWE-204)."""

    error_messages = {
        # Pesan SAMA untuk semua kasus gagal - tidak membocorkan apakah username
        # ada/tidak ada (User Enumeration prevention).
        "invalid_login": "Username atau password salah.",
        "inactive": "Username atau password salah.",
    }
