from django.contrib.auth.models import AbstractUser
from django.db import models


class Role(models.TextChoices):
    """Role pengguna sesuai skenario Hospital Information System."""
    ADMIN = "ADMIN", "Administrator"
    DOKTER = "DOKTER", "Dokter"
    PASIEN = "PASIEN", "Pasien"
    APOTEKER = "APOTEKER", "Apoteker"


class User(AbstractUser):
    """Custom user model dengan role dan password hashing default Django (PBKDF2).

    Mendukung BA-01 (CWE-256/916): password disimpan terhash, tidak pernah plaintext.
    """
    role = models.CharField(
        max_length=16,
        choices=Role.choices,
        default=Role.PASIEN,
    )
    full_name = models.CharField(max_length=120, blank=True)

    # Helper untuk template / view permission checks (least privilege).
    @property
    def is_dokter(self) -> bool:
        return self.role == Role.DOKTER

    @property
    def is_pasien(self) -> bool:
        return self.role == Role.PASIEN

    @property
    def is_apoteker(self) -> bool:
        return self.role == Role.APOTEKER

    @property
    def is_admin_role(self) -> bool:
        return self.role == Role.ADMIN

    def __str__(self) -> str:
        return f"{self.username} ({self.get_role_display()})"
