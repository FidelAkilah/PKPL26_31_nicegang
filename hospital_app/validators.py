"""Input validators (allowlist) untuk mencegah Code Injection (CWE-79/94).

Strategi: validasi sebelum simpan + autoescape pada template.
"""

from __future__ import annotations

import re

from django.core.exceptions import ValidationError

# Hanya digit, panjang 8-16 (NRM = nomor rekam medis hospital).
_NRM_RE = re.compile(r"^[0-9]{8,16}$")
# NIK Indonesia: 16 digit.
_NIK_RE = re.compile(r"^[0-9]{16}$")
# Nomor telepon: opsional + dan digit, 8-15 char.
_PHONE_RE = re.compile(r"^\+?[0-9]{8,15}$")
# Nama: huruf, spasi, dan tanda baca dasar.
_NAME_RE = re.compile(r"^[A-Za-zÀ-ɏ\s.,'-]{1,120}$")
# Kode obat: huruf besar, angka, dash. Mis: PCT-500, AMOX-250.
_KODE_OBAT_RE = re.compile(r"^[A-Z0-9-]{3,20}$")


def validate_nrm(value: str) -> None:
    if not _NRM_RE.match(value):
        raise ValidationError("Nomor rekam medis harus 8-16 digit angka.")


def validate_nik(value: str) -> None:
    if not _NIK_RE.match(value):
        raise ValidationError("NIK harus 16 digit angka.")


def validate_phone(value: str) -> None:
    if not _PHONE_RE.match(value):
        raise ValidationError("Nomor telepon tidak valid (8-15 digit, opsional +).")


def validate_name(value: str) -> None:
    if not _NAME_RE.match(value):
        raise ValidationError("Nama hanya boleh huruf, spasi, dan tanda baca dasar.")


def validate_kode_obat(value: str) -> None:
    if not _KODE_OBAT_RE.match(value):
        raise ValidationError("Kode obat: huruf besar/angka/dash, 3-20 karakter.")
