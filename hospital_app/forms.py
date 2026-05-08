"""Form ModelForm + sanitasi.

Strategi pertahanan berlapis:
- ModelField validators (allowlist regex) - first line of defense.
- bleach.clean() pada free-text - strip tag HTML berbahaya.
- Template autoescape (default Django) - render aman bila disisipi <script>.
"""

from __future__ import annotations

import bleach
from django import forms

from .models import Pasien, RekamMedis

# Allowlist HTML kosong: SEMUA tag akan di-strip jadi teks biasa.
# Mitigasi CWE-79 (XSS) untuk field free-text yang ditampilkan ulang.
_ALLOWED_TAGS: list[str] = []
_ALLOWED_ATTRS: dict = {}


def _sanitize_text(value: str) -> str:
    """Strip semua HTML tag, kembalikan plain text."""
    if value is None:
        return ""
    return bleach.clean(
        value,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        strip=True,
    )


class PasienForm(forms.ModelForm):
    class Meta:
        model = Pasien
        fields = ["nrm", "nik", "nama", "tanggal_lahir", "jenis_kelamin",
                  "no_telepon", "alamat"]
        widgets = {
            "tanggal_lahir": forms.DateInput(attrs={"type": "date"}),
            "alamat": forms.Textarea(attrs={"rows": 3}),
        }

    def clean_nama(self) -> str:
        return _sanitize_text(self.cleaned_data["nama"]).strip()

    def clean_alamat(self) -> str:
        return _sanitize_text(self.cleaned_data["alamat"]).strip()


class RekamMedisForm(forms.ModelForm):
    class Meta:
        model = RekamMedis
        fields = ["nomor", "pasien", "dokter", "tanggal",
                  "anamnesis", "diagnosa", "catatan_dokter"]
        widgets = {
            "tanggal": forms.DateInput(attrs={"type": "date"}),
            "anamnesis": forms.Textarea(attrs={"rows": 3}),
            "diagnosa": forms.Textarea(attrs={"rows": 2}),
            "catatan_dokter": forms.Textarea(attrs={"rows": 4}),
        }

    def clean_nomor(self) -> str:
        # nomor rekam medis: hanya alfanumerik dan dash.
        value = self.cleaned_data["nomor"].strip()
        if not value.replace("-", "").isalnum():
            raise forms.ValidationError("Nomor rekam medis tidak valid.")
        return value

    def clean_anamnesis(self) -> str:
        return _sanitize_text(self.cleaned_data["anamnesis"])

    def clean_diagnosa(self) -> str:
        return _sanitize_text(self.cleaned_data["diagnosa"])

    def clean_catatan_dokter(self) -> str:
        return _sanitize_text(self.cleaned_data["catatan_dokter"])
