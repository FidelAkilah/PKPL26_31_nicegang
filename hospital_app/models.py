"""Model master data Hospital Information System.

Semua model menggunakan Django ORM (parameterized queries by default) -
mitigasi SQL Injection (CWE-89). Tidak ada raw SQL string concatenation.
"""

from django.conf import settings
from django.db import models

from .validators import (
    validate_kode_obat,
    validate_name,
    validate_nik,
    validate_nrm,
    validate_phone,
)


class Pasien(models.Model):
    """Data master pasien - 1:1 dengan User berisi role PASIEN."""
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="pasien_profile",
        null=True, blank=True,
        help_text="Akun login pasien (opsional - pasien bisa belum punya akun).",
    )
    nrm = models.CharField(
        "Nomor Rekam Medis",
        max_length=16, unique=True, db_index=True,
        validators=[validate_nrm],
    )
    nik = models.CharField(
        "NIK", max_length=16, unique=True,
        validators=[validate_nik],
    )
    nama = models.CharField(max_length=120, validators=[validate_name])
    tanggal_lahir = models.DateField()
    JENIS_KELAMIN = [("L", "Laki-laki"), ("P", "Perempuan")]
    jenis_kelamin = models.CharField(max_length=1, choices=JENIS_KELAMIN)
    no_telepon = models.CharField(max_length=15, validators=[validate_phone])
    alamat = models.TextField(max_length=300)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["nrm"]
        verbose_name = "Pasien"
        verbose_name_plural = "Pasien"

    def __str__(self) -> str:
        return f"{self.nrm} - {self.nama}"


class Dokter(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="dokter_profile",
    )
    nip = models.CharField(max_length=20, unique=True, db_index=True)
    nama = models.CharField(max_length=120, validators=[validate_name])
    spesialisasi = models.CharField(max_length=80)
    no_telepon = models.CharField(max_length=15, validators=[validate_phone])

    class Meta:
        ordering = ["nama"]

    def __str__(self) -> str:
        return f"dr. {self.nama} - {self.spesialisasi}"


class Apoteker(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="apoteker_profile",
    )
    nip = models.CharField(max_length=20, unique=True, db_index=True)
    nama = models.CharField(max_length=120, validators=[validate_name])

    class Meta:
        ordering = ["nama"]

    def __str__(self) -> str:
        return f"Apt. {self.nama}"


class Obat(models.Model):
    kode = models.CharField(
        max_length=20, unique=True, db_index=True,
        validators=[validate_kode_obat],
    )
    nama = models.CharField(max_length=120)
    satuan = models.CharField(max_length=20, default="tablet")
    stok = models.PositiveIntegerField(default=0)
    harga = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    class Meta:
        ordering = ["nama"]
        verbose_name = "Obat"
        verbose_name_plural = "Obat"

    def __str__(self) -> str:
        return f"{self.kode} - {self.nama}"


class RekamMedis(models.Model):
    """Rekam medis kunjungan pasien (TC-SQLi-04a, TC-CI-04a, TC-CSRF-04a).

    Field bebas-format (anamnesis, diagnosa, catatan_dokter) di-autoescape
    saat render template (mitigasi XSS / CWE-79).
    """
    nomor = models.CharField(max_length=20, unique=True, db_index=True)
    pasien = models.ForeignKey(Pasien, on_delete=models.PROTECT, related_name="rekam_medis")
    dokter = models.ForeignKey(Dokter, on_delete=models.PROTECT, related_name="rekam_medis")
    tanggal = models.DateField()
    anamnesis = models.TextField(max_length=1000, blank=True)
    diagnosa = models.TextField(max_length=500)
    catatan_dokter = models.TextField(max_length=1000, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-tanggal", "-id"]
        verbose_name = "Rekam Medis"
        verbose_name_plural = "Rekam Medis"

    def __str__(self) -> str:
        return f"{self.nomor} - {self.pasien.nama}"


class JadwalDokter(models.Model):
    HARI = [
        ("SEN", "Senin"), ("SEL", "Selasa"), ("RAB", "Rabu"),
        ("KAM", "Kamis"), ("JUM", "Jumat"), ("SAB", "Sabtu"), ("MIN", "Minggu"),
    ]
    dokter = models.ForeignKey(Dokter, on_delete=models.CASCADE, related_name="jadwal")
    hari = models.CharField(max_length=3, choices=HARI)
    jam_mulai = models.TimeField()
    jam_selesai = models.TimeField()
    ruangan = models.CharField(max_length=40)

    class Meta:
        ordering = ["dokter", "hari", "jam_mulai"]
        verbose_name = "Jadwal Dokter"
        verbose_name_plural = "Jadwal Dokter"

    def __str__(self) -> str:
        return f"{self.dokter} - {self.get_hari_display()} {self.jam_mulai}-{self.jam_selesai}"


class Resep(models.Model):
    """Resep obat dari dokter ke pasien (di-fulfill apoteker)."""
    STATUS = [
        ("DRAFT", "Draft"),
        ("DIKELUARKAN", "Dikeluarkan oleh Apoteker"),
        ("DIBATALKAN", "Dibatalkan"),
    ]
    nomor = models.CharField(max_length=20, unique=True, db_index=True)
    rekam_medis = models.ForeignKey(
        RekamMedis, on_delete=models.PROTECT, related_name="resep_set",
    )
    dokter = models.ForeignKey(Dokter, on_delete=models.PROTECT, related_name="resep_set")
    apoteker = models.ForeignKey(
        Apoteker, on_delete=models.PROTECT,
        related_name="resep_set", null=True, blank=True,
    )
    tanggal = models.DateField()
    status = models.CharField(max_length=12, choices=STATUS, default="DRAFT")
    catatan = models.TextField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-tanggal", "-id"]
        verbose_name = "Resep"
        verbose_name_plural = "Resep"

    def __str__(self) -> str:
        return f"{self.nomor} ({self.get_status_display()})"


class ResepItem(models.Model):
    resep = models.ForeignKey(Resep, on_delete=models.CASCADE, related_name="items")
    obat = models.ForeignKey(Obat, on_delete=models.PROTECT)
    jumlah = models.PositiveIntegerField()
    aturan_pakai = models.CharField(max_length=120)

    class Meta:
        verbose_name = "Item Resep"
        verbose_name_plural = "Item Resep"

    def __str__(self) -> str:
        return f"{self.obat.nama} x {self.jumlah}"
