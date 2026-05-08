from django.contrib import admin

from .models import Apoteker, Dokter, Obat, Pasien


@admin.register(Pasien)
class PasienAdmin(admin.ModelAdmin):
    list_display = ("nrm", "nama", "nik", "jenis_kelamin", "tanggal_lahir")
    search_fields = ("nrm", "nama", "nik")
    list_filter = ("jenis_kelamin",)


@admin.register(Dokter)
class DokterAdmin(admin.ModelAdmin):
    list_display = ("nip", "nama", "spesialisasi")
    search_fields = ("nip", "nama")


@admin.register(Apoteker)
class ApotekerAdmin(admin.ModelAdmin):
    list_display = ("nip", "nama")
    search_fields = ("nip", "nama")


@admin.register(Obat)
class ObatAdmin(admin.ModelAdmin):
    list_display = ("kode", "nama", "stok", "satuan", "harga")
    search_fields = ("kode", "nama")
