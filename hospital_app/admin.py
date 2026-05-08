from django.contrib import admin

from .models import (
    Apoteker, Dokter, JadwalDokter, Obat, Pasien, Resep, ResepItem, RekamMedis,
)


class ResepItemInline(admin.TabularInline):
    model = ResepItem
    extra = 1


@admin.register(JadwalDokter)
class JadwalDokterAdmin(admin.ModelAdmin):
    list_display = ("dokter", "hari", "jam_mulai", "jam_selesai", "ruangan")
    list_filter = ("hari", "dokter")


@admin.register(RekamMedis)
class RekamMedisAdmin(admin.ModelAdmin):
    list_display = ("nomor", "tanggal", "pasien", "dokter")
    search_fields = ("nomor", "pasien__nrm", "pasien__nama")
    list_filter = ("tanggal",)


@admin.register(Resep)
class ResepAdmin(admin.ModelAdmin):
    list_display = ("nomor", "tanggal", "status", "dokter", "apoteker")
    list_filter = ("status", "tanggal")
    search_fields = ("nomor",)
    inlines = [ResepItemInline]


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
