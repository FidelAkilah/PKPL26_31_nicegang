from django.urls import path

from . import views

app_name = "hospital_app"

urlpatterns = [
    path("", views.landing, name="landing"),
    path("dashboard/", views.dashboard, name="dashboard"),

    # Pasien
    path("pasien/", views.pasien_list, name="pasien_list"),
    path("pasien/baru/", views.pasien_create, name="pasien_create"),
    path("pasien/<int:pk>/", views.pasien_detail, name="pasien_detail"),
    path("pasien/<int:pk>/edit/", views.pasien_edit, name="pasien_edit"),

    # Rekam Medis
    path("rekam-medis/", views.rekam_medis_list, name="rekam_medis_list"),
    path("rekam-medis/baru/", views.rekam_medis_create, name="rekam_medis_create"),
    path("rekam-medis/<int:pk>/", views.rekam_medis_detail, name="rekam_medis_detail"),
    path("rekam-medis/<int:pk>/edit/", views.rekam_medis_edit, name="rekam_medis_edit"),

    # Jadwal Dokter
    path("jadwal/", views.jadwal_list, name="jadwal_list"),
    path("jadwal/baru/", views.jadwal_create, name="jadwal_create"),

    # Resep
    path("resep/", views.resep_list, name="resep_list"),
    path("resep/baru/", views.resep_create, name="resep_create"),
    path("resep/<int:pk>/", views.resep_detail, name="resep_detail"),
    path("resep/<int:pk>/dispense/", views.resep_dispense, name="resep_dispense"),
]
