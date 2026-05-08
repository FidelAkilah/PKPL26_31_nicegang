"""Views Hospital Information System.

Mitigasi yang diterapkan:
- SQL Injection (CWE-89): semua query memakai ORM .filter() / parameterized.
- XSS (CWE-79): Django autoescape ON + sanitisasi bleach pada form.
- CSRF (CWE-352): semua POST proteced via {% csrf_token %} + CsrfViewMiddleware.
- Broken Auth (CWE-306): @login_required + role_required.
"""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render

from accounts.models import Role

from .forms import (
    JadwalDokterForm, PasienForm, RekamMedisForm, ResepForm, ResepItemFormSet,
)
from .models import (
    Apoteker, Dokter, JadwalDokter, Obat, Pasien, RekamMedis, Resep,
)
from .permissions import role_required


def landing(request):
    return render(request, "hospital_app/landing.html")


@login_required
def dashboard(request):
    counts = {
        "pasien": Pasien.objects.count(),
        "dokter": Dokter.objects.count(),
        "obat": Obat.objects.count(),
        "rekam_medis": RekamMedis.objects.count(),
    }
    return render(request, "hospital_app/dashboard.html", {"counts": counts})


def csrf_failure(request, reason=""):
    """Custom 403 page untuk CSRF failure (TC-CSRF-02 / CWE-352)."""
    return render(request, "403_csrf.html", {"reason": reason}, status=403)


# --- Pasien ---------------------------------------------------------------

@role_required(Role.DOKTER, Role.APOTEKER, Role.ADMIN)
def pasien_list(request):
    """List + pencarian pasien.

    PENTING (TC-SQLi-04a / CWE-89): query parameter 'q' DIJADIKAN ARGUMEN
    .filter() pada ORM, bukan di-concat ke string SQL. Django men-translate
    ini ke parameterized query, sehingga payload "12345' OR '1'='1" diperlakukan
    sebagai literal string, bukan SQL fragment.
    """
    q = (request.GET.get("q") or "").strip()
    pasien_qs = Pasien.objects.all()
    if q:
        pasien_qs = pasien_qs.filter(
            Q(nrm__icontains=q) | Q(nama__icontains=q) | Q(nik__icontains=q)
        )

    paginator = Paginator(pasien_qs, 20)
    page_obj = paginator.get_page(request.GET.get("page"))

    return render(request, "hospital_app/pasien_list.html", {
        "page_obj": page_obj,
        "q": q,
    })


@role_required(Role.DOKTER, Role.APOTEKER, Role.ADMIN)
def pasien_detail(request, pk: int):
    pasien = get_object_or_404(Pasien, pk=pk)
    rekam = pasien.rekam_medis.select_related("dokter").all()[:50]
    return render(request, "hospital_app/pasien_detail.html", {
        "pasien": pasien, "rekam_list": rekam,
    })


@role_required(Role.DOKTER, Role.ADMIN)
def pasien_edit(request, pk: int):
    """Edit data pasien (TC-CSRF-04a). CSRF wajib pada POST."""
    pasien = get_object_or_404(Pasien, pk=pk)
    form = PasienForm(request.POST or None, instance=pasien)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Data pasien berhasil diperbarui.")
        return redirect("hospital_app:pasien_detail", pk=pasien.pk)
    return render(request, "hospital_app/pasien_form.html", {
        "form": form, "pasien": pasien, "mode": "edit",
    })


@role_required(Role.DOKTER, Role.ADMIN)
def pasien_create(request):
    form = PasienForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        pasien = form.save()
        messages.success(request, "Pasien baru berhasil ditambahkan.")
        return redirect("hospital_app:pasien_detail", pk=pasien.pk)
    return render(request, "hospital_app/pasien_form.html", {
        "form": form, "mode": "create",
    })


# --- Rekam Medis ----------------------------------------------------------

@role_required(Role.DOKTER, Role.APOTEKER, Role.ADMIN)
def rekam_medis_list(request):
    q = (request.GET.get("q") or "").strip()
    rm_qs = RekamMedis.objects.select_related("pasien", "dokter").all()
    if q:
        # ORM filter - parameterized (CWE-89 mitigation).
        rm_qs = rm_qs.filter(
            Q(nomor__icontains=q)
            | Q(pasien__nrm__icontains=q)
            | Q(pasien__nama__icontains=q)
        )
    paginator = Paginator(rm_qs, 20)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(request, "hospital_app/rekam_medis_list.html", {
        "page_obj": page_obj, "q": q,
    })


@role_required(Role.DOKTER, Role.APOTEKER, Role.ADMIN)
def rekam_medis_detail(request, pk: int):
    rm = get_object_or_404(
        RekamMedis.objects.select_related("pasien", "dokter"),
        pk=pk,
    )
    return render(request, "hospital_app/rekam_medis_detail.html", {"rm": rm})


@role_required(Role.DOKTER, Role.ADMIN)
def rekam_medis_create(request):
    form = RekamMedisForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        rm = form.save()
        messages.success(request, "Rekam medis berhasil dibuat.")
        return redirect("hospital_app:rekam_medis_detail", pk=rm.pk)
    return render(request, "hospital_app/rekam_medis_form.html", {
        "form": form, "mode": "create",
    })


@role_required(Role.DOKTER, Role.ADMIN)
def rekam_medis_edit(request, pk: int):
    rm = get_object_or_404(RekamMedis, pk=pk)
    form = RekamMedisForm(request.POST or None, instance=rm)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Rekam medis berhasil diperbarui.")
        return redirect("hospital_app:rekam_medis_detail", pk=rm.pk)
    return render(request, "hospital_app/rekam_medis_form.html", {
        "form": form, "rm": rm, "mode": "edit",
    })


# --- Jadwal Dokter --------------------------------------------------------

@login_required
def jadwal_list(request):
    """List jadwal dokter - bisa diakses semua role yang login."""
    jadwal = JadwalDokter.objects.select_related("dokter").all()
    return render(request, "hospital_app/jadwal_list.html", {"jadwal_list": jadwal})


@role_required(Role.ADMIN)
def jadwal_create(request):
    form = JadwalDokterForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Jadwal berhasil ditambahkan.")
        return redirect("hospital_app:jadwal_list")
    return render(request, "hospital_app/jadwal_form.html", {"form": form, "mode": "create"})


# --- Resep Obat -----------------------------------------------------------

@role_required(Role.DOKTER, Role.APOTEKER, Role.ADMIN)
def resep_list(request):
    q = (request.GET.get("q") or "").strip()
    qs = Resep.objects.select_related("dokter", "apoteker", "rekam_medis__pasien").all()
    if q:
        # ORM filter (CWE-89 mitigation).
        qs = qs.filter(
            Q(nomor__icontains=q) | Q(rekam_medis__pasien__nrm__icontains=q)
        )
    paginator = Paginator(qs, 20)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(request, "hospital_app/resep_list.html", {"page_obj": page_obj, "q": q})


@role_required(Role.DOKTER, Role.ADMIN)
def resep_create(request):
    form = ResepForm(request.POST or None)
    formset = ResepItemFormSet(request.POST or None, prefix="items")
    if request.method == "POST" and form.is_valid() and formset.is_valid():
        resep = form.save()
        formset.instance = resep
        formset.save()
        messages.success(request, "Resep berhasil dibuat.")
        return redirect("hospital_app:resep_detail", pk=resep.pk)
    return render(request, "hospital_app/resep_form.html", {
        "form": form, "formset": formset, "mode": "create",
    })


@role_required(Role.DOKTER, Role.APOTEKER, Role.ADMIN)
def resep_detail(request, pk: int):
    resep = get_object_or_404(
        Resep.objects.select_related("dokter", "apoteker", "rekam_medis__pasien"),
        pk=pk,
    )
    return render(request, "hospital_app/resep_detail.html", {"resep": resep})


@role_required(Role.APOTEKER, Role.ADMIN)
def resep_dispense(request, pk: int):
    """Apoteker mengeluarkan obat sesuai resep (mengubah status -> DIKELUARKAN).

    POST-only + CSRF-protected (TC-CSRF-* / CWE-352).
    """
    if request.method != "POST":
        return redirect("hospital_app:resep_detail", pk=pk)

    resep = get_object_or_404(Resep, pk=pk)
    if resep.status != "DRAFT":
        messages.error(request, "Resep ini sudah tidak bisa diproses.")
        return redirect("hospital_app:resep_detail", pk=pk)

    apoteker = Apoteker.objects.filter(user=request.user).first()
    if apoteker is None and not request.user.is_superuser:
        messages.error(request, "Profil apoteker tidak ditemukan.")
        return redirect("hospital_app:resep_detail", pk=pk)

    resep.status = "DIKELUARKAN"
    resep.apoteker = apoteker
    resep.save(update_fields=["status", "apoteker", "updated_at"])
    messages.success(request, f"Resep {resep.nomor} telah dikeluarkan.")
    return redirect("hospital_app:resep_detail", pk=pk)
