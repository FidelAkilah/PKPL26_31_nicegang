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

from .forms import PasienForm, RekamMedisForm
from .models import Dokter, Obat, Pasien, RekamMedis
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
