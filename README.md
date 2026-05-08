# PKPL Tugas 3 - Hospital Information System

**Kelompok 31 - nicegang**
**Pengantar Keamanan Perangkat Lunak - Genap 2025/2026**

Aplikasi rekam medis digital dengan implementasi *secure coding* terhadap empat
kelas serangan: SQL Injection, Code Injection (XSS/HTML/SSTI), Broken
Authentication, dan CSRF.

---

## 1. Deskripsi Aplikasi

**Skenario:** Hospital Information System (skenario nomor 1 di dokumen tugas).

**Fitur utama yang diimplementasikan:**
- Rekam medis pasien (create, search, detail, edit) - oleh Dokter
- Jadwal praktik dokter (read oleh semua role; manage oleh Admin)
- Resep obat (dibuat Dokter, dikeluarkan oleh Apoteker)
- Master data: Pasien, Dokter, Apoteker, Obat

**Role pengguna (least privilege):**
| Role | Dapat membaca | Dapat menulis |
|---|---|---|
| `DOKTER` | Pasien, Rekam Medis, Resep, Jadwal | Pasien (edit), Rekam Medis, Resep |
| `APOTEKER` | Pasien, Rekam Medis, Resep, Jadwal | Resep (dispense saja) |
| `PASIEN` | Profil sendiri | (read-only) |
| `ADMIN` | Semua | Semua + master data |

**Stack teknologi:**
- Python 3.12 + Django 5.1
- SQLite 3 (default Django)
- `django-axes` 6+ (rate limiting login)
- `bleach` 6+ (HTML sanitization)
- Frontend: HTML + CSS minimal (tanpa framework JS)

---

## 2. Implementasi Secure Coding

### 2.1 SQL Injection Prevention (CWE-89)

**Vulnerability:** *SQL Injection* terjadi ketika input pengguna disisipkan
mentah ke string SQL, sehingga payload seperti `' OR '1'='1' --` mengubah
makna query (login bypass, data dump via UNION SELECT, dll.).

**Mitigasi yang dipakai:**
1. **100% Django ORM** - semua akses DB lewat manager (`.filter()`, `.get()`,
   `.create()`). Django men-translate ini ke *parameterized queries* dengan
   placeholder `?`/`%s` di driver level.
2. **Tidak ada raw SQL** - tidak ada `cursor.execute("..." + var)`, tidak ada
   `Model.objects.raw(f"...")`. Diverifikasi via test `test_tc_sqli_03`.
3. **Validator allowlist** pada field identifier (NRM, NIK, kode obat) -
   hanya digit / huruf yang diperbolehkan.

**Vulnerable (contoh anti-pattern - TIDAK ada di kode kami):**
```python
def pasien_list(request):
    q = request.GET.get("q", "")
    # BAHAYA: string concatenation - SQL Injection terbuka!
    sql = f"SELECT * FROM hospital_app_pasien WHERE nrm LIKE '%{q}%'"
    cursor.execute(sql)
    return render(request, "list.html", {"rows": cursor.fetchall()})
```
Payload `'; DROP TABLE accounts_user; --` akan dieksekusi.

**Secure (yang digunakan):** [hospital_app/views.py](hospital_app/views.py#L48-L66)
```python
@role_required(Role.DOKTER, Role.APOTEKER, Role.ADMIN)
def pasien_list(request):
    q = (request.GET.get("q") or "").strip()
    pasien_qs = Pasien.objects.all()
    if q:
        # ORM .filter() => parameterized query, q diperlakukan sebagai literal.
        pasien_qs = pasien_qs.filter(
            Q(nrm__icontains=q) | Q(nama__icontains=q) | Q(nik__icontains=q)
        )
    ...
```
Payload `12345' OR '1'='1` di-bind sebagai string literal, query SQL hasilnya
`... WHERE nrm LIKE '%12345'' OR ''1''=''1%'` - tidak ada record cocok.

### 2.2 Code Injection (XSS / HTML / SSTI) (CWE-79, CWE-94)

**Vulnerability:** Payload HTML/JS/template tersimpan atau ter-reflect ke
respon dapat dieksekusi browser pengguna lain (mencuri cookie, hijack session).

**Mitigasi yang dipakai:**
1. **Django template autoescape** (default ON) - karakter `<>&"'` otomatis
   di-escape menjadi entity HTML.
2. **`bleach.clean(strip=True, tags=[])`** pada field free-text saat simpan -
   semua tag HTML di-strip jadi teks polos. Pertahanan berlapis.
3. **Tidak menggunakan `|safe` filter atau `mark_safe()`** pada konten dari
   input pengguna.
4. **Tidak ada `render_to_string` dengan template-string dari input pengguna** -
   sehingga SSTI (`{{7*7}}`) tidak mungkin terjadi.

**Vulnerable (anti-pattern - TIDAK ada di kode kami):**
```python
def detail(request, pk):
    rm = RekamMedis.objects.get(pk=pk)
    # BAHAYA: |safe membypass autoescape => XSS terbuka
    return HttpResponse(f"<div>Diagnosa: {rm.diagnosa}</div>")  # diagnosa = "<script>alert(1)</script>"
```

**Secure (yang digunakan):**

Form sanitization - [hospital_app/forms.py:60-66](hospital_app/forms.py#L60-L66):
```python
def clean_diagnosa(self) -> str:
    return _sanitize_text(self.cleaned_data["diagnosa"])

def _sanitize_text(value: str) -> str:
    return bleach.clean(value, tags=[], attributes={}, strip=True)
```

Template autoescape - [hospital_app/templates/hospital_app/rekam_medis_detail.html](hospital_app/templates/hospital_app/rekam_medis_detail.html):
```html
<tr><th>Diagnosa</th><td>{{ rm.diagnosa|linebreaksbr }}</td></tr>
```
Payload `<script>alert(1)</script>` ditampilkan sebagai
`&lt;script&gt;alert(1)&lt;/script&gt;` - browser melihatnya sebagai teks.

### 2.3 Broken Authentication Mitigation (CWE-256, 307, 613, 306, 204)

**Vulnerability gabungan:** plaintext password, brute force tanpa lockout,
session yang persist setelah logout, halaman terproteksi yang bocor tanpa
auth check, pesan error yang membocorkan keberadaan username.

**Mitigasi yang dipakai:**
1. **Hashing PBKDF2** (Django default) - [hospital/settings.py:78-83](hospital/settings.py#L78-L83).
   Saat user dibuat (`set_password()`), password disimpan sebagai
   `pbkdf2_sha256$<iterations>$<salt>$<hash>`.
2. **Rate limiting via `django-axes`** - lockout setelah 5 percobaan gagal
   dalam window 15 menit. Lockout berdasarkan kombinasi `username + ip_address`.
   [hospital/settings.py:107-112](hospital/settings.py#L107-L112).
3. **Session cycling** setelah login (`request.session.cycle_key()`) +
   `session.flush()` saat logout - mencegah session fixation & memastikan
   session token lama tidak bisa direplay.
4. **`@login_required` + `@role_required`** pada semua view non-publik.
5. **Pesan error generik:** `"Username atau password salah."` untuk semua
   gagal login - tidak membedakan "username tidak ada" vs "password salah".
   [accounts/forms.py:69-74](accounts/forms.py#L69-L74).

**Vulnerable (anti-pattern - TIDAK ada di kode kami):**
```python
def login(request):
    user = User.objects.filter(username=request.POST["username"]).first()
    if user is None:
        return render(request, "login.html", {"err": "User not found"})  # bocor!
    if user.password == request.POST["password"]:  # plaintext compare!
        ...
```

**Secure (yang digunakan):** [accounts/views.py:18-30](accounts/views.py#L18-L30)
```python
@require_http_methods(["GET", "POST"])
def login_view(request):
    form = StrictLoginForm(request, data=request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.get_user()
        login(request, user)               # PBKDF2 verify, session create
        request.session.cycle_key()        # rotate session ID (anti-fixation)
        return redirect("hospital_app:dashboard")
    return render(request, "accounts/login.html", {"form": form})
```

### 2.4 CSRF Protection (CWE-352)

**Vulnerability:** Halaman attacker dapat memicu request POST ke aplikasi
korban dengan cookie session korban yang masih aktif.

**Mitigasi yang dipakai:**
1. **`CsrfViewMiddleware`** aktif di [hospital/settings.py:46](hospital/settings.py#L46).
2. **`{% csrf_token %}`** pada semua form POST - menghasilkan hidden input
   `csrfmiddlewaretoken` yang divalidasi server. Token di-HMAC dengan
   `SECRET_KEY` + per-request mask, jadi attacker yang tidak punya secret
   tidak bisa forge token yang valid.
3. **`CSRF_COOKIE_SAMESITE = "Strict"`** - browser tidak mengirim cookie
   pada cross-origin POST. Defense in depth selain validasi token.
4. **`CSRF_COOKIE_HTTPONLY = False`** (sengaja) - token harus terbaca template
   tag, tapi tidak memberi keuntungan ke attacker karena setiap submit harus
   sesuai dengan masked token + secret server.
5. **Custom CSRF failure view** ([hospital_app/views.py:34-36](hospital_app/views.py#L34-L36)) -
   merespon HTTP 403 dengan halaman ramah.

**Vulnerable (anti-pattern - TIDAK ada di kode kami):**
```python
@csrf_exempt   # BAHAYA: nonaktifkan CSRF pada endpoint kritikal
def transfer_view(request):
    if request.method == "POST":
        ...do_transfer()...
```

**Secure (yang digunakan):** [hospital_app/templates/hospital_app/pasien_form.html:8](hospital_app/templates/hospital_app/pasien_form.html#L8)
```html
<form method="post" novalidate>
    {% csrf_token %}   <!-- token wajib, divalidasi server -->
    ...
</form>
```

---

## 3. Cara Menjalankan (Petunjuk Instalasi)

### Prasyarat
- Python 3.10+ (kami uji di 3.12)
- pip, virtualenv

### Langkah

```bash
# 1. Clone repo
git clone https://github.com/FidelAkilah/PKPL26_31_nicegang.git
cd PKPL26_31_nicegang

# 2. Buat virtual environment
python3.12 -m venv venv
# macOS/Linux:
source venv/bin/activate
# Windows (PowerShell):
# venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Migrasi database (SQLite akan dibuat otomatis sebagai db.sqlite3)
python manage.py migrate

# 5. Seed data demo (akun & master data)
python manage.py seed_demo

# 6. Jalankan server
python manage.py runserver
# Buka http://127.0.0.1:8000/
```

### Akun Demo

| Role     | Username  | Password         |
|----------|-----------|------------------|
| ADMIN    | admin     | Admin#Pkpl2026   |
| DOKTER   | dr.budi   | Dokter#Aman2026  |
| DOKTER   | dr.ani    | Dokter#Aman2026  |
| APOTEKER | apt.dewi  | Apoteker#Aman2026|
| PASIEN   | pasien1   | Pasien#Aman2026  |
| PASIEN   | pasien2   | Pasien#Aman2026  |

### Menjalankan Test Suite Keamanan

```bash
python manage.py test hospital_app.tests -v 2
```

Output yang diharapkan: `Ran 17 tests in ~3-4s OK`.

---

## 4. Hasil Test Case

### Test Case Generik (TC-*-01..05) - Status: PASS

| TC-ID | Nama | Status | Bukti |
|---|---|---|---|
| TC-SQLi-01 | Login Bypass via SQL Injection | PASS | `test_tc_sqli_01_login_bypass_blocked` |
| TC-SQLi-02 | Data Extraction via Search Input | PASS | `test_tc_sqli_02_union_select_blocked_in_search` |
| TC-SQLi-03 | Parameterized Query (white-box) | PASS | `test_tc_sqli_03_no_raw_sql_concatenation` |
| TC-CI-01  | Script Tag Injection | PASS | `test_tc_ci_01_script_tag_escaped` |
| TC-CI-02  | HTML Injection | PASS | `test_tc_ci_02_html_injection_escaped` |
| TC-CI-03  | Template Injection (SSTI) | PASS | `test_tc_ci_03_template_injection_not_evaluated` |
| TC-BA-01  | Password Hashing (white-box) | PASS | `test_tc_ba_01_password_is_hashed` |
| TC-BA-02  | Brute Force / Rate Limiting | PASS | `test_tc_ba_02_rate_limiting_after_failures` |
| TC-BA-03  | Session Token Invalidation | PASS | `test_tc_ba_03_session_invalidated_after_logout` |
| TC-BA-04  | Akses Halaman Terproteksi Tanpa Login | PASS | `test_tc_ba_04_protected_page_redirects_unauthenticated` |
| TC-BA-05  | Informasi Error Tidak Informatif | PASS | `test_tc_ba_05_generic_login_error_no_user_enumeration` |
| TC-CSRF-01| CSRF Token Presence on Forms | PASS | `test_tc_csrf_01_token_present_on_forms` |
| TC-CSRF-02| Request CSRF Token Invalid Ditolak | PASS | `test_tc_csrf_02_post_with_invalid_token_rejected` |
| TC-CSRF-03| Cross-Origin Request Tanpa Token | PASS | `test_tc_csrf_03_cross_origin_request_without_token_rejected` |

### Test Case Spesifik Hospital (TC-*-04a) - Status: PASS

| TC-ID | Nama | Status | Bukti |
|---|---|---|---|
| TC-SQLi-04a | Hospital: Pencarian Rekam Medis | PASS | `test_tc_sqli_04a_rekam_medis_search_safe` |
| TC-CI-04a   | Hospital: Nama Pasien / Catatan Dokter | PASS | `test_tc_ci_04a_payload_diagnosa_safe` |
| TC-CSRF-04a | Hospital: Form Ubah Data Pasien | PASS | `test_tc_csrf_04a_pasien_edit_requires_token` |

### Bukti Eksekusi Test (log)

```
$ python manage.py test hospital_app.tests -v 2
Found 17 test(s).
Creating test database for alias 'default'...
test_tc_ba_01_password_is_hashed (...) ... ok
test_tc_ba_02_rate_limiting_after_failures (...) ... ok
test_tc_ba_03_session_invalidated_after_logout (...) ... ok
test_tc_ba_04_protected_page_redirects_unauthenticated (...) ... ok
test_tc_ba_05_generic_login_error_no_user_enumeration (...) ... ok
test_tc_ci_01_script_tag_escaped (...) ... ok
test_tc_ci_02_html_injection_escaped (...) ... ok
test_tc_ci_03_template_injection_not_evaluated (...) ... ok
test_tc_ci_04a_payload_diagnosa_safe (...) ... ok
test_tc_csrf_01_token_present_on_forms (...) ... ok
test_tc_csrf_02_post_with_invalid_token_rejected (...) ... ok
test_tc_csrf_03_cross_origin_request_without_token_rejected (...) ... ok
test_tc_csrf_04a_pasien_edit_requires_token (...) ... ok
test_tc_sqli_01_login_bypass_blocked (...) ... ok
test_tc_sqli_02_union_select_blocked_in_search (...) ... ok
test_tc_sqli_03_no_raw_sql_concatenation (...) ... ok
test_tc_sqli_04a_rekam_medis_search_safe (...) ... ok
----------------------------------------------------------------------
Ran 17 tests in 3.785s

OK
```

---

## 5. Video Demo

> Link YouTube (Unlisted): _to be added before submission_

Video membahas:
1. Demo aplikasi secara fungsional (~2 menit) - login, search rekam medis,
   buat resep, dispense oleh apoteker.
2. Demonstrasi pengujian semua test case + hasilnya (~8 menit).
3. Penjelasan teknik mitigasi dan alasan pemilihan (~3 menit).

---

## 6. Struktur Branch (Git Workflow)

Repo dikembangkan dengan workflow feature-branch untuk traceability:

```
main
├── setup/init                  Project skeleton, settings keamanan
├── feature/auth-system         Login/Register/Logout, hashing, rate-limit, lockout
├── feature/master-data         Models Pasien/Dokter/Apoteker/Obat + seed
├── feature/rekam-medis         CRUD rekam medis + search aman
├── feature/jadwal-resep        Jadwal dokter + resep obat (dispense apoteker)
├── feature/security-tests      17 unit tests untuk semua TC
└── docs/readme                 Dokumentasi
```

Setiap branch di-merge ke `main` dengan `--no-ff` agar history tetap utuh.

---

## 7. Anggota Kelompok

Kelompok 31 - nicegang.

1. Fidel Akilah - 2406358636
2. Alderryl Juan Fauza - 240649550
3. I Gusti Ngurah Agung Airlangga Putra - 2406358794
4. Muhammad Hamiz Ghani Ayusha - 2406360413
---

## Lampiran: CWE yang Dimitigasi

- **CWE-89** - SQL Injection (TC-SQLi-*)
- **CWE-79** - Cross-site Scripting / Stored & Reflected XSS (TC-CI-01, TC-CI-02)
- **CWE-94** - Code Injection / Server-Side Template Injection (TC-CI-03)
- **CWE-256** - Plaintext Storage of a Password (TC-BA-01)
- **CWE-916** - Use of Password Hash with Insufficient Computational Effort (TC-BA-01)
- **CWE-307** - Improper Restriction of Excessive Authentication Attempts (TC-BA-02)
- **CWE-613** - Insufficient Session Expiration (TC-BA-03)
- **CWE-306** - Missing Authentication for Critical Function (TC-BA-04)
- **CWE-204** - Observable Response Discrepancy / User Enumeration (TC-BA-05)
- **CWE-352** - Cross-Site Request Forgery (TC-CSRF-*)
