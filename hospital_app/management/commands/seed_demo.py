"""Management command untuk men-seed data demo.

Jalankan: python manage.py seed_demo

Membuat akun demo untuk semua role (untuk testing test cases) dan
beberapa entri master data minimal.
"""

from datetime import date

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction

from accounts.models import Role
from hospital_app.models import Apoteker, Dokter, Obat, Pasien

User = get_user_model()


# Akun demo. Password sengaja didefinisikan di sini untuk kemudahan testing -
# di production, password dihasilkan random / di-set saat onboarding.
DEMO_USERS = [
    # username, password, role, full_name, email
    ("admin", "Admin#Pkpl2026", Role.ADMIN, "Administrator Sistem", "admin@hospital.local"),
    ("dr.budi", "Dokter#Aman2026", Role.DOKTER, "Budi Santoso", "budi@hospital.local"),
    ("dr.ani", "Dokter#Aman2026", Role.DOKTER, "Ani Lestari", "ani@hospital.local"),
    ("apt.dewi", "Apoteker#Aman2026", Role.APOTEKER, "Dewi Pratiwi", "dewi@hospital.local"),
    ("pasien1", "Pasien#Aman2026", Role.PASIEN, "Citra Hapsari", "citra@example.com"),
    ("pasien2", "Pasien#Aman2026", Role.PASIEN, "Eko Prasetyo", "eko@example.com"),
]


class Command(BaseCommand):
    help = "Seed database dengan data demo untuk testing."

    @transaction.atomic
    def handle(self, *args, **options):
        # Akun
        users = {}
        for username, password, role, full_name, email in DEMO_USERS:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={"role": role, "full_name": full_name, "email": email},
            )
            user.role = role
            user.full_name = full_name
            user.email = email
            if role == Role.ADMIN:
                user.is_staff = True
                user.is_superuser = True
            # set_password() melakukan hashing PBKDF2 - tidak ada plaintext.
            user.set_password(password)
            user.save()
            users[username] = user
            self.stdout.write(f"  user: {username} ({role}) {'created' if created else 'updated'}")

        # Profil dokter
        for username, _, role, full_name, _ in DEMO_USERS:
            if role == Role.DOKTER:
                Dokter.objects.update_or_create(
                    user=users[username],
                    defaults={
                        "nip": f"NIP-{username.upper().replace('.', '')}",
                        "nama": full_name,
                        "spesialisasi": "Umum" if username == "dr.budi" else "Anak",
                        "no_telepon": "+628123456789",
                    },
                )
            elif role == Role.APOTEKER:
                Apoteker.objects.update_or_create(
                    user=users[username],
                    defaults={
                        "nip": f"APT-{username.upper().replace('.', '')}",
                        "nama": full_name,
                    },
                )
            elif role == Role.PASIEN:
                idx = list(users).index(username) - 4  # offset
                nrm = f"{10000000 + idx:08d}"
                nik = f"{3201010101800000 + idx:016d}"
                Pasien.objects.update_or_create(
                    user=users[username],
                    defaults={
                        "nrm": nrm,
                        "nik": nik,
                        "nama": full_name,
                        "tanggal_lahir": date(1990, 1, 1 + idx),
                        "jenis_kelamin": "P" if idx % 2 == 0 else "L",
                        "no_telepon": "+62812345670" + str(idx),
                        "alamat": "Jl. Demo No. " + str(idx + 1),
                    },
                )

        # Master obat
        obat_data = [
            ("PCT-500", "Paracetamol 500mg", "tablet", 500, 1500),
            ("AMOX-250", "Amoxicillin 250mg", "kapsul", 200, 2500),
            ("ORS-200", "Oralit 200ml", "sachet", 100, 3000),
            ("VITC-500", "Vitamin C 500mg", "tablet", 300, 1000),
        ]
        for kode, nama, satuan, stok, harga in obat_data:
            Obat.objects.update_or_create(
                kode=kode,
                defaults={"nama": nama, "satuan": satuan, "stok": stok, "harga": harga},
            )
            self.stdout.write(f"  obat: {kode} - {nama}")

        self.stdout.write(self.style.SUCCESS("Seed data demo berhasil."))
        self.stdout.write("")
        self.stdout.write("Akun demo:")
        for username, password, role, *_ in DEMO_USERS:
            self.stdout.write(f"  {role:8s}  {username:12s}  {password}")
