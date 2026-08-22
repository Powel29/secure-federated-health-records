from __future__ import annotations

from django.contrib import admin

from accounts.models import Profile, RegistrationRequest

admin.site.register(Profile)
admin.site.register(RegistrationRequest)
