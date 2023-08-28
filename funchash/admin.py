from django.contrib import admin
from .models import Chaves

class ChavesAdmin(admin.ModelAdmin):
    list_display = ('user', 'chave_publica', 'chave_privada')

admin.site.register(Chaves, ChavesAdmin)