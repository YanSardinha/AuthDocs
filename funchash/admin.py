from django.contrib import admin
from .models import Chaves, Documento


class ChavesAdmin(admin.ModelAdmin):
    list_display = ('user', 'chave_publica', 'chave_privada')

admin.site.register(Chaves, ChavesAdmin)

@admin.register(Documento)
class DocumentoAdmin(admin.ModelAdmin):
    list_display = ('id','usuario', 'arquivo', 'assinatura', 'conteudo_hash')
    list_filter = ('usuario',)