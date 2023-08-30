from django.contrib import admin
from .models import Chaves, Documento, Mensagem

@admin.register(Chaves)
class ChavesAdmin(admin.ModelAdmin):
    list_display = ('user', 'chave_publica', 'chave_privada')
    list_filter = list_display


@admin.register(Documento)
class DocumentoAdmin(admin.ModelAdmin):
    list_display = ('id','usuario', 'nome', 'assinatura', 'conteudo_hash', 'data_anexo','data_assinatura',)
    list_filter = ('usuario', 'nome', 'data_anexo', 'data_assinatura')

@admin.register(Mensagem)
class MensagemAdmin(admin.ModelAdmin):
    list_display = ('conteudo', 'assinatura')
    list_filter = list_display