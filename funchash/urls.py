from django.contrib import admin
from django.urls import path, include
from .views import gerar_chaves, assinar_documento, anexar_documento, validar_assinatura

urlpatterns = [
    path('gerar_chave/', gerar_chaves, name="gerar_chaves"),
    path('assinar_documento/', assinar_documento, name="assinar_documento"),
    path('anexar_documento/', anexar_documento, name='anexar_documento'),
    path('validar_assinatura/', validar_assinatura, name='validar_assinatura'),
]
