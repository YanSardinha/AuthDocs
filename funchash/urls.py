from django.contrib import admin
from django.urls import path, include
from .views import gerar_chaves, assinar_documento, anexar_documento, validar_assinatura, index, inicio, criar_mensagem, lista_mensagens, validar_mensagem

urlpatterns = [
    path('', index, name="index"),
    path('inicio/', inicio, name="inicio"),
    path('gerar_chave/', gerar_chaves, name="gerar_chaves"),
    path('assinar_documento/', assinar_documento, name="assinar_documento"),
    path('anexar_documento/', anexar_documento, name='anexar_documento'),
    path('validar_assinatura/', validar_assinatura, name='validar_assinatura'),
    path('criar_mensagem/', criar_mensagem, name='criar_mensagem'),
    path('lista_mensagens/', lista_mensagens, name='lista_mensagens'),
    path('validar/<int:mensagem_id>/', validar_mensagem, name='validar_mensagem'),
]
