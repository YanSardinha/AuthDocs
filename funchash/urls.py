from django.contrib import admin
from django.urls import path, include
from .views import valida_assinatura_publica, assinar_documento, anexar_documento, validar_assinatura, index, inicio, criar_mensagem, lista_mensagens, validar_mensagem, lista_documentos

urlpatterns = [
    path('', index, name="index"),
    path('inicio/', inicio, name="inicio"),
    path('assinar_documento/', assinar_documento, name="assinar_documento"),
    path('anexar_documento/', anexar_documento, name='anexar_documento'),
    path('criar_mensagem/', criar_mensagem, name='criar_mensagem'),
    path('lista_mensagens/', lista_mensagens, name='lista_mensagens'),
    path('validar/<int:mensagem_id>/', validar_mensagem, name='validar_mensagem'),
    path('documentos/', lista_documentos, name='lista_documentos'),
    path('validar_assinatura/<int:documento_id>/', validar_assinatura, name='validar_assinatura'),
    path('valida_assinatura_publica/', valida_assinatura_publica, name='valida_assinatura_publica'),
]
