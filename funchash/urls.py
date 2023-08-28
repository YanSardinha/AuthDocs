from django.contrib import admin
from django.urls import path, include
from .views import gerar_chaves

urlpatterns = [
    path('gerar_chave/', gerar_chaves, name="gerar_chaves"),
]
