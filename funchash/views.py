from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Chaves
import hashlib
import os

def gera_chaves_hash():
    seed = os.urandom(16) 
    chave_privada = hashlib.sha256(seed).digest()
    chave_publica = hashlib.sha256(chave_privada).digest()

    return {
        'chave_publica': chave_publica.hex(),
        'chave_privada': chave_privada.hex()
    }

@login_required
def gerar_chaves(request):
    user = request.user
    chave_obj, created = Chaves.objects.get_or_create(user=user)

    if not chave_obj.chave_publica or not chave_obj.chave_privada:
        chaves = gera_chaves_hash()
        chave_obj.chave_publica = chaves['chave_publica']
        chave_obj.chave_privada = chaves['chave_privada']
        chave_obj.save()

    return render(
        request,
        template_name='hash/gerar_chaves.html',
        context={'chaves': chave_obj},
    )
