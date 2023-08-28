from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Chaves

@login_required
def gerar_chaves(request):
    user = request.user
    chave_obj, created = Chaves.objects.get_or_create(user=user)

    if not chave_obj.chave_publica or not chave_obj.chave_privada:
        chave_obj.chave_publica = "sua_chave_publica_aqui"
        chave_obj.chave_privada = "sua_chave_privada_aqui"
        chave_obj.save()

    return render(
        request,
        template_name='hash/gerar_chaves.html',
        context={'chaves': chave_obj},
    )
