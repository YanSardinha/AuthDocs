from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Chaves, Documento
import hashlib
from .forms import DocumentoForm


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


@login_required
def anexar_documento(request):
    if request.method == 'POST':
        form = DocumentoForm(request.POST, request.FILES)
        if form.is_valid():
            documento = form.save(commit=False)
            documento.usuario = request.user
            documento.save()
            return redirect('lista_documentos')  # Redirecione para a lista de documentos
    else:
        form = DocumentoForm()

    return render(
        request,
        template_name='hash/anexar_documento.html',
        context={'form': form},
    )


@login_required
def assinar_documento(request):
    if request.method == 'POST':
        arquivo = request.FILES.get('arquivo')
        if arquivo:
            conteudo = arquivo.read()
            assinatura = hashlib.sha256(conteudo).hexdigest()
            documento = Documento(usuario=request.user, arquivo=arquivo, assinatura=assinatura)
            documento.save()

            return redirect('lista_documentos')

    return render(
        request,
        template_name='hash/assinar_documento.html',
        context={},
    )