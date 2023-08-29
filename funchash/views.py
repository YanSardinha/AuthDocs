from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Chaves, Documento
import hashlib
from .forms import DocumentoForm, ValidacaoAssinaturaForm
from .funcoes.gerar_chave import gera_chaves
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from django.contrib import messages
from django.contrib.auth import authenticate, login


def index(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('inicio')  
        else:
            messages.error(request, 'Credenciais inválidas. Por favor, tente novamente.')

    return render(request, 'base/index.html')

@login_required
def inicio(request):
    return render(request, template_name='base/inicio.html')

@login_required
def gerar_chaves(request):
    user = request.user
    chave_obj, created = Chaves.objects.get_or_create(user=user)

    if not chave_obj.chave_publica or not chave_obj.chave_privada:
        chaves = gera_chaves()
        chave_obj.chave_publica = chaves['chave_publica']
        chave_obj.chave_privada = chaves['chave_privada']
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
            return redirect('lista_documentos') 
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
        documento_id = request.POST.get('documento_id')

        chaves = Chaves.objects.get(user=request.user)
        chave_privada_pem = chaves.chave_privada.encode()
        chave_privada = serialization.load_pem_private_key(
            chave_privada_pem,
            password=None,
        )

        documento = Documento.objects.get(id=documento_id)

        with open(documento.arquivo.path, 'rb') as f:
            conteudo = f.read()
        conteudo_hash = hashes.Hash(hashes.SHA256())
        conteudo_hash.update(conteudo)
        dados_hash = conteudo_hash.finalize()

        assinatura = chave_privada.sign(
            dados_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        documento.assinatura = assinatura
        documento.conteudo_hash = dados_hash
        documento.save()

        return redirect('documento_assinado')


    documentos = Documento.objects.filter(usuario=request.user)
    return render(request, 'hash/assinar_documento.html', {'documentos': documentos})

@login_required
def validar_assinatura(request):
    if request.method == 'POST':
        documento_id = request.POST.get('documento_id')

        chaves = Chaves.objects.get(user=request.user)
        chave_publica_pem = chaves.chave_publica.encode()
        chave_publica = serialization.load_pem_public_key(chave_publica_pem)

        documento = Documento.objects.get(id=documento_id)

        try:
            chave_publica.verify(
                documento.assinatura,
                documento.conteudo_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            valido = True
        except:
            valido = False

        documentos = Documento.objects.filter(usuario=request.user)
        return render(request, 'hash/validar_assinatura.html', {'documentos': documentos, 'valido': valido})

    else:
        documentos = Documento.objects.filter(usuario=request.user)
        return render(request, 'hash/validar_assinatura.html', {'documentos': documentos})