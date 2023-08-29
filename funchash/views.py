from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Chaves, Documento
import hashlib
from .forms import DocumentoForm, ValidacaoAssinaturaForm
from .funcoes.gerar_chave import gera_chaves
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


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
    documentos = Documento.objects.filter(usuario=request.user)
    
    if request.method == 'POST':
        documento_id = request.POST.get('documento')
        documento = Documento.objects.get(id=documento_id)
        
        if documento:
            # Carregar a chave privada PEM do usuário
            private_key_pem = request.user.chaves.chave_privada
            chave_privada = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None
            )

            # Ler o conteúdo do documento e calcular o hash
            conteudo = documento.arquivo.read()
            conteudo_hash = hashlib.sha256(conteudo).digest()

            # Assinar o hash do conteúdo com as informações do usuário
            assinatura = assina_dados(conteudo_hash, chave_privada, request.user)

            # Salvar a assinatura no documento
            documento.assinatura = assinatura
            documento.save()

            return redirect('lista_documentos')  # Redirecionar para a lista de documentos

    return render(
        request,
        template_name='hash/assinar_documento.html',
        context={'documentos': documentos},
    )

def assina_dados(dados, chave_privada, usuario):
    dados_assinatura = f"{usuario.username}:".encode('utf-8') + dados
    assinatura = chave_privada.sign(
        dados_assinatura,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return assinatura


def valida_assinatura(documento, usuario):
    chave_publica_pem = usuario.chaves.chave_publica.encode('utf-8')
    chave_publica = serialization.load_pem_public_key(chave_publica_pem)

    conteudo = documento.arquivo.read()
    conteudo_hash = hashlib.sha256(conteudo).digest()

    assinatura = documento.assinatura

    try:
        chave_publica.verify(
            assinatura,
            conteudo_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Erro de verificação: {e}")
        return False


@login_required
def validar_assinatura(request):
    usuario = request.user
    mensagem = None

    if request.method == 'POST':
        form = ValidacaoAssinaturaForm(request.user, request.POST)
        if form.is_valid():
            documento = form.cleaned_data['documento']
            if valida_assinatura(documento, usuario):
                mensagem = 'Assinatura válida!'
            else:
                mensagem = 'Assinatura inválida!'
    else:
        form = ValidacaoAssinaturaForm(request.user)

    return render(
        request,
        template_name='hash/validar_assinatura.html',
        context={'form': form, 'mensagem': mensagem},
    )
