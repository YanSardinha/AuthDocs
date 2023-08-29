from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Chaves, Documento, Mensagem
from .forms import DocumentoForm, ValidacaoAssinaturaForm, MensagemForm
from .funcoes.gerar_chave import gera_chaves
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from django.contrib import messages
from django.contrib.auth import authenticate, login
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key


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
    

@login_required
def criar_mensagem(request):
    if request.method == 'POST':
        form = MensagemForm(request.POST)
        if form.is_valid():
            mensagem = form.save(commit=False)
            mensagem.user = request.user

            # Obtém as chaves do usuário logado
            chaves = Chaves.objects.get(user=request.user)

            # Carrega a chave privada do usuário
            chave_privada = serialization.load_pem_private_key(
                chaves.chave_privada.encode(),
                password=None,
                backend=default_backend()
            )

            # Gera o hash do conteúdo da mensagem
            conteudo = mensagem.conteudo.encode('utf-8')
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(conteudo)
            hash_conteudo = digest.finalize()

            # Assina o hash do conteúdo com a chave privada
            assinatura = chave_privada.sign(
                hash_conteudo,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Converte a assinatura para uma representação em hexadecimal
            assinatura_hex = assinatura.hex()

            mensagem.assinatura = assinatura_hex
            mensagem.save()

            return redirect('mensagem/lista_mensagens')
    else:
        form = MensagemForm()
    
    return render(request, 'mensagem/criar_mensagem.html', {'form': form})

def lista_mensagens(request):
    mensagens = Mensagem.objects.all()
    return render(request, 'mensagem/lista_mensagem.html', {'mensagens': mensagens})

@login_required
def validar_mensagem(request, mensagem_id):
    mensagem = get_object_or_404(Mensagem, pk=mensagem_id)

    try:
        chaves = Chaves.objects.get(user=request.user)

        chave_publica = load_pem_public_key(
            chaves.chave_publica.encode(),
            backend=default_backend()
        )

        assinatura = bytes.fromhex(mensagem.assinatura)

        conteudo = mensagem.conteudo.encode('utf-8')
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(conteudo)
        hash_conteudo = digest.finalize()

        try:
            chave_publica.verify(
                assinatura,
                hash_conteudo,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            valid = True
        except InvalidSignature:
            valid = False
    except Chaves.DoesNotExist:
        valid = False
    
    return render(request, 'mensagem/validar_mensagem.html', {'mensagem': mensagem, 'valid': valid})
