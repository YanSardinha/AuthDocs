from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import authenticate, login
from .models import Chaves, Documento, Mensagem
from .forms import DocumentoForm, MensagemForm
from .funcoes.gerar_chave import gera_chaves
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from django.http import JsonResponse
import datetime
from django.db.models import Q
from django.contrib.auth.models import User

def index(request):
    print('oi')
    if request.method == 'POST':
        print('oi',request.method)
        if 'login' in request.POST:
          username = request.POST['username']
          password = request.POST['password']
          user = authenticate(request, username=username, password=password)
          
          if user is not None:
              login(request, user)
              return redirect('inicio')
          else:
              messages.error(request, 'Credenciais inválidas. Por favor, tente novamente.')
        elif 'register' in request.POST:
            username = request.POST['username']
            password = request.POST['password']
            email = request.POST['email']

            if User.objects.filter(username=username).exists():
                messages.error(request, 'Este nome de usuário já está em uso. Por favor, escolha outro.')
            elif User.objects.filter(email=email).exists():
                messages.error(request, 'Este e-mail já está em uso. Por favor, escolha outro.')
            else:
                user = User.objects.create_user(username=username, email=email, password=password)
                user.save()
                login(request, user)
                return redirect('inicio')
    else:
      print('out',request.method)

    return render(request, 'base/index.html')

def valida_assinatura_publica(request):
    if request.method == 'POST':
        received_signature = request.POST.get('signature')  # Supondo que a assinatura é passada como parâmetro POST 'signature'

        if received_signature:
            documentos = Documento.objects.all()

            for documento in documentos:
                chave_publica_pem = documento.usuario.chaves.chave_publica.encode('utf-8')
                chave_publica = serialization.load_pem_public_key(
                    chave_publica_pem,
                    backend=default_backend()
                )

                try:
                    received_signature_bytes = bytes.fromhex(received_signature)  # Converta a string hexadecimal de volta para bytes
                    chave_publica.verify(
                        received_signature_bytes,
                        documento.conteudo_hash,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    return JsonResponse({'status': f'Assinatura válida para o usuário {documento.usuario.username}.'})

                except Exception as e:
                    pass

            return JsonResponse({'status': 'Assinatura inválida para todos os usuários.'})

        else:
            return JsonResponse({'status': 'Assinatura não fornecida.'})

    return JsonResponse({'status': 'Método não permitido.'})

@login_required
def inicio(request):
    user = request.user
    chave_obj, created = Chaves.objects.get_or_create(user=user)

    if not chave_obj.chave_publica or not chave_obj.chave_privada:
        chaves = gera_chaves()
        chave_obj.chave_publica = chaves['chave_publica']
        chave_obj.chave_privada = chaves['chave_privada']
        chave_obj.save()

    documentos = Documento.objects.all().order_by('-data_anexo')
    user_documentos = Documento.objects.filter(
        Q(usuario=request.user) & (Q(data_assinatura__isnull=True) | Q(data_assinatura__isnull=False))
    ).order_by('-data_assinatura')
    chaves_usuario = Chaves.objects.get(user=request.user)
    return render(request, template_name='base/inicio.html', context={'documentos':documentos, 'user_documentos': user_documentos, 'chaves_usuario': chaves_usuario})


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
    try:
        chaves = Chaves.objects.get(user=request.user)
    except Chaves.DoesNotExist:
        chaves = None

    if request.method == 'POST':
        if chaves is None:
            mensagem = "Você ainda não possui chaves públicas ou privadas."
        else:
            documento_id = request.POST.get('documento_id')

            chave_privada_pem = chaves.chave_privada.encode()
            chave_privada = serialization.load_pem_private_key(
                chave_privada_pem,
                password=None,
            )

            documento = Documento.objects.get(id=documento_id)

            nome_usuario = request.user.username
            email_usuario = request.user.email

            conteudo_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            conteudo_hash.update(f"{nome_usuario}{email_usuario}".encode('utf-8'))
            dados_hash = conteudo_hash.finalize()

            assinatura = chave_privada.sign(
                dados_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            documento.assinatura = assinatura.hex()  # Armazena a assinatura como string hexadecimal
            documento.conteudo_hash = dados_hash
            documento.data_assinatura = datetime.datetime.now()
            documento.save()

            return redirect('documento_assinado')

    documentos = Documento.objects.filter(usuario=request.user)
    return render(request, 'hash/assinar_documento.html', {'documentos': documentos, 'chaves': chaves})



@login_required
def validar_assinatura(request, documento_id):
    documento = get_object_or_404(Documento, pk=documento_id)

    try:
        chaves = Chaves.objects.get(user=request.user)
    except Chaves.DoesNotExist:
        chaves = None

    mensagem = ""
    valid = False

    if chaves is None:
        mensagem = "Você ainda não possui chaves públicas ou privadas."
    else:
        try:
            chave_publica = serialization.load_pem_public_key(
                chaves.chave_publica.encode(),
                backend=default_backend()
            )

            nome_usuario = request.user.username
            email_usuario = request.user.email

            conteudo_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            conteudo_hash.update(f"{nome_usuario}{email_usuario}".encode('utf-8'))
            hash_nome_email = conteudo_hash.finalize()

            assinatura_hex = documento.assinatura  # Certifique-se de que a assinatura está armazenada como string hexadecimal
            assinatura = bytes.fromhex(assinatura_hex)

            try:
                chave_publica.verify(
                    assinatura,
                    hash_nome_email,  # Usar o hash do nome de usuário e email
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                valid = True
            except InvalidSignature:
                valid = False
        except Exception as e:
            mensagem = f"Erro ao verificar a assinatura: {e}"

    return render(request, 'hash/validar_assinatura.html', {'documento': documento, 'valid': valid, 'mensagem': mensagem})



def lista_documentos(request):
    documentos = Documento.objects.all()  # Alterado aqui
    return render(request, 'hash/lista_documentos.html', {'documentos': documentos})



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

        chave_publica = serialization.load_pem_public_key(
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


