from django.db import models
from django.contrib.auth.models import User


class Chaves(models.Model):
    chave_publica = models.TextField()
    chave_privada = models.TextField()

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        null=False,
        blank=False,
    )

class Documento(models.Model):
    usuario = models.ForeignKey(User, on_delete=models.CASCADE)
    arquivo = models.FileField(upload_to='documentos/')
    assinatura = models.TextField(null=True, blank=True)
    conteudo_hash = models.BinaryField(null=True, blank=True)


class Mensagem(models.Model):
    conteudo = models.TextField()
    assinatura = models.CharField(max_length=200)

    def __str__(self):
        return self.conteudo
