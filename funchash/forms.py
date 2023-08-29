from django import forms
from .models import Documento, Mensagem

class DocumentoForm(forms.ModelForm):
    class Meta:
        model = Documento
        fields = ('arquivo',)


class ValidacaoAssinaturaForm(forms.Form):
    documento = forms.ModelChoiceField(
        queryset=Documento.objects.none(),
        label='Documento',
        widget=forms.Select(attrs={'class': 'form-control'}),
    )

    def __init__(self, user, *args, **kwargs):
        super(ValidacaoAssinaturaForm, self).__init__(*args, **kwargs)
        self.fields['documento'].queryset = Documento.objects.filter(usuario=user)


class MensagemForm(forms.ModelForm):
    class Meta:
        model = Mensagem
        fields = ['conteudo']
