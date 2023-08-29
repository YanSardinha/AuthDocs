# Generated by Django 4.2.4 on 2023-08-29 02:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('funchash', '0003_documento'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='documento',
            name='conteudo',
        ),
        migrations.AddField(
            model_name='documento',
            name='arquivo',
            field=models.FileField(default=1, upload_to='documentos/'),
            preserve_default=False,
        ),
    ]