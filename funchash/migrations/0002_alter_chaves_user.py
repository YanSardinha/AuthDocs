<<<<<<< HEAD
# Generated by Django 4.2.4 on 2023-08-29 02:05
=======
# Generated by Django 4.2.4 on 2023-08-28 11:29
>>>>>>> e6bfd462391861b0b4e42a206f0d149bf5dfe2fe

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('funchash', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='chaves',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
