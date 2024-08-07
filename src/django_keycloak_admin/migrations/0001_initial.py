# Generated by Django 5.0.6 on 2024-06-26 07:29

import django.contrib.auth.models
import django.contrib.auth.validators
import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='Nonce',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('state', models.UUIDField(default=uuid.uuid4, unique=True)),
                ('redirect_uri', models.CharField(max_length=255)),
                ('next_path', models.CharField(max_length=255, null=True)),
            ],
        ),

        migrations.CreateModel(
            name='OpenIdConnectProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('auth_time', models.DateTimeField()),
                ('expires_before', models.DateTimeField()),
                ('access_token', models.TextField(null=True)),
                ('refresh_token', models.TextField(null=True)),
                ('refresh_expires_before', models.DateTimeField(null=True)),
                ('sub', models.CharField(max_length=255, unique=True)),
                ('client_id', models.CharField(max_length=100)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='oidc_profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
