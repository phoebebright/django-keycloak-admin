# Django Keycloak Admin

This is a fork of migueldb https://github.com/migelbd/django-admin-keycloak which is designed to replace the now unmaintained Peter Slump's version of django-keycloak.

While I understand the disire to keep things simple by maintaining the name django_keycloak in the app, it has caused me endless problems as I migrate my various applications - all self inflicted - like having the original library installed in one virtualenv and the new one in another and running conflicting migrations.

So I am renaming this fork django_keycloak_admin as I feel it is different enough that the small extra amount of work in renaming will make the migrations that many people are likely to do easier.



# Django Keycloak

A simple remote authentication module for use with Django and a Keycloak auth server.

Loosely based on Peter Slump's unmaintained `https://github.com/Peter-Slump/django-keycloak`. This updated version works with Keycloak v21.0, Django 5.0.0 and python-keycloak 4.0.0.

## Capabilities

It supports:

- OpenID authentication for logging into Django's admin interface
- Authentication for REST requests, using django-rest-framework

TODO: Support resource & role permissions

## Quickstart

1. Install via pip:
```bash
pip install django-keycloak-admin
```
2. Configure settings:
In your application's settings, add the following lines:
```python
# your-project/settings.py
INSTALLED_APPS = [
    ...
    'django_keycloak_admin'
]
# For admin site authentication
AUTHENTICATION_BACKENDS = [
    ...
    'django_keycloak_admin.backends.KeycloakAuthorizationCodeBackend',
]
AUTH_USER_MODEL = "django_keycloak_admin.KeycloakUser"  # Optional
KEYCLOAK_CLIENTS = {
    "DEFAULT": {
        "URL": ...,
        "REALM": "example-realm",
        "CLIENT_ID": "example-backend-client",
        "CLIENT_SECRET": "*************************",
    },
    # If you're using django's REST framework
    "API": {
        "URL": "http://localhost:8001",
        "REALM": "example-realm",
        "CLIENT_ID": "example-frontend-client",
        "CLIENT_SECRET": None,  # Typically a public client
    },
}

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'django_keycloak_admin.authentication.KeycloakDRFAuthentication',
    ]
}
```
3. Include URLs
Open your app's `urls.py` file, ad add the following:
```python
from django.contrib import admin
from django.urls import path, include
from django_keycloak_admin.views import admin_login

urlpatterns = [
    # This will override the default django login page
    path("admin/", include("django_keycloak_admin.urls")),
    path("admin/", admin.site.urls),
    ...
]
```
4. Migrate changes:
```bash
python manage.py migrate
```

## Roles and Permissions

Roles assigned on keycloak are represented as Django groups, so a user with an 'example' role on the keycloak server will be added to an 'example' group in the Django app. An administrator can configure permissions for the group in the Django admin site.

There is also a special 'superuser' role defined by `KEYCLOAK_ADMIN_ROLE` in settings (and defaulting to 'admin'). If users have this role, they are classified a Django superuser, with all permissions automatically assigned.

## Examples

An example application demonstrating this setup is included in the `examples` folder.


## Migrating from Peter Slump's version

If you're migrating from Peter Slump's version, you'll need to make the following changes that require some manual deletions from the database:

- remove previously keycloak settings and replace with new ones.  Note that the middleware is no longer required.
- delete all the tables that begin django_keycloak.  They have either been replaced by settings or do not require to be populated.
- remove the entries for django_keycloak in the django_migrations table
- run `python manage.py migrate` to create the new tables.
