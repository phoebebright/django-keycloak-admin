import logging

from django.shortcuts import resolve_url
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.http.response import (
    HttpResponseBadRequest,
    HttpResponseServerError,
    HttpResponseRedirect
)
from django.urls.base import reverse
from keycloak.exceptions import KeycloakConnectionError
from django.views.generic.base import RedirectView

from .models import Nonce, DEFAULT_CLIENT


logger = logging.getLogger(__name__)


class Login(RedirectView):
    """Login View."""

    def has_admin_permission(self, request):
        """Check whether the user can access the admin site."""
        return request.user.is_active and request.user.is_staff

    def get_redirect_url(self, *args, **kwargs):
        """Redirects to the OIDC authorization URL."""
        # If the user is already authenticated there's no need to
        # refer them to keycloak
        if self.request.user.is_authenticated:
            next_path = self.request.GET.get("next")
            if self.has_admin_permission(self.request):
                return next_path or "/"
            # Want to prevent an infinite loop, if the user has been authenticated
            # but is not a staff user they will bounce back between the admin page
            # which redirects them to login because they can't view it, which
            # succeeds because they're logged into the session, which directs them back
            # to the admin page.
            # TODO: Should warn the user that they're about to be logged out
            return f'{reverse("keycloak_logout")}?next={next_path}'
        nonce = Nonce.objects.create(
            redirect_uri=self.request.build_absolute_uri(
                location=reverse("keycloak_login_complete")
            ),
            next_path=self.request.GET.get("next"),
        )
        self.request.session["oidc_state"] = str(nonce.state)
        try:
            authorization_url = DEFAULT_CLIENT.auth_url(
                redirect_uri=nonce.redirect_uri, state=str(nonce.state)
            )
        except KeycloakConnectionError as kce:
            logger.error("Unable to fetch auth URL, is keycloak running? (Error: %s)", kce)
            return None
        return authorization_url


class LoginComplete(RedirectView):
    """Login Complete View."""

    def get(self, *args, **kwargs):
        request = self.request

        if "error" in request.GET:
            return HttpResponseServerError(request.GET["error"])

        if "code" not in request.GET and "state" not in request.GET:
            return HttpResponseBadRequest()

        if (
            "oidc_state" not in request.session
            or request.GET["state"] != request.session["oidc_state"]
        ):
            # Missing or incorrect state; login again.
            return HttpResponseRedirect(reverse("keycloak_login"))

        # can fail here is already logged in, so allow it to carry on without error
        try:
            nonce = Nonce.objects.get(state=request.GET['state'])
        except Nonce.DoesNotExist:
            logger.warning(f"Nonce {request.GET['state']} does not exist.")
            return HttpResponseRedirect("/")

        user = authenticate(
            request=request, code=request.GET["code"], redirect_uri=nonce.redirect_uri
        )
        if user and user.is_authenticated:
            login(request, user)
        nonce.delete()
        return HttpResponseRedirect(nonce.next_path or "/")


class Logout(RedirectView):
    """Logout View."""

    def get_redirect_url(self, *args, **kwargs):
            '''replacing with Peter Stump version as getting stuck logging out in production when I had been logged in as a different user in development '''

            if hasattr(self.request.user, 'oidc_profile'):
                # NOTE: getting error invalid refresh token
                try:
                    self.request.realm.client.openid_api_client.logout(
                        self.request.user.oidc_profile.refresh_token
                    )
                except Exception as e:
                    logger.error(f"Error logging out user and getting refresh token: {e}")

                self.request.user.oidc_profile.access_token = None
                self.request.user.oidc_profile.expires_before = None
                self.request.user.oidc_profile.refresh_token = None
                #self.request.user.oidc_profile.refresh_expires_before = None
                self.request.user.oidc_profile.save(update_fields=[
                    'access_token',
                    'expires_before',
                    'refresh_token',
                    'refresh_expires_before'
                ])

                logout(self.request)

                if settings.LOGOUT_REDIRECT_URL:
                    return resolve_url(settings.LOGOUT_REDIRECT_URL)

                return reverse('keycloak_login')



class Register(Login):

    def get_redirect_url(self, *args, **kwargs):

        authorization_url = super().get_redirect_url(*args, **kwargs)

        return authorization_url.replace("/auth?", "/registrations?")

login_view = Login.as_view()
login_complete_view = LoginComplete.as_view()
logout_view = Logout.as_view()
