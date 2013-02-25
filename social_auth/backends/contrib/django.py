"""
This backend uses Django's Auth system to authenticate a django user.
The only benefit for using this is that a UserSocialAuth profile will
be created for the native django user, so you don't need to catch
UserSocialAuth.DoesNotExist to identify native users.
"""
from __future__ import absolute_import

from django.contrib.auth import authenticate
from django.core.urlresolvers import reverse

from social_auth.backends import SocialAuthBackend, BaseAuth, USERNAME
from social_auth.exceptions import AuthException
from social_auth.models import UserSocialAuth

class DjangoBackend(SocialAuthBackend):
    name = 'django'

    def get_user_id(self, details, response):
        return response.id

    def get_user_details(self, response):
        return {USERNAME: response.username,
                'email' : response.email,
                'fullname': '',
                'first_name': '',
                'last_name': ''}

class DjangoAuth(BaseAuth):
    AUTH_BACKEND = DjangoBackend

    def auth_url(self):
        return reverse('login')

    def auth_complete(self, *args, **kwargs):
        user = kwargs['user']
        if user.is_authenticated():
            try:
                if user.social_auth.get().provider == 'django':
                    pass
                else:
                    raise AuthException('Authentication error')
            except UserSocialAuth.DoesNotExist:
                pass

            kwargs.update({
                'response': user,
                self.AUTH_BACKEND.name: True
            })
        return authenticate(*args, **kwargs);
        
BACKENDS = {
    'django' : DjangoAuth,
}
