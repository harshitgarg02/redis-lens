"""
Context processors for RedisLens application
"""

from django.conf import settings


def version_context(request):
    """
    Add version information to template context
    """
    return {
        'APP_VERSION': getattr(settings, 'APP_VERSION', '1.0.0'),
        'APP_VERSION_DISPLAY': getattr(settings, 'APP_VERSION_DISPLAY', 'v1.0.0'),
        'APP_VERSION_FULL': getattr(settings, 'APP_VERSION_FULL', '1.0.0'),
    }
