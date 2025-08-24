"""
URL configuration for RedisLens project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from analyzer.oauth_views import oauth_login, oauth_callback, oauth_logout, oauth_login_page, login_page

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Main authentication endpoints
    path('login/', login_page, name='login_page'),              # Main login page with multiple options
    path('logout/', oauth_logout, name='logout'),               # Universal logout
    
    # OAuth specific endpoints
    path('oauth/login/', oauth_login, name='oauth_login'),      # OAuth initiation
    path('oauth/callback/', oauth_callback, name='oauth_callback'),  # OAuth callback
    path('oauth/logout/', oauth_logout, name='oauth_logout'),   # OAuth logout (same as universal)
    path('oauth/login-page/', oauth_login_page, name='oauth_login_page'),  # OAuth-only login page (legacy)
    
    # Admin logout (fallback)
    path('admin/logout/', auth_views.LogoutView.as_view(), name='admin_logout'),
    
    # Main app URLs
    path('', include('analyzer.urls')),
]
