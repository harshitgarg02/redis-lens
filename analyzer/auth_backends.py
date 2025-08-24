"""
Multiple authentication backends for OAuth and generic login
"""
import requests
import logging
from django.contrib.auth.backends import BaseBackend, ModelBackend
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.conf import settings

logger = logging.getLogger(__name__)


class OAuthBackend(BaseBackend):
    """Custom authentication backend for OAuth with external OAuth provider"""
    
    def authenticate(self, request, access_token=None, **kwargs):
        """
        Authenticate user using OAuth access token
        """
        if not access_token:
            return None
            
        try:
            # Get user details from OAuth provider
            user_data = self.get_user_details(access_token)
            if not user_data:
                return None
                
            # Get or create user
            user = self.get_or_create_user(user_data)
            return user
            
        except Exception as e:
            logger.error(f"OAuth authentication failed: {str(e)}")
            return None
    
    def get_user_details(self, access_token):
        """
        Fetch user details from OAuth provider using access token
        """
        try:
            authn_url = settings.OAUTH_CONFIG['AUTHN_URL']
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(
                f"{authn_url}/oauth/r/api/v1/user/details",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get user details: {response.status_code} - {response.text}")
                return None
                
        except requests.RequestException as e:
            logger.error(f"Error fetching user details: {str(e)}")
            return None
    
    def get_or_create_user(self, user_data):
        """
        Get or create Django user from OAuth user data
        """
        try:
            # Extract user info from OAuth provider response
            # Try multiple field name variations for different OAuth providers
            username = (user_data.get('username') or 
                       user_data.get('preferred_username') or 
                       user_data.get('email', '').split('@')[0])
            email = user_data.get('email', '')
            
            # Try various field names for first name
            first_name = (user_data.get('first_name') or 
                         user_data.get('given_name') or 
                         user_data.get('firstName') or 
                         user_data.get('givenName') or
                         user_data.get('name', '').split(' ')[0] if user_data.get('name') else '')
            
            # Try various field names for last name  
            last_name = (user_data.get('last_name') or 
                        user_data.get('family_name') or 
                        user_data.get('lastName') or 
                        user_data.get('familyName') or
                        user_data.get('surname') or
                        (' '.join(user_data.get('name', '').split(' ')[1:]) if user_data.get('name') and len(user_data.get('name', '').split(' ')) > 1 else ''))
            
            # Debug logging
            logger.info(f"OAuth user data received: {list(user_data.keys())}")
            logger.info(f"Extracted - Username: '{username}', Email: '{email}', First: '{first_name}', Last: '{last_name}'")
            
            # Try to get existing user by username or email
            user = None
            if username:
                try:
                    user = User.objects.get(username=username)
                except User.DoesNotExist:
                    pass
            
            if not user and email:
                try:
                    user = User.objects.get(email=email)
                except User.DoesNotExist:
                    pass
            
            # Create new user if doesn't exist
            if not user:
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name
                )
                logger.info(f"Created new user: {username}")
            else:
                # Update existing user info
                user.email = email
                user.first_name = first_name
                user.last_name = last_name
                user.save()
                logger.info(f"Updated existing user: {username} - Name: '{first_name} {last_name}'")
            
            return user
            
        except Exception as e:
            logger.error(f"Error creating/updating user: {str(e)}")
            return None
    
    def get_user(self, user_id):
        """
        Get user by ID (required by Django)
        """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None



class GenericBackend(ModelBackend):
    """
    Generic username/password authentication (extends Django's default)
    """
    
    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Authenticate user with username/password against Django user database
        """
        if not username or not password:
            return None
        
        try:
            # Use Django's built-in authentication
            user = super().authenticate(request, username=username, password=password, **kwargs)
            if user:
                logger.info(f"Generic authentication successful for user: {username}")
            return user
        except Exception as e:
            logger.error(f"Generic authentication error for user {username}: {str(e)}")
            return None
