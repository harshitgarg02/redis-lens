"""
Management command to create admin user for RedisLens
"""
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import validate_email


class Command(BaseCommand):
    help = 'Create an admin user for RedisLens'

    def add_arguments(self, parser):
        parser.add_argument(
            '--username',
            type=str,
            default='admin',
            help='Admin username (default: admin)'
        )
        parser.add_argument(
            '--email',
            type=str,
            default='admin@redislens.local',
            help='Admin email (default: admin@redislens.local)'
        )
        parser.add_argument(
            '--password',
            type=str,
            default='redis123',
            help='Admin password (default: redis123)'
        )
        parser.add_argument(
            '--first-name',
            type=str,
            default='System',
            help='First name (default: System)'
        )
        parser.add_argument(
            '--last-name',
            type=str,
            default='Administrator',
            help='Last name (default: Administrator)'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force creation even if user exists (will update existing user)'
        )

    def handle(self, *args, **options):
        username = options['username']
        email = options['email']
        password = options['password']
        first_name = options['first_name']
        last_name = options['last_name']
        force = options['force']

        # Validate email
        try:
            validate_email(email)
        except ValidationError:
            raise CommandError(f'Invalid email address: {email}')

        # Check if user exists
        existing_user = User.objects.filter(username=username).first()
        
        if existing_user and not force:
            self.stdout.write(
                self.style.WARNING(
                    f'User "{username}" already exists. Use --force to update existing user.'
                )
            )
            return

        try:
            if existing_user and force:
                # Update existing user
                existing_user.email = email
                existing_user.first_name = first_name
                existing_user.last_name = last_name
                existing_user.set_password(password)
                existing_user.is_staff = True
                existing_user.is_superuser = True
                existing_user.save()
                
                self.stdout.write(
                    self.style.SUCCESS(f'✅ Admin user "{username}" updated successfully!')
                )
            else:
                # Create new user
                user = User.objects.create_superuser(
                    username=username,
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name
                )
                
                self.stdout.write(
                    self.style.SUCCESS(f'✅ Admin user "{username}" created successfully!')
                )

            # Display credentials
            self.stdout.write('')
            self.stdout.write(self.style.HTTP_INFO('📋 Admin Credentials:'))
            self.stdout.write(f'   Username: {username}')
            self.stdout.write(f'   Password: {password}')
            self.stdout.write(f'   Email: {email}')
            self.stdout.write('')
            self.stdout.write(self.style.HTTP_INFO('🌐 Access URLs:'))
            self.stdout.write('   Application: http://localhost:8000/')
            self.stdout.write('   Admin Panel: http://localhost:8000/admin/')
            self.stdout.write('')
            self.stdout.write(
                self.style.WARNING(
                    '⚠️  Please change the default password in production!'
                )
            )

        except Exception as e:
            raise CommandError(f'Failed to create admin user: {e}')