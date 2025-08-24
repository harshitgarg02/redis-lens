"""
Management command to check user data and debug name issues
"""
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User


class Command(BaseCommand):
    help = 'Check user data in the database and show name field status'

    def add_arguments(self, parser):
        parser.add_argument(
            '--fix-names',
            action='store_true',
            dest='fix_names',
            help='Attempt to fix missing names by extracting from email or username',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('=== RedisLens User Database Report ===\n'))
        
        users = User.objects.all()
        total_users = users.count()
        users_with_names = users.exclude(first_name='', last_name='').count()
        users_missing_names = total_users - users_with_names
        
        self.stdout.write(f"Total Users: {total_users}")
        self.stdout.write(f"Users with Names: {users_with_names}")
        self.stdout.write(f"Users Missing Names: {users_missing_names}\n")
        
        self.stdout.write(self.style.WARNING('=== Individual User Details ==='))
        
        for i, user in enumerate(users, 1):
            self.stdout.write(f"\n{i}. Username: '{user.username}'")
            self.stdout.write(f"   Email: '{user.email}'")
            self.stdout.write(f"   First Name: '{user.first_name}'")
            self.stdout.write(f"   Last Name: '{user.last_name}'")
            self.stdout.write(f"   Full Name: '{user.get_full_name()}'")
            self.stdout.write(f"   Date Joined: {user.date_joined}")
            self.stdout.write(f"   Last Login: {user.last_login}")
            self.stdout.write(f"   Staff: {user.is_staff}, Active: {user.is_active}")
            
            # Identify potential issues
            issues = []
            if not user.first_name and not user.last_name:
                issues.append("Missing both first and last name")
            elif not user.first_name:
                issues.append("Missing first name")
            elif not user.last_name:
                issues.append("Missing last name")
            
            if not user.email:
                issues.append("Missing email")
                
            if issues:
                self.stdout.write(f"   ⚠️  Issues: {', '.join(issues)}")
            else:
                self.stdout.write(f"   ✅ Complete profile")
        
        # Fix names if requested
        if options['fix_names']:
            self.stdout.write(self.style.WARNING('\n=== Attempting to Fix Missing Names ==='))
            fixed_count = 0
            
            for user in users.filter(first_name='', last_name=''):
                original_first = user.first_name
                original_last = user.last_name
                
                # Try to extract names from email or username
                if user.email and '@' in user.email:
                    email_local = user.email.split('@')[0]
                    if '.' in email_local:
                        parts = email_local.split('.')
                        user.first_name = parts[0].capitalize()
                        user.last_name = parts[-1].capitalize()
                    elif '_' in email_local:
                        parts = email_local.split('_')
                        user.first_name = parts[0].capitalize()
                        user.last_name = parts[-1].capitalize()
                    else:
                        user.first_name = email_local.capitalize()
                        user.last_name = "User"
                elif user.username:
                    if '.' in user.username:
                        parts = user.username.split('.')
                        user.first_name = parts[0].capitalize()
                        user.last_name = parts[-1].capitalize()
                    elif '_' in user.username:
                        parts = user.username.split('_')
                        user.first_name = parts[0].capitalize()
                        user.last_name = parts[-1].capitalize()
                    else:
                        user.first_name = user.username.capitalize()
                        user.last_name = "User"
                
                # Only save if we made changes
                if user.first_name != original_first or user.last_name != original_last:
                    user.save()
                    fixed_count += 1
                    self.stdout.write(
                        f"✅ Fixed {user.username}: '{original_first} {original_last}' → '{user.first_name} {user.last_name}'"
                    )
            
            self.stdout.write(self.style.SUCCESS(f'\n🎉 Fixed names for {fixed_count} users!'))
        
        self.stdout.write(self.style.SUCCESS('\n=== Report Complete ==='))
