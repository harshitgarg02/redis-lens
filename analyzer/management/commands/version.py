"""
Management command to display version information
"""

from django.core.management.base import BaseCommand
from redislens.version import (
    get_version, get_version_display, get_full_version,
    BUILD_DATE, BUILD_COMMIT, BUILD_BRANCH
)


class Command(BaseCommand):
    help = 'Display RedisLens version information'

    def add_arguments(self, parser):
        parser.add_argument(
            '--format',
            choices=['simple', 'json', 'detailed'],
            default='simple',
            help='Output format (default: simple)'
        )

    def handle(self, *args, **options):
        format_type = options['format']

        if format_type == 'simple':
            self.stdout.write(get_version())
        
        elif format_type == 'json':
            import json
            version_data = {
                'version': get_version(),
                'version_display': get_version_display(),
                'version_full': get_full_version(),
                'build_date': BUILD_DATE,
                'build_commit': BUILD_COMMIT,
                'build_branch': BUILD_BRANCH,
                'application': 'RedisLens',
                'description': 'Redis Analysis & Monitoring Platform'
            }
            self.stdout.write(json.dumps(version_data, indent=2))
        
        elif format_type == 'detailed':
            self.stdout.write(self.style.SUCCESS('RedisLens Version Information'))
            self.stdout.write('-' * 40)
            self.stdout.write(f'Version: {get_version_display()}')
            self.stdout.write(f'Full Version: {get_full_version()}')
            
            if BUILD_DATE:
                self.stdout.write(f'Build Date: {BUILD_DATE}')
            if BUILD_COMMIT:
                self.stdout.write(f'Build Commit: {BUILD_COMMIT}')
            if BUILD_BRANCH:
                self.stdout.write(f'Build Branch: {BUILD_BRANCH}')
            
            self.stdout.write(f'Application: RedisLens')
            self.stdout.write(f'Description: Redis Analysis & Monitoring Platform')
