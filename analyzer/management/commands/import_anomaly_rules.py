import csv
import os
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from analyzer.models import AnomalyRule


class Command(BaseCommand):
    help = 'Import Redis anomaly detection rules from CSV file'

    def add_arguments(self, parser):
        parser.add_argument(
            '--csv-file',
            type=str,
            help='Path to CSV file containing anomaly rules',
            default=None
        )
        parser.add_argument(
            '--clear-existing',
            action='store_true',
            help='Clear existing rules before importing new ones'
        )

    def handle(self, *args, **options):
        csv_file = options['csv_file']
        
        # If no CSV file specified, look for it in the project root
        if not csv_file:
            # Look for the CSV file in the project root
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            potential_files = [
                os.path.join(project_root, 'Redis Anomoly Rules - client-output-buffer-limit_client-query-buffer-li....csv'),
                os.path.join(project_root, 'redis_anomaly_rules.csv'),
                os.path.join(project_root, 'Redis_Anomaly_Rules.csv'),
                os.path.join(project_root, 'anomaly_rules.csv'),
            ]
            
            for file_path in potential_files:
                if os.path.exists(file_path):
                    csv_file = file_path
                    break
            
            if not csv_file:
                raise CommandError(
                    'No CSV file found. Please specify --csv-file or place a file named '
                    '"redis_anomaly_rules.csv" in the project root.'
                )

        if not os.path.exists(csv_file):
            raise CommandError(f'CSV file not found: {csv_file}')

        if options['clear_existing']:
            deleted_count = AnomalyRule.objects.count()
            AnomalyRule.objects.all().delete()
            self.stdout.write(
                self.style.WARNING(f'Cleared {deleted_count} existing anomaly rules')
            )

        # Category mapping from CSV to model choices
        category_mapping = {
            'Client Management': 'client_management',
            'Logging': 'logging',
            'Process Management': 'process_management',
            'Memory': 'memory',
            'Network': 'network',
            'Security': 'security',
            'Performance': 'performance',
            'Data Structures': 'data_structures',
            'Persistence': 'persistence',
            'Replication': 'replication',
        }

        # Severity mapping from CSV to model choices
        severity_mapping = {
            'Notice': 'notice',
            'Warning': 'warning',
            'Critical': 'critical',
        }

        created_count = 0
        updated_count = 0
        error_count = 0

        try:
            with open(csv_file, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                
                for row_num, row in enumerate(reader, start=2):  # Start at 2 since header is row 1
                    try:
                        rule_id = row['Rule ID'].strip()
                        directives = row['Directive(s)'].strip()
                        category = row['Category'].strip()
                        anomaly_description = row['Anomaly Description'].strip()
                        detection_logic = row['Detection Logic'].strip()
                        recommended_state = row['Recommended State'].strip()
                        severity = row['Severity'].strip()

                        # Validate required fields
                        if not all([rule_id, directives, category, anomaly_description, detection_logic, recommended_state, severity]):
                            self.stdout.write(
                                self.style.ERROR(f'Row {row_num}: Missing required fields')
                            )
                            error_count += 1
                            continue

                        # Map category and severity
                        mapped_category = category_mapping.get(category)
                        mapped_severity = severity_mapping.get(severity)

                        if not mapped_category:
                            self.stdout.write(
                                self.style.ERROR(f'Row {row_num}: Unknown category "{category}"')
                            )
                            error_count += 1
                            continue

                        if not mapped_severity:
                            self.stdout.write(
                                self.style.ERROR(f'Row {row_num}: Unknown severity "{severity}"')
                            )
                            error_count += 1
                            continue

                        # Create or update the rule
                        rule, created = AnomalyRule.objects.update_or_create(
                            rule_id=rule_id,
                            defaults={
                                'directives': directives,
                                'category': mapped_category,
                                'anomaly_description': anomaly_description,
                                'detection_logic': detection_logic,
                                'recommended_state': recommended_state,
                                'severity': mapped_severity,
                                'is_active': True,
                            }
                        )

                        if created:
                            created_count += 1
                            self.stdout.write(f'Created rule: {rule_id}')
                        else:
                            updated_count += 1
                            self.stdout.write(f'Updated rule: {rule_id}')

                    except Exception as e:
                        self.stdout.write(
                            self.style.ERROR(f'Row {row_num}: Error processing rule - {str(e)}')
                        )
                        error_count += 1
                        continue

        except Exception as e:
            raise CommandError(f'Error reading CSV file: {str(e)}')

        # Summary
        self.stdout.write(
            self.style.SUCCESS(
                f'\nImport completed:\n'
                f'  Created: {created_count} rules\n'
                f'  Updated: {updated_count} rules\n'
                f'  Errors: {error_count} rules\n'
                f'  Total processed: {created_count + updated_count + error_count}'
            )
        )

        if error_count > 0:
            self.stdout.write(
                self.style.WARNING(
                    f'{error_count} rules had errors and were not imported. '
                    'Please check the error messages above.'
                )
            )
