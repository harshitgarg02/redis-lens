import csv
import json
from datetime import timedelta
from django.http import HttpResponse, JsonResponse
from django.db.models import Q
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from .models import RedisInstance, RedisConfiguration, SentinelAnalysisSession, SentinelInstance, MonitoredMaster, SentinelConfiguration


@login_required
def export_configurations_csv(request):
    """Export configurations to CSV"""
    # Get the same filters as the configurations view
    role_filter = request.GET.get('role', '')
    category_filter = request.GET.get('category', '')
    parameter_filter = request.GET.get('parameter', '')
    instance_filter = request.GET.get('instance', '')
    search_query = request.GET.get('search', '')
    
    # Apply same filtering logic (USER-FILTERED for security)
    configurations = RedisConfiguration.objects.select_related('instance').filter(
        instance__analysis_session__user=request.user
    )
    
    if role_filter:
        configurations = configurations.filter(instance__role=role_filter)
    if category_filter:
        configurations = configurations.filter(category=category_filter)
    if parameter_filter:
        configurations = configurations.filter(parameter_name__icontains=parameter_filter)
    if instance_filter:
        configurations = configurations.filter(
            Q(instance__ip_address__icontains=instance_filter) |
            Q(instance__port__icontains=instance_filter)
        )
    if search_query:
        configurations = configurations.filter(
            Q(parameter_name__icontains=search_query) |
            Q(parameter_value__icontains=search_query) |
            Q(instance__ip_address__icontains=search_query)
        )
    
    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="redis_configurations_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    
    # Write header
    writer.writerow([
        'Instance IP',
        'Port',
        'Role',
        'Status',
        'Parameter Name',
        'Parameter Value',
        'Category',
        'Version',
        'Uptime (seconds)',
        'Connected Clients',
        'Used Memory',
        'Max Memory',
        'Hit Ratio %',
        'Memory Usage %',
        'Last Updated'
    ])
    
    # Write data
    for config in configurations:
        writer.writerow([
            config.instance.ip_address,
            config.instance.port,
            config.instance.role,
            config.instance.status,
            config.parameter_name,
            config.parameter_value,
            config.category,
            config.instance.version,
            config.instance.uptime_seconds,
            config.instance.connected_clients,
            config.instance.used_memory_human,
            config.instance.maxmemory_human,
            config.instance.hit_ratio,
            config.instance.memory_usage_percentage,
            config.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    return response


@login_required
def export_sentinel_session(request, session_id):
    """Export comprehensive Sentinel analysis session data"""
    # Get the session (user-filtered for security)
    session = get_object_or_404(SentinelAnalysisSession, id=session_id, user=request.user)
    
    # Determine format from query parameter
    export_format = request.GET.get('format', 'csv').lower()
    
    if export_format == 'json':
        return export_sentinel_session_json(session)
    else:
        return export_sentinel_session_csv(session)


def export_sentinel_session_csv(session):
    """Export sentinel session data as CSV"""
    timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="sentinel_analysis_{session.id}_{timestamp}.csv"'
    
    writer = csv.writer(response)
    
    # Session Overview
    writer.writerow(['=== SENTINEL ANALYSIS SESSION OVERVIEW ==='])
    writer.writerow(['Session ID', session.id])
    writer.writerow(['Sentinel IP', session.sentinel_ip])
    writer.writerow(['Sentinel Port', session.sentinel_port])
    writer.writerow(['Analysis Type', session.get_analysis_type_display()])
    writer.writerow(['Status', session.status])
    writer.writerow(['Session Name', session.session_name or 'N/A'])
    # Convert to IST for export
    start_time_ist = session.analysis_start_time + timedelta(hours=5, minutes=30)
    end_time_ist = (session.analysis_end_time + timedelta(hours=5, minutes=30)) if session.analysis_end_time else None
    
    writer.writerow(['Start Time (IST)', start_time_ist.strftime('%d %b %Y, %I:%M:%S %p')])
    writer.writerow(['End Time (IST)', end_time_ist.strftime('%d %b %Y, %I:%M:%S %p') if end_time_ist else 'N/A'])
    writer.writerow(['Duration', str(session.duration)])
    writer.writerow(['Total Sentinels Found', session.total_sentinels_found])
    writer.writerow(['Total Masters Found', session.total_masters_found])
    writer.writerow(['Total Instances Analyzed', session.total_instances_analyzed])
    writer.writerow(['Successful Connections', session.successful_connections])
    writer.writerow(['Failed Connections', session.failed_connections])
    if session.error_message:
        writer.writerow(['Error Message', session.error_message])
    writer.writerow([])  # Empty line
    
    # Sentinel Instances
    sentinels = SentinelInstance.objects.filter(analysis_session=session)
    if sentinels.exists():
        writer.writerow(['=== SENTINEL INSTANCES ==='])
        writer.writerow([
            'IP Address', 'Port', 'Status', 'Version', 'Uptime (seconds)', 
            'Sentinel ID', 'Known Sentinels', 'Known Slaves', 'Masters Count',
            'Connected Clients', 'Max Clients', 'Created At'
        ])
        for sentinel in sentinels:
            writer.writerow([
                sentinel.ip_address,
                sentinel.port,
                sentinel.status,
                sentinel.version,
                sentinel.uptime_seconds,
                sentinel.sentinel_id,
                sentinel.known_sentinels,
                sentinel.known_slaves,
                sentinel.masters_count,
                sentinel.connected_clients,
                sentinel.max_clients,
                sentinel.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])
        writer.writerow([])  # Empty line
    
    # Monitored Masters
    masters = MonitoredMaster.objects.filter(sentinel__analysis_session=session)
    if masters.exists():
        writer.writerow(['=== MONITORED MASTERS ==='])
        writer.writerow([
            'Master Name', 'Master IP', 'Master Port', 'Status', 'Quorum',
            'Num Slaves', 'Down After (ms)', 'Failover Timeout', 'Parallel Syncs',
            'Num Other Sentinels', 'Last Ping Sent', 'Last OK Ping', 'Last Ping Reply',
            'Redis Instance Linked', 'Created At', 'Updated At'
        ])
        for master in masters:
            writer.writerow([
                master.master_name,
                master.master_ip,
                master.master_port,
                master.status,
                master.quorum,
                master.num_slaves,
                master.down_after_milliseconds,
                master.failover_timeout,
                master.parallel_syncs,
                master.num_other_sentinels,
                master.last_ping_sent,
                master.last_ok_ping_reply,
                master.last_ping_reply,
                'Yes' if master.redis_instance else 'No',
                master.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                master.updated_at.strftime('%Y-%m-%d %H:%M:%S')
            ])
        writer.writerow([])  # Empty line
    
    # Redis Instances (from monitored masters)
    redis_instances = RedisInstance.objects.filter(
        monitoredmaster__sentinel__analysis_session=session
    ).distinct()
    if redis_instances.exists():
        writer.writerow(['=== REDIS INSTANCES (FROM MONITORED MASTERS) ==='])
        writer.writerow([
            'IP Address', 'Port', 'Role', 'Status', 'Version', 'Master IP', 'Master Port',
            'Uptime (seconds)', 'Connected Clients', 'Max Clients', 'Used Memory',
            'Max Memory', 'Memory Usage %', 'Hit Ratio %', 'Keyspace Hits',
            'Keyspace Misses', 'Total Keys', 'Total Commands', 'Master Name',
            'Created At', 'Updated At'
        ])
        for instance in redis_instances:
            writer.writerow([
                instance.ip_address,
                instance.port,
                instance.role,
                instance.status,
                instance.version,
                instance.master_ip,
                instance.master_port,
                instance.uptime_seconds,
                instance.connected_clients,
                instance.max_clients,
                instance.used_memory_human,
                instance.maxmemory_human,
                instance.memory_usage_percentage,
                instance.hit_ratio,
                instance.keyspace_hits,
                instance.keyspace_misses,
                instance.total_keys,
                instance.total_commands_processed,
                instance.master_name,
                instance.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                instance.updated_at.strftime('%Y-%m-%d %H:%M:%S')
            ])
        writer.writerow([])  # Empty line
    
    # Sentinel Configurations
    configs = SentinelConfiguration.objects.filter(sentinel__analysis_session=session)
    if configs.exists():
        writer.writerow(['=== SENTINEL CONFIGURATIONS ==='])
        writer.writerow([
            'Sentinel IP', 'Sentinel Port', 'Parameter Name', 'Parameter Value',
            'Category', 'Master Name (if applicable)', 'Description', 'Created At'
        ])
        for config in configs:
            writer.writerow([
                config.sentinel.ip_address,
                config.sentinel.port,
                config.parameter_name,
                config.parameter_value,
                config.category,
                config.master_name or 'N/A',
                config.description,
                config.created_at.strftime('%Y-%m-%d %H:%M:%S')
            ])
    
    return response


def export_sentinel_session_json(session):
    """Export sentinel session data as JSON"""
    timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
    
    # Build comprehensive data structure
    data = {
        'session_overview': {
            'session_id': session.id,
            'sentinel_ip': session.sentinel_ip,
            'sentinel_port': session.sentinel_port,
            'analysis_type': session.analysis_type,
            'analysis_type_display': session.get_analysis_type_display(),
            'status': session.status,
            'session_name': session.session_name,
            'start_time': session.analysis_start_time.isoformat(),
            'end_time': session.analysis_end_time.isoformat() if session.analysis_end_time else None,
            'duration_seconds': session.duration.total_seconds() if session.analysis_end_time else None,
            'total_sentinels_found': session.total_sentinels_found,
            'total_masters_found': session.total_masters_found,
            'total_instances_analyzed': session.total_instances_analyzed,
            'successful_connections': session.successful_connections,
            'failed_connections': session.failed_connections,
            'error_message': session.error_message,
            'created_at': session.created_at.isoformat()
        },
        'sentinel_instances': [],
        'monitored_masters': [],
        'redis_instances': [],
        'configurations': []
    }
    
    # Sentinel Instances
    sentinels = SentinelInstance.objects.filter(analysis_session=session)
    for sentinel in sentinels:
        data['sentinel_instances'].append({
            'ip_address': sentinel.ip_address,
            'port': sentinel.port,
            'status': sentinel.status,
            'version': sentinel.version,
            'uptime_seconds': sentinel.uptime_seconds,
            'sentinel_id': sentinel.sentinel_id,
            'known_sentinels': sentinel.known_sentinels,
            'known_slaves': sentinel.known_slaves,
            'masters_count': sentinel.masters_count,
            'connected_clients': sentinel.connected_clients,
            'max_clients': sentinel.max_clients,
            'raw_info_output': sentinel.raw_info_output,
            'created_at': sentinel.created_at.isoformat(),
            'updated_at': sentinel.updated_at.isoformat()
        })
    
    # Monitored Masters
    masters = MonitoredMaster.objects.filter(sentinel__analysis_session=session)
    for master in masters:
        master_data = {
            'master_name': master.master_name,
            'master_ip': master.master_ip,
            'master_port': master.master_port,
            'status': master.status,
            'quorum': master.quorum,
            'num_slaves': master.num_slaves,
            'down_after_milliseconds': master.down_after_milliseconds,
            'failover_timeout': master.failover_timeout,
            'parallel_syncs': master.parallel_syncs,
            'num_other_sentinels': master.num_other_sentinels,
            'last_ping_sent': master.last_ping_sent,
            'last_ok_ping_reply': master.last_ok_ping_reply,
            'last_ping_reply': master.last_ping_reply,
            'redis_instance_linked': master.redis_instance is not None,
            'created_at': master.created_at.isoformat(),
            'updated_at': master.updated_at.isoformat()
        }
        
        # Include linked Redis instance data if available
        if master.redis_instance:
            master_data['redis_instance'] = {
                'ip_address': master.redis_instance.ip_address,
                'port': master.redis_instance.port,
                'role': master.redis_instance.role,
                'status': master.redis_instance.status,
                'version': master.redis_instance.version,
                'uptime_seconds': master.redis_instance.uptime_seconds,
                'connected_clients': master.redis_instance.connected_clients,
                'max_clients': master.redis_instance.max_clients,
                'used_memory': master.redis_instance.used_memory,
                'used_memory_human': master.redis_instance.used_memory_human,
                'maxmemory': master.redis_instance.maxmemory,
                'maxmemory_human': master.redis_instance.maxmemory_human,
                'memory_usage_percentage': master.redis_instance.memory_usage_percentage,
                'hit_ratio': master.redis_instance.hit_ratio,
                'keyspace_hits': master.redis_instance.keyspace_hits,
                'keyspace_misses': master.redis_instance.keyspace_misses,
                'total_keys': master.redis_instance.total_keys,
                'total_commands_processed': master.redis_instance.total_commands_processed,
                'master_name': master.redis_instance.master_name,
                'raw_info_output': master.redis_instance.raw_info_output
            }
        
        data['monitored_masters'].append(master_data)
    
    # Redis Instances (all instances from this session)
    redis_instances = RedisInstance.objects.filter(
        monitoredmaster__sentinel__analysis_session=session
    ).distinct()
    for instance in redis_instances:
        data['redis_instances'].append({
            'ip_address': instance.ip_address,
            'port': instance.port,
            'role': instance.role,
            'status': instance.status,
            'version': instance.version,
            'master_ip': instance.master_ip,
            'master_port': instance.master_port,
            'uptime_seconds': instance.uptime_seconds,
            'connected_clients': instance.connected_clients,
            'max_clients': instance.max_clients,
            'used_memory': instance.used_memory,
            'used_memory_human': instance.used_memory_human,
            'maxmemory': instance.maxmemory,
            'maxmemory_human': instance.maxmemory_human,
            'memory_usage_percentage': instance.memory_usage_percentage,
            'hit_ratio': instance.hit_ratio,
            'keyspace_hits': instance.keyspace_hits,
            'keyspace_misses': instance.keyspace_misses,
            'total_keys': instance.total_keys,
            'total_commands_processed': instance.total_commands_processed,
            'master_name': instance.master_name,
            'raw_info_output': instance.raw_info_output,
            'created_at': instance.created_at.isoformat(),
            'updated_at': instance.updated_at.isoformat()
        })
    
    # Configurations
    configs = SentinelConfiguration.objects.filter(sentinel__analysis_session=session)
    for config in configs:
        data['configurations'].append({
            'sentinel_ip': config.sentinel.ip_address,
            'sentinel_port': config.sentinel.port,
            'parameter_name': config.parameter_name,
            'parameter_value': config.parameter_value,
            'category': config.category,
            'master_name': config.master_name,
            'description': config.description,
            'created_at': config.created_at.isoformat(),
            'updated_at': config.updated_at.isoformat()
        })
    
    # Add export metadata
    data['export_metadata'] = {
        'exported_at': timezone.now().isoformat(),
        'export_format': 'json',
        'exporter': 'Redis Analyzer - Sentinel Session Export',
        'version': '1.0'
    }
    
    response = JsonResponse(data)
    response['Content-Disposition'] = f'attachment; filename="sentinel_analysis_{session.id}_{timestamp}.json"'
    return response


@login_required
def export_instances_csv(request):
    """Export instances summary to CSV"""
    instances = RedisInstance.objects.filter(
        analysis_session__user=request.user
    ).order_by('role', 'ip_address')
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="redis_instances_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    
    # Write header
    writer.writerow([
        'IP Address',
        'Port',
        'Role',
        'Status',
        'Version',
        'Master IP',
        'Master Port',
        'Uptime (seconds)',
        'Connected Clients',
        'Used Memory',
        'Max Memory',
        'Memory Usage %',
        'Hit Ratio %',
        'Keyspace Hits',
        'Keyspace Misses',
        'Total Commands',
        'Created At',
        'Updated At'
    ])
    
    # Write data
    for instance in instances:
        writer.writerow([
            instance.ip_address,
            instance.port,
            instance.role,
            instance.status,
            instance.version,
            instance.master_ip,
            instance.master_port,
            instance.uptime_seconds,
            instance.connected_clients,
            instance.used_memory_human,
            instance.maxmemory_human,
            instance.memory_usage_percentage,
            instance.hit_ratio,
            instance.keyspace_hits,
            instance.keyspace_misses,
            instance.total_commands_processed,
            instance.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            instance.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    return response