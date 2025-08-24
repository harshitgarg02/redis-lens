import csv
import json
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from .models import (
    RedisInstance, RedisConfiguration, AnalysisSession, ReplicationInfo,
    SentinelInstance, SentinelConfiguration, MonitoredMaster, SentinelAnalysisSession,
    AnomalyRule, AnomalyDetection
)
# OAuth-only authentication - no local forms needed
from .redis_service import RedisAnalyzer
from .sentinel_service import SentinelAnalyzer
from .anomaly_detector import AnomalyDetector
import logging

logger = logging.getLogger(__name__)


# ================== EDUCATIONAL VIEWS ==================

@login_required
def redis_concepts(request):
    """Educational page explaining Redis concepts"""
    return render(request, 'analyzer/redis_concepts.html')


@login_required
def guided_setup(request):
    """Guided setup page with step-by-step instructions"""
    return render(request, 'analyzer/guided_setup.html')


@login_required
def analysis_selection(request):
    """Parent analysis page to choose between Redis and Sentinel analysis"""
    return render(request, 'analyzer/analysis_selection.html')


# Registration removed - OAuth-only authentication
# def register(request):
#     """User registration view - DISABLED: OAuth-only authentication"""
#     # Registration is handled automatically through OAuth
#     return redirect('oauth_login_page')


@login_required
def dashboard(request):
    """Main dashboard view - redesigned for better navigation"""
    
    # Get recent analysis sessions for current user
    recent_redis_sessions = AnalysisSession.objects.filter(user=request.user).order_by('-created_at')[:5]
    recent_sentinel_sessions = SentinelAnalysisSession.objects.filter(user=request.user).order_by('-created_at')[:5]
    
    # Get statistics for current user's sessions
    total_instances = RedisInstance.objects.filter(
        analysis_session__user=request.user
    ).distinct().count()
    
    online_instances = RedisInstance.objects.filter(
        analysis_session__user=request.user,
        status='online'
    ).distinct().count()
    
    masters = RedisInstance.objects.filter(
        analysis_session__user=request.user,
        role='master'
    ).distinct().count()
    
    slaves = RedisInstance.objects.filter(
        analysis_session__user=request.user,
        role__in=['slave', 'replica']
    ).distinct().count()
    
    total_sentinels = SentinelInstance.objects.filter(
        analysis_session__user=request.user
    ).distinct().count()
    
    online_sentinels = SentinelInstance.objects.filter(
        analysis_session__user=request.user,
        status='online'
    ).distinct().count()
    
    monitored_masters_count = MonitoredMaster.objects.filter(
        sentinel__analysis_session__user=request.user
    ).distinct().count()
    
    # Get recent individual instances for quick access
    recent_redis_instances = RedisInstance.objects.filter(
        analysis_session__user=request.user
    ).select_related('analysis_session').order_by('-created_at')[:8]
    
    # Get recent sentinel instances for quick access  
    recent_sentinel_instances = SentinelInstance.objects.filter(
        analysis_session__user=request.user
    ).select_related('analysis_session').order_by('-created_at')[:6]
    
    # Get recent monitored masters for quick access
    recent_monitored_masters = MonitoredMaster.objects.filter(
        sentinel__analysis_session__user=request.user
    ).select_related('sentinel', 'redis_instance').order_by('-created_at')[:6]
    
    # Active analysis counts
    total_redis_sessions = AnalysisSession.objects.filter(user=request.user).count()
    total_sentinel_sessions = SentinelAnalysisSession.objects.filter(user=request.user).count()
    
    # Anomaly statistics
    user_anomalies = AnomalyDetection.objects.filter(
        Q(redis_instance__analysis_session__user=request.user) |
        Q(sentinel_instance__analysis_session__user=request.user)
    )
    total_anomalies = user_anomalies.count()
    critical_anomalies = user_anomalies.filter(rule__severity='critical', status='detected').count()
    unresolved_anomalies = user_anomalies.filter(status='detected').count()
    recent_anomalies = user_anomalies.select_related('rule', 'redis_instance', 'sentinel_instance').order_by('-detected_at')[:5]
    
    # Check if user has any analysis data (for welcome guide)
    has_recent_analysis = recent_redis_sessions.exists() or recent_sentinel_sessions.exists()
    
    context = {
        # Recent sessions
        'recent_redis_sessions': recent_redis_sessions,
        'recent_sentinel_sessions': recent_sentinel_sessions,
        'has_recent_analysis': has_recent_analysis,
        
        # Statistics
        'total_instances': total_instances,
        'online_instances': online_instances,
        'masters': masters,
        'slaves': slaves,
        'total_sentinels': total_sentinels,
        'online_sentinels': online_sentinels,
        'monitored_masters_count': monitored_masters_count,
        'total_redis_sessions': total_redis_sessions,
        'total_sentinel_sessions': total_sentinel_sessions,
        
        # Anomaly statistics
        'total_anomalies': total_anomalies,
        'critical_anomalies': critical_anomalies,
        'unresolved_anomalies': unresolved_anomalies,
        'recent_anomalies': recent_anomalies,
        
        # Quick access data
        'recent_redis_instances': recent_redis_instances,
        'recent_sentinel_instances': recent_sentinel_instances,
        'recent_monitored_masters': recent_monitored_masters,
    }
    
    return render(request, 'analyzer/dashboard.html', context)


@login_required
def analyze_redis(request):
    """Start Redis analysis"""
    if request.method == 'POST':
        master_ip = request.POST.get('master_ip')
        master_port = int(request.POST.get('master_port', 6379))
        password = request.POST.get('password', '')
        session_name = request.POST.get('session_name', '')
        
        if not master_ip:
            messages.error(request, 'Master IP address is required')
            return redirect('dashboard')
        
        try:
            analyzer = RedisAnalyzer(user=request.user, session_name=session_name)
            session = analyzer.analyze_redis_cluster(
                master_ip, 
                master_port, 
                password if password else None
            )
            
            if session.status == 'completed':
                messages.success(request, f'Analysis completed successfully. Found {session.total_instances_found} instances.')
            elif session.status == 'partial':
                messages.warning(request, f'Analysis partially completed. {session.successful_connections}/{session.total_instances_found} instances analyzed.')
            else:
                messages.error(request, f'Analysis failed: {session.error_message}')
            
            return redirect('analysis_detail', session_id=session.id)
            
        except Exception as e:
            logger.error(f"Analysis error: {str(e)}")
            messages.error(request, f'Analysis failed: {str(e)}')
            return redirect('dashboard')
    
    return render(request, 'analyzer/analyze.html')


@login_required
def analysis_detail(request, session_id):
    """View analysis session details"""
    session = get_object_or_404(AnalysisSession, id=session_id, user=request.user)
    
    # Get instances from this specific session only
    instances = RedisInstance.objects.filter(
        analysis_session=session
    ).order_by('role', 'ip_address')
    
    # Calculate correct counts
    total_count = instances.count()
    master_count = instances.filter(role='master').count()
    slave_count = instances.filter(role__in=['slave', 'replica']).count()
    
    context = {
        'session': session,
        'instances': instances,
        'total_count': total_count,
        'master_count': master_count,
        'slave_count': slave_count,
    }
    
    return render(request, 'analyzer/analysis_detail.html', context)


@login_required
def clear_all_analysis(request):
    """Clear all analysis data"""
    if request.method == 'POST':
        try:
            # Delete all data in the correct order to handle foreign key constraints
            from .models import (
                ReplicationInfo, RedisConfiguration, RedisInstance, AnalysisSession,
                SentinelConfiguration, MonitoredMaster, SentinelInstance, SentinelAnalysisSession
            )
            
            # Count records before deletion (only for current user)
            user_sessions = AnalysisSession.objects.filter(user=request.user)
            user_sentinel_sessions = SentinelAnalysisSession.objects.filter(user=request.user)
            
            # Get related instances for current user (get IDs to avoid distinct().delete() issue)
            user_instance_ids = list(RedisInstance.objects.filter(analysis_session__user=request.user).distinct().values_list('id', flat=True))
            user_sentinel_instance_ids = list(SentinelInstance.objects.filter(analysis_session__user=request.user).distinct().values_list('id', flat=True))
            
            # Count before deletion
            replication_count = ReplicationInfo.objects.filter(
                Q(master_instance_id__in=user_instance_ids) | Q(slave_instance_id__in=user_instance_ids)
            ).count()
            config_count = RedisConfiguration.objects.filter(instance_id__in=user_instance_ids).count()
            instance_count = len(user_instance_ids)
            session_count = user_sessions.count()
            
            sentinel_config_count = SentinelConfiguration.objects.filter(sentinel_id__in=user_sentinel_instance_ids).count()
            monitored_master_count = MonitoredMaster.objects.filter(sentinel_id__in=user_sentinel_instance_ids).count()
            sentinel_instance_count = len(user_sentinel_instance_ids)
            sentinel_session_count = user_sentinel_sessions.count()
            
            # Delete in order to avoid foreign key constraint issues (only current user's data)
            # First delete relationships and configurations
            ReplicationInfo.objects.filter(
                Q(master_instance_id__in=user_instance_ids) | Q(slave_instance_id__in=user_instance_ids)
            ).delete()
            RedisConfiguration.objects.filter(instance_id__in=user_instance_ids).delete()
            SentinelConfiguration.objects.filter(sentinel_id__in=user_sentinel_instance_ids).delete()
            MonitoredMaster.objects.filter(sentinel_id__in=user_sentinel_instance_ids).delete()
            
            # Then delete instances (using ID lists to avoid distinct().delete() issue)
            RedisInstance.objects.filter(id__in=user_instance_ids).delete()
            SentinelInstance.objects.filter(id__in=user_sentinel_instance_ids).delete()
            
            # Finally delete sessions
            user_sessions.delete()
            user_sentinel_sessions.delete()
            
            total_sessions = session_count + sentinel_session_count
            total_instances = instance_count + sentinel_instance_count
            total_configs = config_count + sentinel_config_count
            
            messages.success(
                request, 
                f'Successfully cleared your analysis data: {total_sessions} sessions, '
                f'{total_instances} instances, {total_configs} configurations, '
                f'{replication_count} replication records, {monitored_master_count} monitored masters.'
            )
            
        except Exception as e:
            logger.error(f"Error clearing analysis data: {str(e)}")
            messages.error(request, f'Error clearing analysis data: {str(e)}')
    
    return redirect('dashboard')


@login_required
def instance_configurations(request):
    """View and filter Redis configurations"""
    # Get filter parameters
    role_filter = request.GET.get('role', '')
    category_filter = request.GET.get('category', '')
    parameter_filter = request.GET.get('parameter', '')
    instance_filter = request.GET.get('instance', '')
    search_query = request.GET.get('search', '')
    
    # Base queryset - only current user's data
    configurations = RedisConfiguration.objects.select_related('instance').filter(
        instance__analysis_session__user=request.user
    ).distinct()
    
    # Apply filters
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
    
    # Get filter options for dropdowns - only current user's data, properly deduplicated
    roles = list(set(RedisInstance.objects.filter(analysis_session__user=request.user).values_list('role', flat=True).distinct()))
    categories = list(set(RedisConfiguration.objects.filter(instance__analysis_session__user=request.user).values_list('category', flat=True).distinct()))
    instances = RedisInstance.objects.filter(analysis_session__user=request.user).values('ip_address', 'port', 'role').distinct().order_by('ip_address', 'port')
    
    # Pagination
    paginator = Paginator(configurations, 50)  # Show 50 configurations per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'configurations': page_obj,
        'roles': roles,
        'categories': categories,
        'instances': instances,
        'current_filters': {
            'role': role_filter,
            'category': category_filter,
            'parameter': parameter_filter,
            'instance': instance_filter,
            'search': search_query,
        }
    }
    
    return render(request, 'analyzer/configurations.html', context)


@login_required
def instance_detail(request, instance_id):
    """View detailed information about a specific Redis instance"""
    instance = get_object_or_404(RedisInstance, id=instance_id, analysis_session__user=request.user)
    configurations = instance.configurations.all().order_by('category', 'parameter_name')
    
    # Get replication info
    master_replications = instance.master_replications.all()
    slave_replications = instance.slave_replications.all()
    
    # Get keyspace information
    keyspace_info = instance.keyspace_info.all().order_by('database_name')
    
    # Get anomalies for this instance
    anomalies = AnomalyDetection.objects.filter(redis_instance=instance).select_related('rule').order_by('-detected_at')
    anomaly_count = anomalies.count()
    critical_anomalies = anomalies.filter(rule__severity='critical').count()
    warning_anomalies = anomalies.filter(rule__severity='warning').count()
    unresolved_anomalies = anomalies.filter(status='detected').count()
    
    # Get configuration parameters that have anomalies
    anomalous_configs = set()
    config_anomaly_info = {}  # Maps config parameter name to anomaly info
    for anomaly in anomalies:
        if anomaly.affected_configs:
            for config_name in anomaly.affected_configs.keys():
                anomalous_configs.add(config_name)
                if config_name not in config_anomaly_info:
                    config_anomaly_info[config_name] = {
                        'anomalies': [],
                        'highest_severity': 'notice',
                        'count': 0
                    }
                config_anomaly_info[config_name]['anomalies'].append(anomaly)
                config_anomaly_info[config_name]['count'] += 1
                # Track highest severity
                current_severity = config_anomaly_info[config_name]['highest_severity']
                if anomaly.rule.severity == 'critical' or (anomaly.rule.severity == 'warning' and current_severity == 'notice'):
                    config_anomaly_info[config_name]['highest_severity'] = anomaly.rule.severity
    
    # Attach anomaly information to configuration objects
    for config in configurations:
        param_name = config.parameter_name
        if param_name in config_anomaly_info:
            config.has_anomaly = True
            config.highest_severity = config_anomaly_info[param_name]['highest_severity']
            config.anomaly_count = config_anomaly_info[param_name]['count']
            config.related_anomalies = config_anomaly_info[param_name]['anomalies']
        else:
            config.has_anomaly = False
            config.highest_severity = None
            config.anomaly_count = 0
            config.related_anomalies = []
    
    # Group configurations by category
    configs_by_category = {}
    for config in configurations:
        if config.category not in configs_by_category:
            configs_by_category[config.category] = []
        configs_by_category[config.category].append(config)
    
    context = {
        'instance': instance,
        'configurations': configurations,
        'configs_by_category': configs_by_category,
        'master_replications': master_replications,
        'slave_replications': slave_replications,
        'keyspace_info': keyspace_info,
        'anomalies': anomalies[:5],  # Show recent 5 anomalies
        'anomaly_count': anomaly_count,
        'critical_anomalies': critical_anomalies,
        'warning_anomalies': warning_anomalies,
        'unresolved_anomalies': unresolved_anomalies,
        'anomalous_configs': anomalous_configs,
        'config_anomaly_info': config_anomaly_info,
    }
    
    return render(request, 'analyzer/instance_detail.html', context)


# ================== SENTINEL ANALYSIS VIEWS ==================

@login_required
def sentinel_analyze(request):
    """Start Sentinel analysis"""
    if request.method == 'POST':
        sentinel_ip = request.POST.get('sentinel_ip')
        sentinel_port = int(request.POST.get('sentinel_port', 26379))
        password = request.POST.get('password', '')
        session_name = request.POST.get('session_name', '')
        analysis_type = request.POST.get('analysis_type', 'full')
        
        if not sentinel_ip:
            messages.error(request, 'Sentinel IP address is required')
            return redirect('sentinel_analyze')
        
        try:
            analyzer = SentinelAnalyzer(user=request.user, session_name=session_name)
            
            if analysis_type == 'config':
                session = analyzer.analyze_sentinel_configuration(
                    sentinel_ip, sentinel_port, password if password else None
                )
            elif analysis_type == 'discovery':
                session = analyzer.analyze_sentinel_masters(
                    sentinel_ip, sentinel_port, password if password else None
                )
            elif analysis_type == 'topology':
                session = analyzer.analyze_sentinel_topology(
                    sentinel_ip, sentinel_port, password if password else None
                )
            else:  # full
                session = analyzer.analyze_sentinel_full(
                    sentinel_ip, sentinel_port, password if password else None
                )
            
            if session.status == 'completed':
                messages.success(request, f'Sentinel analysis completed successfully.')
            elif session.status == 'partial':
                messages.warning(request, f'Sentinel analysis partially completed.')
            else:
                messages.error(request, f'Sentinel analysis failed: {session.error_message}')
            
            return redirect('sentinel_analysis_detail', session_id=session.id)
            
        except Exception as e:
            logger.error(f"Sentinel analysis error: {str(e)}")
            messages.error(request, f'Sentinel analysis failed: {str(e)}')
            return redirect('sentinel_analyze')
    
    return render(request, 'analyzer/sentinel_analyze.html')


@login_required
def sentinel_analysis_detail(request, session_id):
    """View Sentinel analysis session details"""
    session = get_object_or_404(SentinelAnalysisSession, id=session_id, user=request.user)
    
    # Get Sentinel instances from this session (user-filtered for security)
    sentinels = SentinelInstance.objects.filter(
        analysis_session=session
    ).order_by('ip_address')
    
    # Get monitored masters (user-filtered for security) and deduplicate by master name + IP
    all_monitored_masters = MonitoredMaster.objects.filter(
        sentinel__analysis_session__user=request.user,
        sentinel__in=sentinels
    ).select_related('redis_instance', 'sentinel').order_by('master_name', 'master_ip', 'master_port', '-created_at')
    
    # Deduplicate masters based on master_name + IP:port combination
    # Keep the most recent entry for each unique master
    unique_masters = {}
    for master in all_monitored_masters:
        master_key = f"{master.master_name}:{master.master_ip}:{master.master_port}"
        if master_key not in unique_masters:
            unique_masters[master_key] = master
    
    monitored_masters = sorted(unique_masters.values(), key=lambda x: x.master_name)
    
    # Get Redis instances (if master discovery was performed) (user-filtered for security)
    redis_instances = []
    if session.analysis_type in ['discovery', 'full', 'topology']:
        # Filter Redis instances created during this specific sentinel session
        end_time = session.analysis_end_time or timezone.now()
        redis_instances = RedisInstance.objects.filter(
            analysis_session__user=request.user,
            created_at__gte=session.analysis_start_time,
            created_at__lte=end_time
        ).order_by('role', 'ip_address')
    
    context = {
        'session': session,
        'sentinels': sentinels,
        'monitored_masters': monitored_masters,
        'redis_instances': redis_instances,
        'total_sentinels': sentinels.count(),
        'total_masters': len(monitored_masters),  # Use len() since monitored_masters is now a list
        'total_redis_instances': redis_instances.count() if redis_instances else 0,
    }
    
    return render(request, 'analyzer/sentinel_analysis_detail.html', context)


@login_required
def sentinel_configurations(request):
    """View and filter Sentinel configurations"""
    # Get filter parameters
    sentinel_filter = request.GET.get('sentinel', '')
    category_filter = request.GET.get('category', '')
    parameter_filter = request.GET.get('parameter', '')
    master_filter = request.GET.get('master', '')
    search_query = request.GET.get('search', '')
    
    # Base queryset - only current user's data
    configurations = SentinelConfiguration.objects.select_related('sentinel').filter(
        sentinel__analysis_session__user=request.user
    ).distinct()
    
    # Apply filters
    if sentinel_filter:
        configurations = configurations.filter(
            Q(sentinel__ip_address__icontains=sentinel_filter)
        )
    
    if category_filter:
        configurations = configurations.filter(category=category_filter)
    
    if parameter_filter:
        configurations = configurations.filter(parameter_name__icontains=parameter_filter)
    
    if master_filter:
        configurations = configurations.filter(master_name__icontains=master_filter)
    
    if search_query:
        configurations = configurations.filter(
            Q(parameter_name__icontains=search_query) |
            Q(parameter_value__icontains=search_query) |
            Q(sentinel__ip_address__icontains=search_query) |
            Q(master_name__icontains=search_query)
        )
    
    # Get filter options for dropdowns - only current user's data, properly deduplicated
    sentinels = SentinelInstance.objects.filter(analysis_session__user=request.user).values('ip_address', 'port').distinct().order_by('ip_address', 'port')
    categories = list(set(SentinelConfiguration.objects.filter(sentinel__analysis_session__user=request.user).values_list('category', flat=True).distinct()))
    masters = list(set(SentinelConfiguration.objects.filter(sentinel__analysis_session__user=request.user).exclude(master_name='').values_list('master_name', flat=True).distinct()))
    
    # Pagination
    paginator = Paginator(configurations, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'configurations': page_obj,
        'sentinels': sentinels,
        'categories': categories,
        'masters': masters,
        'current_filters': {
            'sentinel': sentinel_filter,
            'category': category_filter,
            'parameter': parameter_filter,
            'master': master_filter,
            'search': search_query,
        }
    }
    
    return render(request, 'analyzer/sentinel_configurations.html', context)


@login_required
def monitored_masters(request):
    """View monitored masters"""
    # Get filter parameters
    sentinel_filter = request.GET.get('sentinel', '')
    status_filter = request.GET.get('status', '')
    search_query = request.GET.get('search', '')
    
    # Base queryset - only current user's data
    masters = MonitoredMaster.objects.select_related('sentinel', 'redis_instance').filter(
        sentinel__analysis_session__user=request.user
    ).distinct()
    
    # Apply filters
    if sentinel_filter:
        masters = masters.filter(sentinel__ip_address__icontains=sentinel_filter)
    
    if status_filter:
        masters = masters.filter(status=status_filter)
    
    if search_query:
        masters = masters.filter(
            Q(master_name__icontains=search_query) |
            Q(master_ip__icontains=search_query) |
            Q(sentinel__ip_address__icontains=search_query)
        )
    
    # Get filter options - only current user's data, properly deduplicated
    sentinels = SentinelInstance.objects.filter(analysis_session__user=request.user).values('ip_address', 'port').distinct().order_by('ip_address', 'port')
    statuses = list(set(MonitoredMaster.objects.filter(sentinel__analysis_session__user=request.user).values_list('status', flat=True).distinct()))
    
    # Pagination
    paginator = Paginator(masters, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'masters': page_obj,
        'sentinels': sentinels,
        'statuses': statuses,
        'current_filters': {
            'sentinel': sentinel_filter,
            'status': status_filter,
            'search': search_query,
        }
    }
    
    return render(request, 'analyzer/monitored_masters.html', context)


@login_required
def sentinel_detail(request, sentinel_id):
    """View detailed information about a specific Sentinel instance"""
    sentinel = get_object_or_404(SentinelInstance, id=sentinel_id, analysis_session__user=request.user)
    configurations = sentinel.configurations.all().order_by('category', 'parameter_name')
    monitored_masters = sentinel.monitored_masters.all().order_by('master_name')
    
    # Group configurations by category
    configs_by_category = {}
    for config in configurations:
        if config.category not in configs_by_category:
            configs_by_category[config.category] = []
        configs_by_category[config.category].append(config)
    
    context = {
        'sentinel': sentinel,
        'configurations': configurations,
        'configs_by_category': configs_by_category,
        'monitored_masters': monitored_masters,
    }
    
    return render(request, 'analyzer/sentinel_detail.html', context)


@login_required
def master_sessions(request):
    """View all Redis master analysis sessions for current user"""
    sessions = AnalysisSession.objects.filter(user=request.user).order_by('-created_at')
    
    # Pagination
    paginator = Paginator(sessions, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'sessions': page_obj,
    }
    
    return render(request, 'analyzer/master_sessions.html', context)


@csrf_exempt
def elb_healthcheck(request):
    """Simple health check endpoint for ELB/load balancer monitoring"""
    return HttpResponse("ok", content_type="text/plain")


@login_required
def sentinel_sessions(request):
    """View all Sentinel analysis sessions for current user"""
    sessions = SentinelAnalysisSession.objects.filter(user=request.user).order_by('-created_at')
    
    # Pagination
    paginator = Paginator(sessions, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'sessions': page_obj,
    }
    
    return render(request, 'analyzer/sentinel_sessions.html', context)


# ================== ANOMALY DETECTION VIEWS ==================

@login_required
def anomaly_dashboard(request):
    """Main anomaly detection dashboard"""
    # Get all anomalies for current user's instances
    user_anomalies = AnomalyDetection.objects.filter(
        Q(redis_instance__analysis_session__user=request.user) |
        Q(sentinel_instance__analysis_session__user=request.user)
    ).select_related('rule', 'redis_instance', 'sentinel_instance').order_by('-detected_at')
    
    # Filter parameters
    severity_filter = request.GET.get('severity', '')
    category_filter = request.GET.get('category', '')
    status_filter = request.GET.get('status', '')
    search_query = request.GET.get('search', '')
    
    # Apply filters
    if severity_filter:
        user_anomalies = user_anomalies.filter(rule__severity=severity_filter)
    
    if category_filter:
        user_anomalies = user_anomalies.filter(rule__category=category_filter)
    
    if status_filter:
        user_anomalies = user_anomalies.filter(status=status_filter)
    
    if search_query:
        user_anomalies = user_anomalies.filter(
            Q(rule__rule_id__icontains=search_query) |
            Q(rule__anomaly_description__icontains=search_query) |
            Q(redis_instance__ip_address__icontains=search_query) |
            Q(sentinel_instance__ip_address__icontains=search_query)
        )
    
    # Get statistics
    total_anomalies = user_anomalies.count()
    critical_count = user_anomalies.filter(rule__severity='critical').count()
    warning_count = user_anomalies.filter(rule__severity='warning').count()
    notice_count = user_anomalies.filter(rule__severity='notice').count()
    
    # Count by status
    detected_count = user_anomalies.filter(status='detected').count()
    acknowledged_count = user_anomalies.filter(status='acknowledged').count()
    resolved_count = user_anomalies.filter(status='resolved').count()
    false_positive_count = user_anomalies.filter(status='false_positive').count()
    
    # Count by category
    category_counts = {}
    for anomaly in user_anomalies:
        category = anomaly.rule.get_category_display()
        category_counts[category] = category_counts.get(category, 0) + 1
    
    # Recent anomalies for quick view
    recent_anomalies = user_anomalies[:10]
    
    # Get filter options
    severities = AnomalyRule.SEVERITY_CHOICES
    categories = AnomalyRule.CATEGORY_CHOICES
    statuses = AnomalyDetection.STATUS_CHOICES
    
    # Pagination
    paginator = Paginator(user_anomalies, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'anomalies': page_obj,
        'recent_anomalies': recent_anomalies,
        'total_anomalies': total_anomalies,
        'critical_count': critical_count,
        'warning_count': warning_count,
        'notice_count': notice_count,
        'detected_count': detected_count,
        'acknowledged_count': acknowledged_count,
        'resolved_count': resolved_count,
        'false_positive_count': false_positive_count,
        'category_counts': category_counts,
        'severities': severities,
        'categories': categories,
        'statuses': statuses,
        'current_filters': {
            'severity': severity_filter,
            'category': category_filter,
            'status': status_filter,
            'search': search_query,
        }
    }
    
    return render(request, 'analyzer/anomaly_dashboard.html', context)


@login_required
def anomaly_detail(request, anomaly_id):
    """View detailed information about a specific anomaly"""
    anomaly = get_object_or_404(
        AnomalyDetection, 
        id=anomaly_id,
        redis_instance__analysis_session__user=request.user
    ) if AnomalyDetection.objects.filter(
        id=anomaly_id, 
        redis_instance__analysis_session__user=request.user
    ).exists() else get_object_or_404(
        AnomalyDetection,
        id=anomaly_id,
        sentinel_instance__analysis_session__user=request.user
    )
    
    context = {
        'anomaly': anomaly,
        'instance': anomaly.redis_instance or anomaly.sentinel_instance,
    }
    
    return render(request, 'analyzer/anomaly_detail.html', context)


@login_required
@require_http_methods(["POST"])
def update_anomaly_status(request, anomaly_id):
    """Update anomaly status (acknowledge, resolve, etc.)"""
    anomaly = get_object_or_404(
        AnomalyDetection,
        id=anomaly_id
    )
    
    # Verify user owns this anomaly
    if anomaly.redis_instance:
        if anomaly.redis_instance.analysis_session.user != request.user:
            return JsonResponse({'error': 'Not authorized'}, status=403)
    elif anomaly.sentinel_instance:
        if anomaly.sentinel_instance.analysis_session.user != request.user:
            return JsonResponse({'error': 'Not authorized'}, status=403)
    
    new_status = request.POST.get('status')
    notes = request.POST.get('notes', '')
    
    if new_status not in ['detected', 'acknowledged', 'resolved', 'false_positive']:
        return JsonResponse({'error': 'Invalid status'}, status=400)
    
    old_status = anomaly.status
    anomaly.status = new_status
    anomaly.notes = notes
    
    if new_status == 'acknowledged' and old_status != 'acknowledged':
        anomaly.acknowledged_at = timezone.now()
        anomaly.acknowledged_by = request.user
    elif new_status == 'resolved' and old_status != 'resolved':
        anomaly.resolved_at = timezone.now()
        anomaly.resolved_by = request.user
    
    anomaly.save()
    
    messages.success(request, f'Anomaly status updated to {new_status}')
    
    return JsonResponse({
        'success': True,
        'new_status': new_status,
        'status_display': anomaly.get_status_display()
    })


@login_required
def run_anomaly_detection(request):
    """Run anomaly detection on user's instances"""
    if request.method == 'POST':
        try:
            detector = AnomalyDetector()
            results = detector.run_full_detection(user_instances_only=True, user=request.user)
            
            messages.success(
                request,
                f'Anomaly detection completed. Analyzed {results["total_instances_analyzed"]} Redis instances '
                f'and {results["total_sentinels_analyzed"]} Sentinels. '
                f'Found {results["newly_detected"]} new anomalies.'
            )
            
            if results['errors']:
                for error in results['errors'][:3]:  # Show first 3 errors
                    messages.warning(request, f'Detection error: {error}')
            
        except Exception as e:
            logger.error(f"Error running anomaly detection: {str(e)}")
            messages.error(request, f'Anomaly detection failed: {str(e)}')
    
    return redirect('anomaly_dashboard')


@login_required
def anomaly_rules(request):
    """View and manage anomaly detection rules"""
    # Get filter parameters
    category_filter = request.GET.get('category', '')
    severity_filter = request.GET.get('severity', '')
    search_query = request.GET.get('search', '')
    active_only = request.GET.get('active_only', 'true') == 'true'
    
    # Base queryset
    rules = AnomalyRule.objects.all()
    
    # Apply filters
    if category_filter:
        rules = rules.filter(category=category_filter)
    
    if severity_filter:
        rules = rules.filter(severity=severity_filter)
    
    if active_only:
        rules = rules.filter(is_active=True)
    
    if search_query:
        rules = rules.filter(
            Q(rule_id__icontains=search_query) |
            Q(anomaly_description__icontains=search_query) |
            Q(directives__icontains=search_query)
        )
    
    # Get filter options
    categories = AnomalyRule.CATEGORY_CHOICES
    severities = AnomalyRule.SEVERITY_CHOICES
    
    # Pagination
    paginator = Paginator(rules, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'rules': page_obj,
        'categories': categories,
        'severities': severities,
        'current_filters': {
            'category': category_filter,
            'severity': severity_filter,
            'search': search_query,
            'active_only': active_only,
        }
    }
    
    return render(request, 'analyzer/anomaly_rules.html', context)


@login_required
def instance_anomalies(request, instance_id):
    """View anomalies for a specific Redis instance"""
    instance = get_object_or_404(RedisInstance, id=instance_id, analysis_session__user=request.user)
    
    anomalies = AnomalyDetection.objects.filter(
        redis_instance=instance
    ).select_related('rule').order_by('-detected_at')
    
    # Calculate statistics
    critical_anomalies = anomalies.filter(rule__severity='critical').count()
    warning_anomalies = anomalies.filter(rule__severity='warning').count()
    unresolved_anomalies = anomalies.filter(status='detected').count()
    
    # Run detection if requested
    if request.method == 'POST' and request.POST.get('action') == 'detect':
        try:
            detector = AnomalyDetector()
            new_anomalies = detector.detect_instance_anomalies(instance)
            
            messages.success(
                request,
                f'Anomaly detection completed for {instance}. '
                f'Found {len([a for a in new_anomalies if a])} new anomalies.'
            )
        except Exception as e:
            logger.error(f"Error detecting anomalies for instance {instance}: {str(e)}")
            messages.error(request, f'Anomaly detection failed: {str(e)}')
        
        return redirect('instance_anomalies', instance_id=instance_id)
    
    context = {
        'instance': instance,
        'anomalies': anomalies,
        'critical_anomalies': critical_anomalies,
        'warning_anomalies': warning_anomalies,
        'unresolved_anomalies': unresolved_anomalies,
    }
    
    return render(request, 'analyzer/instance_anomalies.html', context)


@login_required
def sentinel_anomalies(request, sentinel_id):
    """View anomalies for a specific Sentinel instance"""
    sentinel = get_object_or_404(SentinelInstance, id=sentinel_id, analysis_session__user=request.user)
    
    anomalies = AnomalyDetection.objects.filter(
        sentinel_instance=sentinel
    ).select_related('rule').order_by('-detected_at')
    
    # Calculate statistics
    critical_anomalies = anomalies.filter(rule__severity='critical').count()
    warning_anomalies = anomalies.filter(rule__severity='warning').count()
    unresolved_anomalies = anomalies.filter(status='detected').count()
    
    # Run detection if requested
    if request.method == 'POST' and request.POST.get('action') == 'detect':
        try:
            detector = AnomalyDetector()
            new_anomalies = detector.detect_sentinel_anomalies(sentinel)
            
            messages.success(
                request,
                f'Anomaly detection completed for {sentinel}. '
                f'Found {len([a for a in new_anomalies if a])} new anomalies.'
            )
        except Exception as e:
            logger.error(f"Error detecting anomalies for sentinel {sentinel}: {str(e)}")
            messages.error(request, f'Anomaly detection failed: {str(e)}')
        
        return redirect('sentinel_anomalies', sentinel_id=sentinel_id)
    
    context = {
        'sentinel': sentinel,
        'anomalies': anomalies,
        'critical_anomalies': critical_anomalies,
        'warning_anomalies': warning_anomalies,
        'unresolved_anomalies': unresolved_anomalies,
    }
    
    return render(request, 'analyzer/sentinel_anomalies.html', context)