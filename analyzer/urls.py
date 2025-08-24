from django.urls import path
from . import views
from . import export_views

urlpatterns = [
    # Health check endpoint
    path('elb-healthcheck/', views.elb_healthcheck, name='elb_healthcheck'),
    
    # Main views
    path('', views.dashboard, name='dashboard'),
    
    # Educational and Guided Setup
    path('concepts/', views.redis_concepts, name='redis_concepts'),
    path('guided-setup/', views.guided_setup, name='guided_setup'),
    
    # Analysis selection parent page
    path('analysis/', views.analysis_selection, name='analysis_selection'),
    
    # Specific analysis pages
    path('analyze/', views.analyze_redis, name='analyze_redis'),
    path('analysis/<int:session_id>/', views.analysis_detail, name='analysis_detail'),
    path('configurations/', views.instance_configurations, name='instance_configurations'),
    path('sessions/', views.master_sessions, name='master_sessions'),
    path('instance/<int:instance_id>/', views.instance_detail, name='instance_detail'),
    path('clear-all/', views.clear_all_analysis, name='clear_all_analysis'),
    
    # Sentinel views
    path('sentinel/analyze/', views.sentinel_analyze, name='sentinel_analyze'),
    path('sentinel/analysis/<int:session_id>/', views.sentinel_analysis_detail, name='sentinel_analysis_detail'),
    path('sentinel/configurations/', views.sentinel_configurations, name='sentinel_configurations'),
    path('sentinel/masters/', views.monitored_masters, name='monitored_masters'),
    path('sentinel/<int:sentinel_id>/', views.sentinel_detail, name='sentinel_detail'),
    path('sentinel/sessions/', views.sentinel_sessions, name='sentinel_sessions'),
    path('sentinel/export/<int:session_id>/', export_views.export_sentinel_session, name='export_sentinel_session'),
    
    # Export views
    path('export/configurations/', export_views.export_configurations_csv, name='export_configurations_csv'),
    path('export/instances/', export_views.export_instances_csv, name='export_instances_csv'),
    
    # Anomaly detection views
    path('anomalies/', views.anomaly_dashboard, name='anomaly_dashboard'),
    path('anomalies/<int:anomaly_id>/', views.anomaly_detail, name='anomaly_detail'),
    path('anomalies/<int:anomaly_id>/update-status/', views.update_anomaly_status, name='update_anomaly_status'),
    path('anomalies/rules/', views.anomaly_rules, name='anomaly_rules'),
    path('anomalies/detect/', views.run_anomaly_detection, name='run_anomaly_detection'),
    path('instance/<int:instance_id>/anomalies/', views.instance_anomalies, name='instance_anomalies'),
    path('sentinel/<int:sentinel_id>/anomalies/', views.sentinel_anomalies, name='sentinel_anomalies'),
]