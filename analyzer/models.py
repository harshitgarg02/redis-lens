from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


class RedisInstance(models.Model):
    """Model to store Redis instance information"""
    
    ROLE_CHOICES = [
        ('master', 'Master'),
        ('slave', 'Slave'),
        ('replica', 'Replica'),
    ]
    
    STATUS_CHOICES = [
        ('online', 'Online'),
        ('offline', 'Offline'),
        ('error', 'Error'),
    ]
    
    analysis_session = models.ForeignKey('AnalysisSession', on_delete=models.CASCADE, null=True, blank=True, related_name='instances')
    ip_address = models.GenericIPAddressField()
    port = models.IntegerField(default=6379)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    master_ip = models.GenericIPAddressField(null=True, blank=True)
    master_port = models.IntegerField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='offline')
    version = models.CharField(max_length=50, blank=True)
    uptime_seconds = models.BigIntegerField(null=True, blank=True)
    connected_clients = models.IntegerField(null=True, blank=True)
    max_clients = models.IntegerField(null=True, blank=True)  # Maximum number of clients
    master_name = models.CharField(max_length=100, blank=True, null=True)  # Master name (for masters)
    used_memory = models.BigIntegerField(null=True, blank=True)  # in bytes
    used_memory_human = models.CharField(max_length=20, blank=True)
    maxmemory = models.BigIntegerField(null=True, blank=True)  # in bytes
    maxmemory_human = models.CharField(max_length=20, blank=True)
    keyspace_hits = models.BigIntegerField(null=True, blank=True)
    keyspace_misses = models.BigIntegerField(null=True, blank=True)
    total_keys = models.BigIntegerField(null=True, blank=True)  # Total keys across all databases
    total_commands_processed = models.BigIntegerField(null=True, blank=True)
    raw_info_output = models.TextField(blank=True, null=True)  # Raw Redis INFO command output
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['analysis_session', 'ip_address', 'port']
        ordering = ['role', 'ip_address']
    
    def __str__(self):
        return f"{self.ip_address}:{self.port} ({self.role})"
    
    @property
    def hit_ratio(self):
        """Calculate hit ratio percentage"""
        if self.keyspace_hits and self.keyspace_misses:
            total = self.keyspace_hits + self.keyspace_misses
            return round((self.keyspace_hits / total) * 100, 2) if total > 0 else 0
        return 0
    
    @property
    def memory_usage_percentage(self):
        """Calculate memory usage percentage"""
        if self.used_memory and self.maxmemory:
            return round((self.used_memory / self.maxmemory) * 100, 2)
        return 0


class RedisConfiguration(models.Model):
    """Model to store Redis configuration parameters"""
    
    CONFIG_CATEGORIES = [
        ('general', 'General'),
        ('memory', 'Memory'),
        ('persistence', 'Persistence'),
        ('replication', 'Replication'),
        ('security', 'Security'),
        ('networking', 'Networking'),
        ('logging', 'Logging'),
        ('slowlog', 'Slowlog'),
        ('clients', 'Clients'),
        ('modules', 'Modules'),
        ('other', 'Other'),
    ]
    
    instance = models.ForeignKey(RedisInstance, on_delete=models.CASCADE, related_name='configurations')
    parameter_name = models.CharField(max_length=100)
    parameter_value = models.TextField(blank=True)
    category = models.CharField(max_length=20, choices=CONFIG_CATEGORIES, default='other')
    is_default = models.BooleanField(default=False)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['instance', 'parameter_name']
        ordering = ['category', 'parameter_name']
    
    def __str__(self):
        return f"{self.instance} - {self.parameter_name}: {self.parameter_value}"


class KeyspaceInfo(models.Model):
    """Model to store database-wise keyspace information"""
    
    instance = models.ForeignKey(RedisInstance, on_delete=models.CASCADE, related_name='keyspace_info')
    database_name = models.CharField(max_length=20)  # db0, db1, etc.
    keys_count = models.BigIntegerField(default=0)
    expires_count = models.BigIntegerField(default=0, null=True, blank=True)
    avg_ttl = models.BigIntegerField(default=0, null=True, blank=True)  # in milliseconds
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['instance', 'database_name']
        ordering = ['database_name']
    
    def __str__(self):
        return f"{self.instance} - {self.database_name}: {self.keys_count} keys"


class AnalysisSession(models.Model):
    """Model to track analysis sessions"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='redis_analysis_sessions')
    master_ip = models.GenericIPAddressField()
    master_port = models.IntegerField(default=6379)
    session_name = models.CharField(max_length=100, blank=True)
    total_instances_found = models.IntegerField(default=0)
    successful_connections = models.IntegerField(default=0)
    failed_connections = models.IntegerField(default=0)
    analysis_start_time = models.DateTimeField(default=timezone.now)
    analysis_end_time = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ('running', 'Running'),
            ('completed', 'Completed'),
            ('failed', 'Failed'),
            ('partial', 'Partial'),
        ],
        default='running'
    )
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Analysis of {self.master_ip}:{self.master_port} - {self.status}"
    
    @property
    def duration(self):
        """Calculate analysis duration"""
        if self.analysis_end_time:
            return self.analysis_end_time - self.analysis_start_time
        return timezone.now() - self.analysis_start_time


class ReplicationInfo(models.Model):
    """Model to store Redis replication information"""
    
    master_instance = models.ForeignKey(
        RedisInstance, 
        on_delete=models.CASCADE, 
        related_name='master_replications'
    )
    slave_instance = models.ForeignKey(
        RedisInstance, 
        on_delete=models.CASCADE, 
        related_name='slave_replications'
    )
    replication_offset = models.BigIntegerField(null=True, blank=True)
    lag_in_seconds = models.IntegerField(null=True, blank=True)
    replication_state = models.CharField(max_length=50, blank=True)
    priority = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['master_instance', 'slave_instance']
    
    def __str__(self):
        return f"{self.master_instance} -> {self.slave_instance}"


class SentinelInstance(models.Model):
    """Model to store Redis Sentinel instance information"""
    
    STATUS_CHOICES = [
        ('online', 'Online'),
        ('offline', 'Offline'),
        ('error', 'Error'),
    ]
    
    analysis_session = models.ForeignKey('SentinelAnalysisSession', on_delete=models.CASCADE, null=True, blank=True, related_name='sentinels')
    ip_address = models.GenericIPAddressField()
    port = models.IntegerField(default=26379)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='offline')
    version = models.CharField(max_length=50, blank=True)
    uptime_seconds = models.BigIntegerField(null=True, blank=True)
    sentinel_id = models.CharField(max_length=100, blank=True)  # Sentinel ID from INFO
    known_sentinels = models.IntegerField(null=True, blank=True)  # Number of known sentinels
    known_slaves = models.IntegerField(null=True, blank=True)  # Total known slaves
    masters_count = models.IntegerField(null=True, blank=True)  # Number of monitored masters
    connected_clients = models.IntegerField(null=True, blank=True)  # Number of connected clients
    max_clients = models.IntegerField(null=True, blank=True)  # Maximum number of clients
    raw_info_output = models.TextField(blank=True, null=True)  # Raw Sentinel INFO command output
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['analysis_session', 'ip_address', 'port']
        ordering = ['ip_address']
    
    def __str__(self):
        return f"Sentinel {self.ip_address}:{self.port}"


class SentinelConfiguration(models.Model):
    """Model to store Sentinel configuration parameters"""
    
    CONFIG_CATEGORIES = [
        ('general', 'General'),
        ('monitoring', 'Monitoring'),
        ('notification', 'Notification'),
        ('failover', 'Failover'),
        ('security', 'Security'),
        ('networking', 'Networking'),
        ('logging', 'Logging'),
        ('other', 'Other'),
    ]
    
    sentinel = models.ForeignKey(SentinelInstance, on_delete=models.CASCADE, related_name='configurations')
    parameter_name = models.CharField(max_length=100)
    parameter_value = models.TextField(blank=True)
    category = models.CharField(max_length=20, choices=CONFIG_CATEGORIES, default='other')
    master_name = models.CharField(max_length=100, blank=True)  # If parameter is master-specific
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['sentinel', 'parameter_name', 'master_name']
        ordering = ['category', 'parameter_name']
    
    def __str__(self):
        if self.master_name:
            return f"{self.sentinel} - {self.master_name} - {self.parameter_name}: {self.parameter_value}"
        return f"{self.sentinel} - {self.parameter_name}: {self.parameter_value}"


class MonitoredMaster(models.Model):
    """Model to store information about masters monitored by Sentinel"""
    
    STATUS_CHOICES = [
        ('master', 'Master'),
        ('down', 'Down'),
        ('failover', 'Failover in Progress'),
        ('disconnected', 'Disconnected'),
    ]
    
    sentinel = models.ForeignKey(SentinelInstance, on_delete=models.CASCADE, related_name='monitored_masters')
    master_name = models.CharField(max_length=100)  # Master name in Sentinel config
    master_ip = models.GenericIPAddressField()
    master_port = models.IntegerField(default=6379)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='master')
    quorum = models.IntegerField(null=True, blank=True)  # Required quorum for failover
    down_after_milliseconds = models.IntegerField(null=True, blank=True)
    failover_timeout = models.IntegerField(null=True, blank=True)
    parallel_syncs = models.IntegerField(null=True, blank=True)
    last_ping_sent = models.IntegerField(null=True, blank=True)
    last_ok_ping_reply = models.IntegerField(null=True, blank=True)
    last_ping_reply = models.IntegerField(null=True, blank=True)
    num_slaves = models.IntegerField(null=True, blank=True)
    num_other_sentinels = models.IntegerField(null=True, blank=True)
    # Link to actual Redis instance if analyzed
    redis_instance = models.ForeignKey(RedisInstance, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['sentinel', 'master_name']
        ordering = ['master_name']
    
    def __str__(self):
        return f"{self.sentinel} monitors {self.master_name} ({self.master_ip}:{self.master_port})"


class SentinelAnalysisSession(models.Model):
    """Model to track Sentinel analysis sessions"""
    
    ANALYSIS_TYPE_CHOICES = [
        ('config', 'Sentinel Configuration Analysis'),
        ('discovery', 'Sentinel Master Discovery Analysis'),
        ('full', 'Full Sentinel Analysis'),
        ('topology', 'Topology Discovery Analysis'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sentinel_analysis_sessions')
    sentinel_ip = models.GenericIPAddressField()
    sentinel_port = models.IntegerField(default=26379)
    analysis_type = models.CharField(max_length=10, choices=ANALYSIS_TYPE_CHOICES)
    session_name = models.CharField(max_length=100, blank=True)
    total_sentinels_found = models.IntegerField(default=0)
    total_masters_found = models.IntegerField(default=0)
    total_instances_analyzed = models.IntegerField(default=0)
    successful_connections = models.IntegerField(default=0)
    failed_connections = models.IntegerField(default=0)
    analysis_start_time = models.DateTimeField(default=timezone.now)
    analysis_end_time = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ('running', 'Running'),
            ('completed', 'Completed'),
            ('failed', 'Failed'),
            ('partial', 'Partial'),
        ],
        default='running'
    )
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Sentinel Analysis of {self.sentinel_ip}:{self.sentinel_port} - {self.get_analysis_type_display()} - {self.status}"
    
    @property
    def duration(self):
        """Calculate analysis duration"""
        if self.analysis_end_time:
            return self.analysis_end_time - self.analysis_start_time
        return timezone.now() - self.analysis_start_time


class AnomalyRule(models.Model):
    """Model to store Redis configuration anomaly detection rules"""
    
    SEVERITY_CHOICES = [
        ('notice', 'Notice'),
        ('warning', 'Warning'), 
        ('critical', 'Critical'),
    ]
    
    CATEGORY_CHOICES = [
        ('client_management', 'Client Management'),
        ('logging', 'Logging'),
        ('process_management', 'Process Management'),
        ('memory', 'Memory'),
        ('network', 'Network'),
        ('security', 'Security'),
        ('performance', 'Performance'),
        ('data_structures', 'Data Structures'),
        ('persistence', 'Persistence'),
        ('replication', 'Replication'),
    ]
    
    rule_id = models.CharField(max_length=20, unique=True)  # e.g., CLIENT-001
    directives = models.TextField()  # Comma-separated list of config directives
    category = models.CharField(max_length=30, choices=CATEGORY_CHOICES)
    anomaly_description = models.TextField()
    detection_logic = models.TextField()  # The IF condition logic
    recommended_state = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    is_active = models.BooleanField(default=True)  # Allow enabling/disabling rules
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['rule_id']
    
    def __str__(self):
        return f"{self.rule_id} - {self.anomaly_description[:50]}..."
    
    @property
    def directive_list(self):
        """Return list of directives this rule checks"""
        return [d.strip() for d in self.directives.split(',')]


class AnomalyDetection(models.Model):
    """Model to store detected anomalies for Redis instances"""
    
    STATUS_CHOICES = [
        ('detected', 'Detected'),
        ('acknowledged', 'Acknowledged'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]
    
    redis_instance = models.ForeignKey(RedisInstance, on_delete=models.CASCADE, related_name='anomalies')
    sentinel_instance = models.ForeignKey(SentinelInstance, on_delete=models.CASCADE, related_name='anomalies', null=True, blank=True)
    rule = models.ForeignKey(AnomalyRule, on_delete=models.CASCADE, related_name='detections')
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='detected')
    affected_configs = models.JSONField(default=dict)  # Store actual config values that triggered the rule
    detection_context = models.JSONField(default=dict)  # Additional context data for debugging
    notes = models.TextField(blank=True)  # User notes for acknowledged/resolved anomalies
    detected_at = models.DateTimeField(default=timezone.now)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    acknowledged_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='acknowledged_anomalies')
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_anomalies')
    
    class Meta:
        ordering = ['-detected_at']
        unique_together = ['redis_instance', 'sentinel_instance', 'rule']  # Prevent duplicate detections
    
    def __str__(self):
        instance = self.redis_instance or self.sentinel_instance
        return f"{instance} - {self.rule.rule_id} ({self.status})"
    
    @property
    def severity(self):
        """Get severity from the associated rule"""
        return self.rule.severity
    
    @property
    def category(self):
        """Get category from the associated rule"""
        return self.rule.category