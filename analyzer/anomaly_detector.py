import re
import logging
from typing import List, Dict, Any, Optional
from django.db.models import Q
from .models import (
    RedisInstance, SentinelInstance, RedisConfiguration, SentinelConfiguration,
    AnomalyRule, AnomalyDetection
)

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Service class for detecting Redis configuration anomalies"""
    
    def __init__(self):
        self.active_rules = AnomalyRule.objects.filter(is_active=True)
    
    def detect_instance_anomalies(self, instance: RedisInstance) -> List[AnomalyDetection]:
        """
        Detect anomalies for a specific Redis instance
        
        Args:
            instance: RedisInstance to analyze
            
        Returns:
            List of detected anomalies
        """
        detected_anomalies = []
        
        # Get all configurations for this instance
        configs = {
            config.parameter_name: config.parameter_value 
            for config in instance.configurations.all()
        }
        
        # Evaluate each active rule
        for rule in self.active_rules:
            try:
                anomaly = self._evaluate_rule_for_instance(rule, instance, configs)
                if anomaly:
                    detected_anomalies.append(anomaly)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id} for instance {instance}: {str(e)}")
        
        return detected_anomalies
    
    def detect_sentinel_anomalies(self, sentinel: SentinelInstance) -> List[AnomalyDetection]:
        """
        Detect anomalies for a specific Sentinel instance
        
        Args:
            sentinel: SentinelInstance to analyze
            
        Returns:
            List of detected anomalies
        """
        detected_anomalies = []
        
        # Get all configurations for this sentinel
        configs = {
            config.parameter_name: config.parameter_value 
            for config in sentinel.configurations.all()
        }
        
        # Evaluate sentinel-specific rules
        sentinel_rules = self.active_rules.filter(
            Q(category__in=['security', 'networking', 'logging', 'process_management']) |
            Q(directives__icontains='sentinel')
        )
        
        for rule in sentinel_rules:
            try:
                anomaly = self._evaluate_rule_for_sentinel(rule, sentinel, configs)
                if anomaly:
                    detected_anomalies.append(anomaly)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.rule_id} for sentinel {sentinel}: {str(e)}")
        
        return detected_anomalies
    
    def _evaluate_rule_for_instance(self, rule: AnomalyRule, instance: RedisInstance, configs: Dict[str, str]) -> Optional[AnomalyDetection]:
        """
        Evaluate a specific rule against a Redis instance
        
        Args:
            rule: AnomalyRule to evaluate
            instance: RedisInstance being evaluated
            configs: Dictionary of configuration parameters
            
        Returns:
            AnomalyDetection if anomaly detected, None otherwise
        """
        # Check if any of the rule's directives exist in the instance configs
        rule_directives = rule.directive_list
        relevant_configs = {}
        
        for directive in rule_directives:
            # Handle various directive name formats
            normalized_directive = self._normalize_directive_name(directive)
            for config_name, config_value in configs.items():
                if self._matches_directive(config_name, normalized_directive):
                    relevant_configs[config_name] = config_value
        
        if not relevant_configs and not self._is_rule_about_missing_config(rule):
            # Rule requires configs that don't exist on this instance
            return None
        
        # Evaluate the rule logic
        is_anomaly, context = self._evaluate_rule_logic(rule, instance, configs, relevant_configs)
        
        if is_anomaly:
            # Use affected_configs from context if available (for complex rules)
            affected_configs = context.get('affected_configs', relevant_configs)
            
            # Create or get existing anomaly detection
            anomaly, created = AnomalyDetection.objects.get_or_create(
                redis_instance=instance,
                rule=rule,
                defaults={
                    'affected_configs': affected_configs,
                    'detection_context': context,
                    'status': 'detected'
                }
            )
            
            if not created:
                # Update existing anomaly with latest context
                anomaly.affected_configs = affected_configs
                anomaly.detection_context = context
                anomaly.save()
            
            return anomaly
        
        return None
    
    def _evaluate_rule_for_sentinel(self, rule: AnomalyRule, sentinel: SentinelInstance, configs: Dict[str, str]) -> Optional[AnomalyDetection]:
        """
        Evaluate a specific rule against a Sentinel instance
        """
        rule_directives = rule.directive_list
        relevant_configs = {}
        
        for directive in rule_directives:
            normalized_directive = self._normalize_directive_name(directive)
            for config_name, config_value in configs.items():
                if self._matches_directive(config_name, normalized_directive):
                    relevant_configs[config_name] = config_value
        
        if not relevant_configs and not self._is_rule_about_missing_config(rule):
            return None
        
        # For sentinel, we adapt the rule evaluation
        is_anomaly, context = self._evaluate_sentinel_rule_logic(rule, sentinel, configs, relevant_configs)
        
        if is_anomaly:
            anomaly, created = AnomalyDetection.objects.get_or_create(
                sentinel_instance=sentinel,
                rule=rule,
                defaults={
                    'affected_configs': relevant_configs,
                    'detection_context': context,
                    'status': 'detected'
                }
            )
            
            if not created:
                anomaly.affected_configs = relevant_configs
                anomaly.detection_context = context
                anomaly.save()
            
            return anomaly
        
        return None
    
    def _evaluate_rule_logic(self, rule: AnomalyRule, instance: RedisInstance, all_configs: Dict[str, str], relevant_configs: Dict[str, str]) -> tuple[bool, Dict[str, Any]]:
        """
        Evaluate the specific logic for each rule
        
        Returns:
            Tuple of (is_anomaly, context_data)
        """
        context = {
            'rule_id': rule.rule_id,
            'evaluation_method': 'pattern_matching',
            'configs_evaluated': relevant_configs,
            'instance_info': {
                'role': instance.role,
                'memory_usage': instance.used_memory,
                'max_memory': instance.maxmemory,
                'version': instance.version
            }
        }
        
        try:
            # Rule-specific evaluations based on rule ID patterns
            if rule.rule_id.startswith('CLIENT-'):
                return self._evaluate_client_rules(rule, instance, all_configs, relevant_configs, context)
            elif rule.rule_id.startswith('MEM-'):
                return self._evaluate_memory_rules(rule, instance, all_configs, relevant_configs, context)
            elif rule.rule_id.startswith('SEC-'):
                return self._evaluate_security_rules(rule, instance, all_configs, relevant_configs, context)
            elif rule.rule_id.startswith('PERF-'):
                return self._evaluate_performance_rules(rule, instance, all_configs, relevant_configs, context)
            elif rule.rule_id.startswith('REPL-'):
                return self._evaluate_replication_rules(rule, instance, all_configs, relevant_configs, context)
            elif rule.rule_id.startswith('AOF-') or rule.rule_id.startswith('RDB-'):
                return self._evaluate_persistence_rules(rule, instance, all_configs, relevant_configs, context)
            elif rule.rule_id.startswith('LOG-'):
                return self._evaluate_logging_rules(rule, instance, all_configs, relevant_configs, context)
            elif rule.rule_id.startswith('NET-'):
                return self._evaluate_network_rules(rule, instance, all_configs, relevant_configs, context)
            elif rule.rule_id.startswith('PROC-'):
                return self._evaluate_process_rules(rule, instance, all_configs, relevant_configs, context)
            else:
                # Generic evaluation
                return self._evaluate_generic_rule(rule, instance, all_configs, relevant_configs, context)
                
        except Exception as e:
            logger.error(f"Error in rule evaluation for {rule.rule_id}: {str(e)}")
            context['error'] = str(e)
            return False, context
    
    def _evaluate_client_rules(self, rule: AnomalyRule, instance: RedisInstance, all_configs: Dict[str, str], relevant_configs: Dict[str, str], context: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        """Evaluate CLIENT-* rules"""
        rule_id = rule.rule_id
        
        if rule_id == 'CLIENT-001':
            # replica buffer limit vs replication backlog size
            client_buffer_config = all_configs.get('client-output-buffer-limit', '')
            buffer_limits = self._parse_full_client_output_buffer_limit(client_buffer_config)
            backlog_size = self._parse_memory_size(all_configs.get('repl-backlog-size', '1mb'))
            
            if buffer_limits and backlog_size:
                replica_limit = buffer_limits.get('slave', buffer_limits.get('replica', {}))
                if replica_limit and replica_limit.get('hard_limit', 0) < backlog_size and replica_limit.get('hard_limit', 0) > 0:
                    context['replica_hard_limit'] = replica_limit['hard_limit']
                    context['replica_hard_limit_mb'] = replica_limit['hard_limit'] / (1024 * 1024)
                    context['backlog_size'] = backlog_size
                    context['backlog_size_mb'] = backlog_size / (1024 * 1024)
                    context['affected_configs'] = {'client-output-buffer-limit': client_buffer_config, 'repl-backlog-size': all_configs.get('repl-backlog-size')}
                    return True, context
                
        elif rule_id == 'CLIENT-002':
            # Unlimited output buffers
            client_buffer_config = all_configs.get('client-output-buffer-limit', '')
            buffer_limits = self._parse_full_client_output_buffer_limit(client_buffer_config)
            
            if buffer_limits:
                pubsub_unlimited = False
                replica_unlimited = False
                
                pubsub_limit = buffer_limits.get('pubsub', {})
                if pubsub_limit and pubsub_limit.get('hard_limit', 0) == 0 and pubsub_limit.get('soft_limit', 0) == 0:
                    pubsub_unlimited = True
                
                replica_limit = buffer_limits.get('slave', buffer_limits.get('replica', {}))
                if replica_limit and replica_limit.get('hard_limit', 0) == 0 and replica_limit.get('soft_limit', 0) == 0:
                    replica_unlimited = True
                
                if pubsub_unlimited or replica_unlimited:
                    context['unlimited_buffers'] = {
                        'pubsub': pubsub_unlimited,
                        'replica': replica_unlimited
                    }
                    context['affected_configs'] = {'client-output-buffer-limit': client_buffer_config}
                    return True, context
                
        elif rule_id == 'CLIENT-003':
            # Low client query buffer limit
            query_buffer = self._parse_memory_size(all_configs.get('client-query-buffer-limit', '1gb'))
            min_recommended = self._parse_memory_size('10mb')
            
            if query_buffer and query_buffer < min_recommended:
                context['current_limit'] = query_buffer
                context['recommended_minimum'] = min_recommended
                return True, context
                
        elif rule_id == 'CLIENT-004':
            # maxclients vs OS file descriptor limit
            max_clients = int(all_configs.get('maxclients', '10000'))
            # We can't easily get OS limits, so we use a reasonable assumption
            # Typically OS limit is around 65536, Redis reserves 32
            assumed_os_limit = 65536
            
            if max_clients > (assumed_os_limit - 32):
                context['max_clients'] = max_clients
                context['estimated_os_limit'] = assumed_os_limit
                context['note'] = 'OS file descriptor limit estimated'
                return True, context
                
        elif rule_id == 'CLIENT-005':
            # Disabled client timeout
            timeout = int(all_configs.get('timeout', '0'))
            
            if timeout == 0:
                context['timeout'] = timeout
                return True, context
                
        elif rule_id == 'CLIENT-006':
            # Disabled TCP keepalive
            keepalive = int(all_configs.get('tcp-keepalive', '300'))
            
            if keepalive == 0:
                context['tcp_keepalive'] = keepalive
                return True, context
        
        return False, context
    
    def _evaluate_memory_rules(self, rule: AnomalyRule, instance: RedisInstance, all_configs: Dict[str, str], relevant_configs: Dict[str, str], context: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        """Evaluate MEM-* rules"""
        rule_id = rule.rule_id
        
        if rule_id == 'MEM-004':
            # replica-ignore-maxmemory should be yes for replicas
            if instance.role in ['replica', 'slave']:
                ignore_maxmem = all_configs.get('replica-ignore-maxmemory', all_configs.get('slave-ignore-maxmemory', 'yes'))
                
                if ignore_maxmem == 'no':
                    context['replica_ignore_maxmemory'] = ignore_maxmem
                    context['instance_role'] = instance.role
                    return True, context
                    
        elif rule_id == 'MEM-005':
            # activerehashing should be enabled
            activerehashing = all_configs.get('activerehashing', 'yes')
            
            if activerehashing == 'no':
                context['activerehashing'] = activerehashing
                return True, context
                
        elif rule_id == 'MEM-006':
            # jemalloc-bg-thread should be enabled
            jemalloc_bg = all_configs.get('jemalloc-bg-thread', 'yes')
            
            if jemalloc_bg == 'no':
                context['jemalloc_bg_thread'] = jemalloc_bg
                return True, context
                
        elif rule_id == 'MEM-007':
            # tracking-table-max-keys should be limited
            tracking_max = int(all_configs.get('tracking-table-max-keys', '1000000'))
            
            if tracking_max == 0:
                context['tracking_table_max_keys'] = tracking_max
                return True, context
        
        return False, context
    
    def _evaluate_security_rules(self, rule: AnomalyRule, instance: RedisInstance, all_configs: Dict[str, str], relevant_configs: Dict[str, str], context: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        """Evaluate SEC-* rules"""
        rule_id = rule.rule_id
        
        if rule_id == 'SEC-003':
            # Conflicting ACL configuration
            has_aclfile = 'aclfile' in all_configs and all_configs['aclfile']
            has_requirepass = 'requirepass' in all_configs and all_configs['requirepass']
            has_user_directive = any(key.startswith('user ') for key in all_configs.keys())
            
            if has_aclfile and (has_requirepass or has_user_directive):
                context['conflicting_auth'] = {
                    'aclfile': has_aclfile,
                    'requirepass': has_requirepass,
                    'user_directive': has_user_directive
                }
                return True, context
                
        elif rule_id == 'SEC-004':
            # Replica authentication
            if instance.role in ['replica', 'slave'] and instance.master_ip:
                # Check if replica has auth configured
                has_masterauth = 'masterauth' in all_configs and all_configs['masterauth']
                has_masteruser = 'masteruser' in all_configs and all_configs['masteruser']
                
                # We can't easily check if master requires auth, so we assume it might
                # This would need to be enhanced with master instance checking
                context['replica_auth_config'] = {
                    'masterauth': has_masterauth,
                    'masteruser': has_masteruser,
                    'note': 'Cannot verify if master requires authentication'
                }
                # Only flag as anomaly if neither auth method is configured
                if not has_masterauth and not has_masteruser:
                    return True, context
        
        return False, context
    
    def _evaluate_performance_rules(self, rule: AnomalyRule, instance: RedisInstance, all_configs: Dict[str, str], relevant_configs: Dict[str, str], context: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        """Evaluate PERF-* rules"""
        rule_id = rule.rule_id
        
        if rule_id == 'PERF-001':
            # Transparent Huge Pages
            disable_thp = all_configs.get('disable-thp', 'yes')
            
            if disable_thp == 'no':
                context['disable_thp'] = disable_thp
                return True, context
                
        elif rule_id == 'PERF-002':
            # I/O threads on low CPU systems
            io_threads = int(all_configs.get('io-threads', '1'))
            # We can't get actual CPU count, so we estimate based on common scenarios
            estimated_cores = 4  # Conservative estimate
            
            if io_threads > 1 and estimated_cores < 4:
                context['io_threads'] = io_threads
                context['estimated_cores'] = estimated_cores
                context['note'] = 'CPU core count estimated'
                return True, context
                
        elif rule_id == 'PERF-004':
            # Lua script timeout
            lua_timeout = int(all_configs.get('lua-time-limit', '5000'))
            
            if lua_timeout <= 0 or lua_timeout > 10000:
                context['lua_time_limit'] = lua_timeout
                return True, context
                
        elif rule_id == 'PERF-005':
            # Gopher protocol enabled
            gopher_enabled = all_configs.get('gopher-enabled', 'no')
            
            if gopher_enabled == 'yes':
                context['gopher_enabled'] = gopher_enabled
                return True, context
        
        return False, context
    
    def _evaluate_replication_rules(self, rule: AnomalyRule, instance: RedisInstance, all_configs: Dict[str, str], relevant_configs: Dict[str, str], context: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        """Evaluate REPL-* rules"""
        rule_id = rule.rule_id
        
        if rule_id == 'REPL-001':
            # min-replicas-to-write
            if instance.role == 'master':
                min_replicas = int(all_configs.get('min-replicas-to-write', '0'))
                
                if min_replicas == 0:
                    context['min_replicas_to_write'] = min_replicas
                    return True, context
                    
        elif rule_id == 'REPL-002':
            # replica priority for DR replicas
            if instance.role in ['replica', 'slave']:
                priority = int(all_configs.get('replica-priority', all_configs.get('slave-priority', '100')))
                
                # This would need external context to know if it's a DR replica
                # For now, we'll flag replicas with non-zero priority in different subnets
                context['replica_priority'] = priority
                context['note'] = 'Manual review needed for DR replica identification'
                # Don't automatically flag this as anomaly without more context
                
        elif rule_id == 'REPL-003':
            # replication timeout vs ping period
            repl_timeout = int(all_configs.get('repl-timeout', '60'))
            ping_period = int(all_configs.get('repl-ping-replica-period', '10'))
            
            if repl_timeout <= ping_period:
                context['repl_timeout'] = repl_timeout
                context['ping_period'] = ping_period
                return True, context
        
        return False, context
    
    def _evaluate_persistence_rules(self, rule: AnomalyRule, instance: RedisInstance, all_configs: Dict[str, str], relevant_configs: Dict[str, str], context: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        """Evaluate AOF-* and RDB-* rules"""
        rule_id = rule.rule_id
        
        if rule_id == 'AOF-001':
            # aof-load-truncated
            aof_load_truncated = all_configs.get('aof-load-truncated', 'yes')
            
            if aof_load_truncated == 'no':
                context['aof_load_truncated'] = aof_load_truncated
                return True, context
                
        elif rule_id == 'AOF-002':
            # no-appendfsync-on-rewrite
            no_fsync_rewrite = all_configs.get('no-appendfsync-on-rewrite', 'no')
            
            if no_fsync_rewrite == 'yes':
                context['no_appendfsync_on_rewrite'] = no_fsync_rewrite
                return True, context
                
        elif rule_id == 'RDB-001':
            # rdbcompression
            rdb_compression = all_configs.get('rdbcompression', 'yes')
            
            if rdb_compression == 'no':
                context['rdbcompression'] = rdb_compression
                return True, context
                
        elif rule_id == 'RDB-002':
            # rdbchecksum
            rdb_checksum = all_configs.get('rdbchecksum', 'yes')
            
            if rdb_checksum == 'no':
                context['rdbchecksum'] = rdb_checksum
                return True, context
        
        return False, context
    
    def _evaluate_logging_rules(self, rule: AnomalyRule, instance: RedisInstance, all_configs: Dict[str, str], relevant_configs: Dict[str, str], context: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        """Evaluate LOG-* rules"""
        rule_id = rule.rule_id
        
        if rule_id == 'LOG-001':
            # Verbose logging in production
            loglevel = all_configs.get('loglevel', 'notice')
            
            # Assume production if not explicitly development
            is_production = True  # This could be enhanced with environment detection
            
            if is_production and loglevel in ['debug', 'verbose']:
                context['loglevel'] = loglevel
                context['environment'] = 'production'
                return True, context
                
        elif rule_id == 'LOG-002':
            # Daemonize with stdout logging
            daemonize = all_configs.get('daemonize', 'no')
            logfile = all_configs.get('logfile', '')
            
            if daemonize == 'yes' and not logfile:
                context['daemonize'] = daemonize
                context['logfile'] = logfile
                return True, context
        
        return False, context
    
    def _evaluate_network_rules(self, rule: AnomalyRule, instance: RedisInstance, all_configs: Dict[str, str], relevant_configs: Dict[str, str], context: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        """Evaluate NET-* rules"""
        rule_id = rule.rule_id
        
        if rule_id == 'NET-004':
            # Unix socket permissions
            unix_socket_perm = all_configs.get('unixsocketperm', '0')
            
            if unix_socket_perm == '777':
                context['unixsocketperm'] = unix_socket_perm
                return True, context
                
        elif rule_id == 'NET-005':
            # Cluster announce settings in NAT/Docker
            has_announce_ip = 'cluster-announce-ip' in all_configs
            has_announce_port = 'cluster-announce-port' in all_configs
            has_announce_bus_port = 'cluster-announce-bus-port' in all_configs
            
            # We can't easily detect NAT/Docker, so we check if cluster is enabled
            cluster_enabled = all_configs.get('cluster-enabled', 'no') == 'yes'
            
            if cluster_enabled and not (has_announce_ip and has_announce_port and has_announce_bus_port):
                context['cluster_announce_settings'] = {
                    'announce_ip': has_announce_ip,
                    'announce_port': has_announce_port,
                    'announce_bus_port': has_announce_bus_port
                }
                context['note'] = 'Review if running in NAT/Docker environment'
                return True, context
        
        return False, context
    
    def _evaluate_process_rules(self, rule: AnomalyRule, instance: RedisInstance, all_configs: Dict[str, str], relevant_configs: Dict[str, str], context: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        """Evaluate PROC-* rules"""
        rule_id = rule.rule_id
        
        if rule_id == 'PROC-001':
            # Daemonize with systemd/upstart
            daemonize = all_configs.get('daemonize', 'no')
            supervised = all_configs.get('supervised', 'no')
            
            # We can't easily detect systemd/upstart, so we check for common patterns
            if daemonize == 'yes':
                context['daemonize'] = daemonize
                context['supervised'] = supervised
                context['note'] = 'Check if running under systemd/upstart'
                return True, context
                
        elif rule_id == 'PROC-002':
            # No supervision configured
            supervised = all_configs.get('supervised', 'no')
            
            if supervised == 'no':
                context['supervised'] = supervised
                context['note'] = 'Check if running under systemd/upstart'
                # Don't automatically flag without more context
        
        return False, context
    
    def _evaluate_generic_rule(self, rule: AnomalyRule, instance: RedisInstance, all_configs: Dict[str, str], relevant_configs: Dict[str, str], context: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        """Generic rule evaluation for unknown rule types"""
        # Basic pattern matching for common issues
        context['evaluation_method'] = 'generic'
        
        # Check for common patterns in detection logic
        detection_logic = rule.detection_logic.lower()
        
        if 'disabled' in detection_logic or '== \'no\'' in detection_logic:
            # Look for disabled features
            for config_name, config_value in relevant_configs.items():
                if config_value.lower() in ['no', 'disabled', '0']:
                    context['disabled_feature'] = {config_name: config_value}
                    return True, context
        
        return False, context
    
    def _evaluate_sentinel_rule_logic(self, rule: AnomalyRule, sentinel: SentinelInstance, all_configs: Dict[str, str], relevant_configs: Dict[str, str]) -> tuple[bool, Dict[str, Any]]:
        """
        Evaluate rule logic specifically for Sentinel instances
        """
        context = {
            'rule_id': rule.rule_id,
            'evaluation_method': 'sentinel_specific',
            'configs_evaluated': relevant_configs,
            'sentinel_info': {
                'known_sentinels': sentinel.known_sentinels,
                'known_slaves': sentinel.known_slaves,
                'masters_count': sentinel.masters_count
            }
        }
        
        # Adapt Redis rules for Sentinel context
        # Most rules will be generic evaluations
        return self._evaluate_generic_rule(rule, None, all_configs, relevant_configs, context)
    
    # Utility methods
    
    def _normalize_directive_name(self, directive: str) -> str:
        """Normalize directive names for comparison"""
        return directive.lower().strip().replace('_', '-')
    
    def _matches_directive(self, config_name: str, directive: str) -> bool:
        """Check if a config name matches a directive"""
        normalized_config = self._normalize_directive_name(config_name)
        normalized_directive = self._normalize_directive_name(directive)
        
        return (
            normalized_config == normalized_directive or
            normalized_config.startswith(normalized_directive + ' ') or
            normalized_directive in normalized_config
        )
    
    def _is_rule_about_missing_config(self, rule: AnomalyRule) -> bool:
        """Check if rule is about missing configuration"""
        detection_logic = rule.detection_logic.lower()
        return 'not set' in detection_logic or 'missing' in detection_logic
    
    def _parse_memory_size(self, size_str: str) -> Optional[int]:
        """Parse memory size string to bytes"""
        if not size_str:
            return None
        
        size_str = size_str.lower().strip()
        
        # Handle numeric values
        if size_str.isdigit():
            return int(size_str)
        
        # Parse with units
        units = {
            'b': 1,
            'kb': 1024,
            'mb': 1024 * 1024,
            'gb': 1024 * 1024 * 1024,
            'k': 1024,
            'm': 1024 * 1024,
            'g': 1024 * 1024 * 1024
        }
        
        for unit, multiplier in units.items():
            if size_str.endswith(unit):
                try:
                    number = float(size_str[:-len(unit)])
                    return int(number * multiplier)
                except ValueError:
                    continue
        
        return None
    
    def _parse_client_output_buffer_limit(self, limit_str: str) -> Optional[Dict[str, int]]:
        """Parse client output buffer limit string"""
        if not limit_str:
            return None
        
        parts = limit_str.split()
        if len(parts) >= 2:
            try:
                hard_limit = self._parse_memory_size(parts[0])
                soft_limit = self._parse_memory_size(parts[1])
                soft_seconds = int(parts[2]) if len(parts) > 2 else 0
                
                return {
                    'hard_limit': hard_limit,
                    'soft_limit': soft_limit,
                    'soft_seconds': soft_seconds
                }
            except (ValueError, IndexError):
                pass
        
        return None
    
    def _parse_full_client_output_buffer_limit(self, limit_str: str) -> Optional[Dict[str, Dict[str, int]]]:
        """
        Parse full client output buffer limit configuration.
        
        Example input: 'normal 0 0 0 slave 268435456 67108864 60 pubsub 33554432 8388608 60'
        
        Returns dictionary like:
        {
            'normal': {'hard_limit': 0, 'soft_limit': 0, 'soft_seconds': 0},
            'slave': {'hard_limit': 268435456, 'soft_limit': 67108864, 'soft_seconds': 60},
            'pubsub': {'hard_limit': 33554432, 'soft_limit': 8388608, 'soft_seconds': 60}
        }
        """
        if not limit_str:
            return None
        
        try:
            parts = limit_str.split()
            result = {}
            
            i = 0
            while i < len(parts):
                if i + 3 < len(parts):  # Need at least client_type + 3 values
                    client_type = parts[i]
                    hard_limit = int(parts[i + 1])
                    soft_limit = int(parts[i + 2])
                    soft_seconds = int(parts[i + 3])
                    
                    result[client_type] = {
                        'hard_limit': hard_limit,
                        'soft_limit': soft_limit,
                        'soft_seconds': soft_seconds
                    }
                    i += 4
                else:
                    break
            
            return result if result else None
            
        except (ValueError, IndexError) as e:
            logger.warning(f"Failed to parse client output buffer limit '{limit_str}': {str(e)}")
            return None
    
    def run_full_detection(self, user_instances_only: bool = True, user=None) -> Dict[str, Any]:
        """
        Run anomaly detection on all instances
        
        Args:
            user_instances_only: If True, only analyze instances belonging to the user
            user: User object for filtering (required if user_instances_only is True)
            
        Returns:
            Dictionary with detection results and statistics
        """
        results = {
            'total_instances_analyzed': 0,
            'total_sentinels_analyzed': 0,
            'total_anomalies_detected': 0,
            'anomalies_by_severity': {'critical': 0, 'warning': 0, 'notice': 0},
            'anomalies_by_category': {},
            'newly_detected': 0,
            'errors': []
        }
        
        try:
            # Get instances to analyze
            if user_instances_only and user:
                redis_instances = RedisInstance.objects.filter(analysis_session__user=user)
                sentinel_instances = SentinelInstance.objects.filter(analysis_session__user=user)
            else:
                redis_instances = RedisInstance.objects.all()
                sentinel_instances = SentinelInstance.objects.all()
            
            # Analyze Redis instances
            for instance in redis_instances:
                try:
                    anomalies = self.detect_instance_anomalies(instance)
                    results['total_instances_analyzed'] += 1
                    
                    for anomaly in anomalies:
                        if anomaly:  # Newly created anomaly
                            results['newly_detected'] += 1
                        results['total_anomalies_detected'] += 1
                        results['anomalies_by_severity'][anomaly.severity] += 1
                        
                        category = anomaly.category
                        results['anomalies_by_category'][category] = results['anomalies_by_category'].get(category, 0) + 1
                        
                except Exception as e:
                    results['errors'].append(f"Error analyzing Redis instance {instance}: {str(e)}")
            
            # Analyze Sentinel instances
            for sentinel in sentinel_instances:
                try:
                    anomalies = self.detect_sentinel_anomalies(sentinel)
                    results['total_sentinels_analyzed'] += 1
                    
                    for anomaly in anomalies:
                        if anomaly:  # Newly created anomaly
                            results['newly_detected'] += 1
                        results['total_anomalies_detected'] += 1
                        results['anomalies_by_severity'][anomaly.severity] += 1
                        
                        category = anomaly.category
                        results['anomalies_by_category'][category] = results['anomalies_by_category'].get(category, 0) + 1
                        
                except Exception as e:
                    results['errors'].append(f"Error analyzing Sentinel instance {sentinel}: {str(e)}")
                    
        except Exception as e:
            results['errors'].append(f"Critical error in full detection: {str(e)}")
        
        return results
