import redis
import logging
from typing import Dict, List, Tuple, Optional
from django.utils import timezone
from .models import RedisInstance, RedisConfiguration, AnalysisSession, ReplicationInfo, KeyspaceInfo

logger = logging.getLogger(__name__)


class RedisAnalyzer:
    """Service class for analyzing Redis configurations"""
    
    # Configuration parameter categories mapping
    CONFIG_CATEGORIES = {
        # Memory related
        'maxmemory': 'memory',
        'maxmemory-policy': 'memory',
        'maxmemory-samples': 'memory',
        'used-memory': 'memory',
        'mem-fragmentation-ratio': 'memory',
        
        # Persistence related
        'save': 'persistence',
        'stop-writes-on-bgsave-error': 'persistence',
        'rdbcompression': 'persistence',
        'rdbchecksum': 'persistence',
        'dir': 'persistence',
        'dbfilename': 'persistence',
        'appendonly': 'persistence',
        'appendfilename': 'persistence',
        'appendfsync': 'persistence',
        'no-appendfsync-on-rewrite': 'persistence',
        'auto-aof-rewrite-percentage': 'persistence',
        'auto-aof-rewrite-min-size': 'persistence',
        
        # Replication related
        'repl-diskless-sync': 'replication',
        'repl-diskless-sync-delay': 'replication',
        'repl-ping-slave-period': 'replication',
        'repl-timeout': 'replication',
        'repl-disable-tcp-nodelay': 'replication',
        'repl-backlog-size': 'replication',
        'repl-backlog-ttl': 'replication',
        'slave-priority': 'replication',
        'replica-priority': 'replication',
        'min-slaves-to-write': 'replication',
        'min-slaves-max-lag': 'replication',
        'slave-read-only': 'replication',
        'replica-read-only': 'replication',
        
        # Security related
        'requirepass': 'security',
        'masterauth': 'security',
        'rename-command': 'security',
        'protected-mode': 'security',
        
        # Networking related
        'port': 'networking',
        'bind': 'networking',
        'timeout': 'networking',
        'tcp-keepalive': 'networking',
        'tcp-backlog': 'networking',
        
        # Logging related
        'loglevel': 'logging',
        'logfile': 'logging',
        'syslog-enabled': 'logging',
        'syslog-ident': 'logging',
        'syslog-facility': 'logging',
        
        # Slowlog related
        'slowlog-log-slower-than': 'slowlog',
        'slowlog-max-len': 'slowlog',
        
        # Clients related
        'maxclients': 'clients',
        'client-output-buffer-limit': 'clients',
    }
    
    def __init__(self, user=None, session_name: str = None):
        self.user = user
        # Generate better session name with IST timestamp
        if not session_name:
            ist_time = timezone.now() + timezone.timedelta(hours=5, minutes=30)
            self.session_name = f"Redis_Analysis_{ist_time.strftime('%d%b%Y_%I%M%p')}"
        else:
            self.session_name = session_name
        self.session = None
    
    def connect_to_redis(self, host: str, port: int = 6379, password: str = None, timeout: int = 5) -> Optional[redis.Redis]:
        """Establish connection to Redis instance"""
        try:
            client = redis.Redis(
                host=host,
                port=port,
                password=password,
                socket_timeout=timeout,
                socket_connect_timeout=timeout,
                decode_responses=True
            )
            # Test connection
            client.ping()
            return client
        except Exception as e:
            logger.error(f"Failed to connect to Redis at {host}:{port}: {str(e)}")
            return None
    
    def get_redis_info(self, client: redis.Redis) -> Dict:
        """Get Redis server information"""
        try:
            info = client.info()
            return info
        except Exception as e:
            logger.error(f"Failed to get Redis info: {str(e)}")
            return {}
    
    def get_redis_info_raw(self, client: redis.Redis) -> str:
        """Get raw Redis INFO command output as text"""
        try:
            # Get raw text response from INFO command
            # Use a direct Redis connection to get raw text format
            response = client.execute_command('INFO')
            
            # If it's already a string (the raw format), return it
            if isinstance(response, str):
                return response
            
            # If it's a dict (parsed), we need to format it back to INFO style
            if isinstance(response, dict):
                lines = []
                current_section = ""
                
                for key, value in response.items():
                    # Handle section headers (like # Server, # Memory, etc.)
                    if key in ['redis_version']:
                        lines.append("# Server")
                    elif key in ['used_memory']:
                        lines.append("# Memory")
                    elif key in ['loading']:
                        lines.append("# Persistence")
                    elif key in ['total_connections_received']:
                        lines.append("# Stats")
                    elif key in ['role']:
                        lines.append("# Replication")
                    elif key in ['used_cpu_sys']:
                        lines.append("# CPU")
                    elif key in ['cluster_enabled']:
                        lines.append("# Cluster")
                    elif key.startswith('db'):
                        if current_section != "keyspace":
                            lines.append("# Keyspace")
                            current_section = "keyspace"
                        # Format keyspace entries
                        if isinstance(value, dict):
                            formatted_value = ','.join([f"{k}={v}" for k, v in value.items()])
                            lines.append(f"{key}:{formatted_value}")
                        continue
                    
                    # Format regular key-value pairs
                    if isinstance(value, dict) and key.startswith('slave'):
                        formatted_value = ','.join([f"{k}={v}" for k, v in value.items()])
                        lines.append(f"{key}:{formatted_value}")
                    elif not key.startswith('db'):
                        lines.append(f"{key}:{value}")
                
                return '\n'.join(lines)
            
            # Fallback: convert to string
            return str(response)
            
        except Exception as e:
            logger.error(f"Failed to get raw Redis info: {str(e)}")
            return ""
    
    def get_redis_config(self, client: redis.Redis) -> Dict:
        """Get Redis configuration"""
        try:
            config = client.config_get("*")
            return config
        except Exception as e:
            logger.error(f"Failed to get Redis config: {str(e)}")
            return {}
    
    def get_replication_info(self, client: redis.Redis) -> Dict:
        """Get Redis replication information"""
        try:
            repl_info = client.info('replication')
            return repl_info
        except Exception as e:
            logger.error(f"Failed to get replication info: {str(e)}")
            return {}
    
    def discover_slaves(self, master_client: redis.Redis) -> List[Tuple[str, int]]:
        """Discover slave instances from master"""
        slaves = []
        try:
            repl_info = self.get_replication_info(master_client)
            slave_count = repl_info.get('connected_slaves', 0)
            
            for i in range(slave_count):
                slave_key = f'slave{i}'
                if slave_key in repl_info:
                    slave_info = repl_info[slave_key]
                    ip = None
                    port = 6379
                    
                    # Handle both string format and dictionary format
                    if isinstance(slave_info, dict):
                        # New format: dictionary with structured data
                        ip = slave_info.get('ip')
                        port = slave_info.get('port', 6379)
                    elif isinstance(slave_info, str):
                        # Legacy format: string like "ip=10.0.0.2,port=6379,state=online,offset=123,lag=0"
                        parts = slave_info.split(',')
                        for part in parts:
                            if part.startswith('ip='):
                                ip = part.split('=')[1]
                            elif part.startswith('port='):
                                port = int(part.split('=')[1])
                    else:
                        # Try to parse as string anyway
                        try:
                            parts = str(slave_info).split(',')
                            for part in parts:
                                if 'ip=' in part:
                                    ip = part.split('=')[1]
                                elif 'port=' in part:
                                    port = int(part.split('=')[1])
                        except:
                            logger.warning(f"Could not parse slave info: {slave_info}")
                            continue
                    
                    if ip:
                        slaves.append((ip, int(port)))
                    else:
                        logger.warning(f"Could not extract IP from slave info: {slave_info}")
            
        except Exception as e:
            logger.error(f"Failed to discover slaves: {str(e)}")
        
        return slaves
    
    def categorize_config_parameter(self, param_name: str) -> str:
        """Categorize configuration parameter"""
        param_lower = param_name.lower()
        
        # Direct mapping
        if param_lower in self.CONFIG_CATEGORIES:
            return self.CONFIG_CATEGORIES[param_lower]
        
        # Pattern matching
        if any(keyword in param_lower for keyword in ['memory', 'mem']):
            return 'memory'
        elif any(keyword in param_lower for keyword in ['repl', 'slave', 'replica']):
            return 'replication'
        elif any(keyword in param_lower for keyword in ['save', 'aof', 'rdb', 'persist']):
            return 'persistence'
        elif any(keyword in param_lower for keyword in ['log', 'debug']):
            return 'logging'
        elif any(keyword in param_lower for keyword in ['client', 'conn']):
            return 'clients'
        elif any(keyword in param_lower for keyword in ['port', 'bind', 'tcp', 'network']):
            return 'networking'
        elif any(keyword in param_lower for keyword in ['auth', 'pass', 'security']):
            return 'security'
        elif any(keyword in param_lower for keyword in ['slow']):
            return 'slowlog'
        else:
            return 'other'
    
    def get_keyspace_info(self, info: Dict) -> Dict:
        """Extract detailed keyspace information per database"""
        keyspace_data = {}
        total_keys = 0
        
        try:
            # Look for keyspace info in different sections
            keyspace_info = {}
            
            # Try to get keyspace section directly
            if 'keyspace' in info:
                keyspace_info = info['keyspace']
            else:
                # Look for db0, db1, etc. keys in main info
                for key, value in info.items():
                    if key.startswith('db'):
                        keyspace_info[key] = value
            
            # Process keyspace info for each database
            for db_name, db_info in keyspace_info.items():
                if not db_name.startswith('db'):
                    continue
                    
                db_data = {
                    'keys': 0,
                    'expires': 0,
                    'avg_ttl': 0
                }
                
                if isinstance(db_info, dict):
                    # Dictionary format
                    db_data['keys'] = int(db_info.get('keys', 0))
                    db_data['expires'] = int(db_info.get('expires', 0))
                    db_data['avg_ttl'] = int(db_info.get('avg_ttl', 0))
                elif isinstance(db_info, str):
                    # String format like "keys=123,expires=12,avg_ttl=0"
                    try:
                        parts = db_info.split(',')
                        for part in parts:
                            if '=' in part:
                                key, value = part.split('=', 1)
                                key = key.strip()
                                if key == 'keys':
                                    db_data['keys'] = int(value)
                                elif key == 'expires':
                                    db_data['expires'] = int(value)
                                elif key == 'avg_ttl':
                                    db_data['avg_ttl'] = int(value)
                    except (ValueError, IndexError):
                        continue
                
                if db_data['keys'] > 0:  # Only store databases that have keys
                    keyspace_data[db_name] = db_data
                    total_keys += db_data['keys']
                    
        except Exception as e:
            logger.error(f"Failed to extract keyspace info: {str(e)}")
            
        return {
            'databases': keyspace_data,
            'total_keys': total_keys
        }
    
    def get_total_keys_from_keyspace(self, info: Dict) -> int:
        """Extract total keys count from keyspace info"""
        keyspace_result = self.get_keyspace_info(info)
        return keyspace_result['total_keys']
    
    def save_redis_instance(self, host: str, port: int, info: Dict, config: Dict, repl_info: Dict, raw_info: str = "", master_name: str = "") -> RedisInstance:
        """Save Redis instance information to database"""
        
        # Determine role
        role = 'master'
        master_ip = None
        master_port = None
        
        if repl_info.get('role') == 'slave':
            role = 'slave'
            master_host = repl_info.get('master_host')
            master_port_val = repl_info.get('master_port')
            if master_host:
                master_ip = master_host
                master_port = master_port_val
        
        # Create or update instance (include analysis_session to ensure user isolation)
        instance, created = RedisInstance.objects.update_or_create(
            analysis_session=self.session,
            ip_address=host,
            port=port,
            defaults={
                'analysis_session': self.session,
                'role': role,
                'master_ip': master_ip,
                'master_port': master_port,
                'status': 'online',
                'version': info.get('redis_version', ''),
                'uptime_seconds': info.get('uptime_in_seconds'),
                'connected_clients': info.get('connected_clients'),
                'max_clients': info.get('maxclients'),
                'master_name': master_name if role == 'master' else None,
                'used_memory': info.get('used_memory'),
                'used_memory_human': info.get('used_memory_human', ''),
                'maxmemory': int(config.get('maxmemory', 0)) if config.get('maxmemory') else None,
                'maxmemory_human': self.bytes_to_human(int(config.get('maxmemory', 0))) if config.get('maxmemory') else '',
                'keyspace_hits': info.get('keyspace_hits'),
                'keyspace_misses': info.get('keyspace_misses'),
                'total_keys': self.get_total_keys_from_keyspace(info),
                'total_commands_processed': info.get('total_commands_processed'),
                'raw_info_output': raw_info,
            }
        )
        
        # Save keyspace information
        self.save_keyspace_info(instance, info)
        
        return instance
    
    def save_keyspace_info(self, instance: RedisInstance, info: Dict):
        """Save keyspace information to database"""
        try:
            # Clear existing keyspace info for this instance
            KeyspaceInfo.objects.filter(instance=instance).delete()
            
            # Get keyspace data
            keyspace_result = self.get_keyspace_info(info)
            databases = keyspace_result['databases']
            
            # Save each database's keyspace info
            for db_name, db_data in databases.items():
                KeyspaceInfo.objects.create(
                    instance=instance,
                    database_name=db_name,
                    keys_count=db_data['keys'],
                    expires_count=db_data['expires'],
                    avg_ttl=db_data['avg_ttl']
                )
                
        except Exception as e:
            logger.error(f"Failed to save keyspace info for {instance}: {str(e)}")
    
    def save_redis_configurations(self, instance: RedisInstance, config: Dict):
        """Save Redis configurations to database"""
        
        # Clear existing configurations for this instance
        RedisConfiguration.objects.filter(instance=instance).delete()
        
        for param_name, param_value in config.items():
            category = self.categorize_config_parameter(param_name)
            
            RedisConfiguration.objects.create(
                instance=instance,
                parameter_name=param_name,
                parameter_value=str(param_value),
                category=category,
            )
    
    def save_replication_info(self, master_instance: RedisInstance, slave_instance: RedisInstance, repl_info: Dict):
        """Save replication relationship information"""
        
        # Determine replication state based on available fields
        repl_state = 'unknown'
        if 'master_link_status' in repl_info:
            repl_state = repl_info.get('master_link_status', 'unknown')
        elif 'master_sync_in_progress' in repl_info:
            if repl_info.get('master_sync_in_progress') == '1':
                repl_state = 'syncing'
            else:
                repl_state = 'connected' if repl_info.get('master_last_io_seconds_ago', '0') != '-1' else 'disconnected'
        
        ReplicationInfo.objects.update_or_create(
            master_instance=master_instance,
            slave_instance=slave_instance,
            defaults={
                'replication_offset': repl_info.get('slave_repl_offset'),
                'lag_in_seconds': repl_info.get('master_last_io_seconds_ago'),
                'replication_state': repl_state,
                'priority': repl_info.get('slave_priority'),
            }
        )
    
    def bytes_to_human(self, bytes_val: int) -> str:
        """Convert bytes to human readable format"""
        if not bytes_val:
            return "0B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f}{unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f}PB"
    
    def analyze_redis_cluster(self, master_host: str, master_port: int = 6379, password: str = None) -> AnalysisSession:
        """Analyze entire Redis cluster starting from master"""
        
        # Create analysis session
        self.session = AnalysisSession.objects.create(
            user=self.user,
            master_ip=master_host,
            master_port=master_port,
            session_name=self.session_name,
            status='running'
        )
        
        try:
            # Connect to master
            master_client = self.connect_to_redis(master_host, master_port, password)
            if not master_client:
                self.session.status = 'failed'
                self.session.error_message = f"Failed to connect to master at {master_host}:{master_port}"
                self.session.analysis_end_time = timezone.now()
                self.session.save()
                return self.session
            
            # Get master information
            master_info = self.get_redis_info(master_client)
            master_config = self.get_redis_config(master_client)
            master_repl_info = self.get_replication_info(master_client)
            master_raw_info = self.get_redis_info_raw(master_client)
            
            # Save master instance
            master_instance = self.save_redis_instance(
                master_host, master_port, master_info, master_config, master_repl_info, master_raw_info
            )
            self.save_redis_configurations(master_instance, master_config)
            
            successful_connections = 1
            failed_connections = 0
            total_instances = 1
            
            # Discover and analyze slaves
            slaves = self.discover_slaves(master_client)
            total_instances += len(slaves)
            
            for slave_host, slave_port in slaves:
                try:
                    slave_client = self.connect_to_redis(slave_host, slave_port, password)
                    if slave_client:
                        slave_info = self.get_redis_info(slave_client)
                        slave_config = self.get_redis_config(slave_client)
                        slave_repl_info = self.get_replication_info(slave_client)
                        slave_raw_info = self.get_redis_info_raw(slave_client)
                        
                        # Save slave instance
                        slave_instance = self.save_redis_instance(
                            slave_host, slave_port, slave_info, slave_config, slave_repl_info, slave_raw_info
                        )
                        self.save_redis_configurations(slave_instance, slave_config)
                        
                        # Save replication relationship
                        self.save_replication_info(master_instance, slave_instance, slave_repl_info)
                        
                        successful_connections += 1
                        slave_client.close()
                    else:
                        failed_connections += 1
                        # Mark slave as offline (include analysis_session for user isolation)
                        RedisInstance.objects.update_or_create(
                            analysis_session=self.session,
                            ip_address=slave_host,
                            port=slave_port,
                            defaults={
                                'analysis_session': self.session,
                                'status': 'offline'
                            }
                        )
                except Exception as e:
                    logger.error(f"Failed to analyze slave {slave_host}:{slave_port}: {str(e)}")
                    failed_connections += 1
            
            # Update session
            self.session.total_instances_found = total_instances
            self.session.successful_connections = successful_connections
            self.session.failed_connections = failed_connections
            
            if failed_connections == 0:
                self.session.status = 'completed'
            elif successful_connections > 0:
                self.session.status = 'partial'
            else:
                self.session.status = 'failed'
            
            # Run anomaly detection on all analyzed instances
            if successful_connections > 0:
                try:
                    from .anomaly_detector import AnomalyDetector
                    detector = AnomalyDetector()
                    
                    # Get all instances from this session
                    session_instances = RedisInstance.objects.filter(analysis_session=self.session)
                    
                    anomaly_results = {
                        'total_anomalies': 0,
                        'critical_anomalies': 0,
                        'instances_with_anomalies': 0
                    }
                    
                    for instance in session_instances:
                        try:
                            anomalies = detector.detect_instance_anomalies(instance)
                            if anomalies:
                                instance_anomaly_count = len([a for a in anomalies if a])
                                if instance_anomaly_count > 0:
                                    anomaly_results['instances_with_anomalies'] += 1
                                    anomaly_results['total_anomalies'] += instance_anomaly_count
                                    
                                    # Count critical anomalies
                                    for anomaly in anomalies:
                                        if anomaly and anomaly.rule.severity == 'critical':
                                            anomaly_results['critical_anomalies'] += 1
                        except Exception as e:
                            logger.warning(f"Anomaly detection failed for instance {instance}: {str(e)}")
                    
                    logger.info(f"Anomaly detection completed for session {self.session.id}: "
                              f"{anomaly_results['total_anomalies']} anomalies found across "
                              f"{anomaly_results['instances_with_anomalies']} instances")
                    
                except Exception as e:
                    logger.error(f"Anomaly detection failed for session {self.session.id}: {str(e)}")
            
            self.session.analysis_end_time = timezone.now()
            self.session.save()
            master_client.close()
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            self.session.status = 'failed'
            self.session.error_message = str(e)
            self.session.analysis_end_time = timezone.now()
            self.session.save()
        
        return self.session