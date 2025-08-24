import redis
import logging
from typing import Dict, List, Tuple, Optional
from django.utils import timezone
from .models import (
    SentinelInstance, SentinelConfiguration, MonitoredMaster, 
    SentinelAnalysisSession, RedisInstance, RedisConfiguration, ReplicationInfo
)
from .redis_service import RedisAnalyzer

logger = logging.getLogger(__name__)


class SentinelAnalyzer:
    """Service class for analyzing Redis Sentinel configurations and discovering masters"""
    
    # Sentinel Configuration parameter categories mapping
    SENTINEL_CONFIG_CATEGORIES = {
        # Monitoring related
        'monitor': 'monitoring',
        'down-after-milliseconds': 'monitoring',
        'failover-timeout': 'failover',
        'parallel-syncs': 'failover',
        'quorum': 'monitoring',
        
        # Security related
        'auth-pass': 'security',
        'sentinel-pass': 'security',
        'requirepass': 'security',
        
        # Networking related
        'port': 'networking',
        'bind': 'networking',
        'announce-ip': 'networking',
        'announce-port': 'networking',
        
        # Logging related
        'logfile': 'logging',
        'loglevel': 'logging',
        'syslog-enabled': 'logging',
        
        # Notification related
        'notification-script': 'notification',
        'client-reconfig-script': 'notification',
        
        # General
        'dir': 'general',
        'daemonize': 'general',
        'pidfile': 'general',
    }
    
    def __init__(self, user=None, session_name: str = None):
        self.user = user
        # Generate better session name with IST timestamp
        if not session_name:
            ist_time = timezone.now() + timezone.timedelta(hours=5, minutes=30)
            self.session_name = f"Sentinel_Analysis_{ist_time.strftime('%d%b%Y_%I%M%p')}"
        else:
            self.session_name = session_name
        self.session = None
        self.redis_analyzer = RedisAnalyzer(user=user)  # Reuse existing Redis analyzer for masters/slaves
    
    def connect_to_sentinel(self, host: str, port: int = 26379, password: str = None, timeout: int = 5) -> Optional[redis.Redis]:
        """Establish connection to Redis Sentinel instance"""
        try:
            # Try with decode_responses=True first (recommended for compatibility)
            client = redis.Redis(
                host=host,
                port=port,
                password=password,
                socket_timeout=timeout,
                socket_connect_timeout=timeout,
                decode_responses=True
            )
            # Test connection by getting sentinel info
            client.info()
            return client
        except Exception as e:
            logger.warning(f"Failed to connect to Sentinel at {host}:{port} with decode_responses=True: {str(e)}")
            # Try fallback without decode_responses
            try:
                client = redis.Redis(
                    host=host,
                    port=port,
                    password=password,
                    socket_timeout=timeout,
                    socket_connect_timeout=timeout,
                    decode_responses=False
                )
                # Test connection by getting sentinel info
                client.info()
                return client
            except Exception as e2:
                logger.error(f"Failed to connect to Sentinel at {host}:{port}: {str(e2)}")
                return None
    
    def get_sentinel_info(self, client: redis.Redis) -> Dict:
        """Get Sentinel server information"""
        try:
            info = client.info()
            return info
        except Exception as e:
            logger.error(f"Failed to get Sentinel info: {str(e)}")
            return {}
    
    def get_sentinel_info_raw(self, client: redis.Redis) -> str:
        """Get raw Sentinel INFO command output as text"""
        try:
            # Execute INFO command and get raw response
            raw_output = client.execute_command('INFO')
            
            # If it's already a string (the raw format), return it
            if isinstance(raw_output, str):
                return raw_output
            
            # If it's a dict (parsed), we need to format it back to INFO style
            if isinstance(raw_output, dict):
                lines = []
                current_section = ""
                
                for key, value in raw_output.items():
                    # Handle section headers (like # Server, # Sentinel, etc.)
                    if key in ['redis_version']:
                        lines.append("# Server")
                    elif key in ['sentinel_masters']:
                        lines.append("# Sentinel")
                    elif key in ['used_memory']:
                        lines.append("# Memory")
                    elif key in ['used_cpu_sys']:
                        lines.append("# CPU")
                    
                    # Format regular key-value pairs
                    if not key.startswith('master'):  # Skip complex master objects
                        lines.append(f"{key}:{value}")
                
                return '\n'.join(lines)
            
            # Fallback: convert to string
            return str(raw_output)
            
        except Exception as e:
            logger.error(f"Failed to get raw Sentinel info: {str(e)}")
            return ""
    
    def get_sentinel_config(self, client: redis.Redis) -> Dict:
        """Get Sentinel configuration"""
        try:
            # Try to get basic Sentinel configuration
            # Note: Sentinel doesn't support CONFIG command like Redis
            # Instead, we'll collect configuration from INFO and other commands
            config = {}
            
            # Get basic Sentinel info which contains some config info
            info = client.info()
            if info:
                # Extract configuration-like information from INFO
                config.update({
                    'port': info.get('tcp_port', 26379),
                    'bind': info.get('bind', ''),
                    'logfile': info.get('logfile', ''),
                    'dir': info.get('config_file_dir', ''),
                    'sentinel_id': info.get('run_id', ''),
                    'redis_version': info.get('redis_version', ''),
                    'uptime_in_seconds': info.get('uptime_in_seconds', 0),
                })
            
            # Try to get additional config using sentinel-specific commands
            try:
                # This might work on some Sentinel versions
                additional_config = client.config_get("*")
                if additional_config:
                    config.update(additional_config)
            except:
                # Sentinel doesn't support CONFIG command, which is expected
                logger.info("Sentinel doesn't support CONFIG command (expected behavior)")
            
            return config
        except Exception as e:
            logger.error(f"Failed to get Sentinel config: {str(e)}")
            return {}
    
    def get_monitored_masters(self, client: redis.Redis) -> List[Dict]:
        """Get list of masters monitored by this Sentinel"""
        try:
            masters = client.sentinel_masters()
            logger.info(f"Raw sentinel_masters() response: {masters}")
            logger.info(f"Type of masters: {type(masters)}")
            
            # Handle different response formats
            if isinstance(masters, dict):
                # Check if this is a dictionary of masters (key=master_name, value=master_info)
                # or a single master info dictionary
                processed_masters = []
                
                # Look for indicators that this is a master info dict vs masters collection dict
                master_info_keys = {'name', 'ip', 'port', 'flags', 'runid'}
                dict_keys = set(masters.keys())
                
                # If the dict has typical master info keys, treat as single master
                if master_info_keys.intersection(dict_keys):
                    logger.info("Detected single master info dictionary")
                    return [masters]
                else:
                    # This is a collection of masters (master_name -> master_info mapping)
                    logger.info(f"Detected masters collection dictionary with {len(masters)} masters")
                    for master_name, master_info in masters.items():
                        if isinstance(master_info, dict):
                            # Ensure master has 'name' field
                            if 'name' not in master_info:
                                master_info['name'] = master_name
                            processed_masters.append(master_info)
                        else:
                            logger.warning(f"Master {master_name} has non-dict info: {type(master_info)}")
                    
                    return processed_masters
            elif isinstance(masters, list):
                # Process each master in the list
                processed_masters = []
                for i, master in enumerate(masters):
                    logger.info(f"Master {i}: {master} (type: {type(master)})")
                    
                    if isinstance(master, dict):
                        processed_masters.append(master)
                    elif isinstance(master, (list, tuple)) and len(master) >= 2:
                        # Some Redis clients return list of [name, info_dict] pairs
                        if len(master) == 2 and isinstance(master[1], dict):
                            master_dict = master[1].copy()
                            master_dict['name'] = master[0]  # Add name to the dict
                            processed_masters.append(master_dict)
                        else:
                            logger.warning(f"Unexpected master format: {master}")
                    else:
                        logger.warning(f"Skipping master with unexpected format: {master} (type: {type(master)})")
                
                return processed_masters
            else:
                logger.error(f"Unexpected masters response format: {type(masters)}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get monitored masters: {str(e)}")
            return []
    
    def get_master_details(self, client: redis.Redis, master_name: str) -> Dict:
        """Get detailed information about a specific master"""
        try:
            master_info = client.sentinel_master(master_name)
            return master_info
        except Exception as e:
            logger.error(f"Failed to get master details for {master_name}: {str(e)}")
            return {}
    
    def get_master_slaves(self, client: redis.Redis, master_name: str) -> List[Dict]:
        """Get list of slaves for a specific master"""
        try:
            # Try different approaches to handle Redis client version compatibility
            try:
                # First try the standard call
                slaves = client.sentinel_slaves(master_name)
            except TypeError as te:
                if 'return_responses' in str(te):
                    # Handle Redis client version incompatibility
                    logger.info(f"Handling Redis client compatibility issue for slaves of master {master_name}")
                    try:
                        # Try using execute_command directly
                        slaves = client.execute_command('SENTINEL', 'SLAVES', master_name)
                    except Exception as exec_e:
                        logger.warning(f"execute_command also failed for slaves of master {master_name}: {str(exec_e)}")
                        # Try creating a new client with different settings
                        try:
                            temp_client = redis.Redis(
                                host=client.connection_pool.connection_kwargs['host'],
                                port=client.connection_pool.connection_kwargs['port'],
                                password=client.connection_pool.connection_kwargs.get('password'),
                                decode_responses=True,
                                socket_timeout=5
                            )
                            slaves = temp_client.execute_command('SENTINEL', 'SLAVES', master_name)
                            temp_client.close()
                        except Exception as temp_e:
                            logger.error(f"All fallback methods failed for slaves of master {master_name}: {str(temp_e)}")
                            return []
                else:
                    raise te
            
            # Process the response
            if isinstance(slaves, list):
                processed_slaves = []
                for slave in slaves:
                    if isinstance(slave, dict):
                        processed_slaves.append(slave)
                    elif isinstance(slave, list) and len(slave) >= 2:
                        # Convert list format to dict format
                        slave_dict = {}
                        for i in range(0, len(slave), 2):
                            if i + 1 < len(slave):
                                key = slave[i]
                                value = slave[i + 1]
                                slave_dict[key] = value
                        processed_slaves.append(slave_dict)
                    else:
                        logger.warning(f"Unexpected slave format: {slave}")
                return processed_slaves
            else:
                logger.warning(f"Unexpected slaves response format: {type(slaves)}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get slaves for master {master_name}: {str(e)}")
            return []
    
    def get_other_sentinels(self, client: redis.Redis, master_name: str) -> List[Dict]:
        """Get list of other sentinels monitoring the same master"""
        try:
            # Try different approaches to handle Redis client version compatibility
            try:
                # First try the standard call
                sentinels = client.sentinel_sentinels(master_name)
            except TypeError as te:
                if 'return_responses' in str(te):
                    # Handle Redis client version incompatibility
                    logger.info(f"Handling Redis client compatibility issue for master {master_name}")
                    try:
                        # Try using execute_command directly
                        sentinels = client.execute_command('SENTINEL', 'SENTINELS', master_name)
                    except Exception as exec_e:
                        logger.warning(f"execute_command also failed for master {master_name}: {str(exec_e)}")
                        # Try creating a new client with different settings
                        try:
                            temp_client = redis.Redis(
                                host=client.connection_pool.connection_kwargs['host'],
                                port=client.connection_pool.connection_kwargs['port'],
                                password=client.connection_pool.connection_kwargs.get('password'),
                                decode_responses=True,
                                socket_timeout=5
                            )
                            sentinels = temp_client.execute_command('SENTINEL', 'SENTINELS', master_name)
                            temp_client.close()
                        except Exception as temp_e:
                            logger.error(f"All fallback methods failed for master {master_name}: {str(temp_e)}")
                            return []
                else:
                    raise te
            
            # Process the response
            if isinstance(sentinels, list):
                processed_sentinels = []
                for sentinel in sentinels:
                    if isinstance(sentinel, dict):
                        processed_sentinels.append(sentinel)
                    elif isinstance(sentinel, list) and len(sentinel) >= 2:
                        # Convert list format to dict format
                        sentinel_dict = {}
                        for i in range(0, len(sentinel), 2):
                            if i + 1 < len(sentinel):
                                key = sentinel[i]
                                value = sentinel[i + 1]
                                sentinel_dict[key] = value
                        processed_sentinels.append(sentinel_dict)
                    else:
                        logger.warning(f"Unexpected sentinel format: {sentinel}")
                return processed_sentinels
            else:
                logger.warning(f"Unexpected sentinels response format: {type(sentinels)}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get other sentinels for master {master_name}: {str(e)}")
            return []
    
    def categorize_sentinel_parameter(self, param_name: str) -> str:
        """Categorize Sentinel configuration parameter"""
        param_lower = param_name.lower()
        
        # Direct mapping
        if param_lower in self.SENTINEL_CONFIG_CATEGORIES:
            return self.SENTINEL_CONFIG_CATEGORIES[param_lower]
        
        # Pattern matching
        if any(keyword in param_lower for keyword in ['monitor', 'master', 'quorum']):
            return 'monitoring'
        elif any(keyword in param_lower for keyword in ['failover', 'timeout', 'parallel']):
            return 'failover'
        elif any(keyword in param_lower for keyword in ['auth', 'pass', 'security']):
            return 'security'
        elif any(keyword in param_lower for keyword in ['notification', 'script', 'notify']):
            return 'notification'
        elif any(keyword in param_lower for keyword in ['log', 'debug']):
            return 'logging'
        elif any(keyword in param_lower for keyword in ['port', 'bind', 'announce', 'network']):
            return 'networking'
        else:
            return 'other'
    
    def save_sentinel_instance(self, host: str, port: int, info: Dict, masters_count: int = 0, raw_info: str = "") -> SentinelInstance:
        """Save Sentinel instance information to database"""
        
        # Always create a new SentinelInstance for each analysis session
        instance = SentinelInstance.objects.create(
            analysis_session=self.session,
            ip_address=host,
            port=port,
            status='online',
            version=info.get('redis_version', ''),
            uptime_seconds=info.get('uptime_in_seconds'),
            sentinel_id=info.get('run_id', ''),
            masters_count=masters_count,
            connected_clients=info.get('connected_clients'),
            max_clients=info.get('maxclients'),
            raw_info_output=raw_info,
        )
        
        return instance
    
    def save_sentinel_configurations(self, sentinel: SentinelInstance, config: Dict, masters_config: Dict = None):
        """Save Sentinel configurations to database"""
        
        # Clear existing configurations for this sentinel
        SentinelConfiguration.objects.filter(sentinel=sentinel).delete()
        
        # Save general configurations
        for param_name, param_value in config.items():
            category = self.categorize_sentinel_parameter(param_name)
            
            SentinelConfiguration.objects.create(
                sentinel=sentinel,
                parameter_name=param_name,
                parameter_value=str(param_value),
                category=category,
            )
        
        # Save master-specific configurations if provided
        if masters_config:
            for master_name, master_params in masters_config.items():
                for param_name, param_value in master_params.items():
                    category = self.categorize_sentinel_parameter(param_name)
                    
                    SentinelConfiguration.objects.create(
                        sentinel=sentinel,
                        parameter_name=param_name,
                        parameter_value=str(param_value),
                        category=category,
                        master_name=master_name,
                    )
    
    def save_monitored_master(self, sentinel: SentinelInstance, master_info: Dict) -> MonitoredMaster:
        """Save monitored master information to database"""
        
        def safe_int(value, default=0):
            """Safely convert value to int"""
            try:
                return int(value) if value is not None else default
            except (ValueError, TypeError):
                return default
        
        master_name = master_info.get('name', 'unnamed_master')
        master_ip = master_info.get('ip', '')
        master_port = safe_int(master_info.get('port'), 6379)
        
        # Always create a new MonitoredMaster for each analysis session
        monitored_master = MonitoredMaster.objects.create(
            sentinel=sentinel,
            master_name=master_name,
            master_ip=master_ip,
            master_port=master_port,
            status=master_info.get('flags', 'master'),
            quorum=safe_int(master_info.get('quorum')),
            down_after_milliseconds=safe_int(master_info.get('down-after-milliseconds')),
            failover_timeout=safe_int(master_info.get('failover-timeout')),
            parallel_syncs=safe_int(master_info.get('parallel-syncs')),
            last_ping_sent=safe_int(master_info.get('last-ping-sent')),
            last_ok_ping_reply=safe_int(master_info.get('last-ok-ping-reply')),
            last_ping_reply=safe_int(master_info.get('last-ping-reply')),
            num_slaves=safe_int(master_info.get('num-slaves')),
            num_other_sentinels=safe_int(master_info.get('num-other-sentinels')),
        )
        
        return monitored_master
    
    def analyze_sentinel_configuration(self, sentinel_host: str, sentinel_port: int = 26379, password: str = None) -> SentinelAnalysisSession:
        """Analyze Sentinel configuration only"""
        
        # Create analysis session
        self.session = SentinelAnalysisSession.objects.create(
            user=self.user,
            sentinel_ip=sentinel_host,
            sentinel_port=sentinel_port,
            analysis_type='config',
            session_name=self.session_name,
            status='running'
        )
        
        try:
            # Connect to Sentinel
            sentinel_client = self.connect_to_sentinel(sentinel_host, sentinel_port, password)
            if not sentinel_client:
                self.session.status = 'failed'
                self.session.error_message = f"Failed to connect to Sentinel at {sentinel_host}:{sentinel_port}"
                self.session.analysis_end_time = timezone.now()
                self.session.save()
                return self.session
            
            # Get Sentinel information and configuration
            sentinel_info = self.get_sentinel_info(sentinel_client)
            sentinel_config = self.get_sentinel_config(sentinel_client)
            masters = self.get_monitored_masters(sentinel_client)
            
            # Save Sentinel instance
            sentinel_instance = self.save_sentinel_instance(
                sentinel_host, sentinel_port, sentinel_info, len(masters)
            )
            
            # Save Sentinel configurations
            self.save_sentinel_configurations(sentinel_instance, sentinel_config)
            
            # Save monitored masters (basic info only for config analysis)
            for master_info in masters:
                self.save_monitored_master(sentinel_instance, master_info)
            
            # Update session
            self.session.total_sentinels_found = 1
            self.session.total_masters_found = len(masters)
            self.session.successful_connections = 1
            self.session.failed_connections = 0
            self.session.analysis_end_time = timezone.now()
            self.session.status = 'completed'
            
            sentinel_client.close()
            
        except Exception as e:
            logger.error(f"Sentinel configuration analysis failed: {str(e)}")
            self.session.status = 'failed'
            self.session.error_message = str(e)
            self.session.analysis_end_time = timezone.now()
        
        self.session.save()
        return self.session
    
    def analyze_sentinel_masters(self, sentinel_host: str, sentinel_port: int = 26379, password: str = None) -> SentinelAnalysisSession:
        """Analyze all masters discovered through Sentinel and their slaves"""
        
        # Create analysis session
        self.session = SentinelAnalysisSession.objects.create(
            user=self.user,
            sentinel_ip=sentinel_host,
            sentinel_port=sentinel_port,
            analysis_type='discovery',
            session_name=self.session_name,
            status='running'
        )
        
        try:
            # Connect to Sentinel
            sentinel_client = self.connect_to_sentinel(sentinel_host, sentinel_port, password)
            if not sentinel_client:
                self.session.status = 'failed'
                self.session.error_message = f"Failed to connect to Sentinel at {sentinel_host}:{sentinel_port}"
                self.session.analysis_end_time = timezone.now()
                self.session.save()
                return self.session
            
            # Get Sentinel information and monitored masters
            sentinel_info = self.get_sentinel_info(sentinel_client)
            sentinel_raw_info = self.get_sentinel_info_raw(sentinel_client)
            masters = self.get_monitored_masters(sentinel_client)
            
            # Save Sentinel instance
            sentinel_instance = self.save_sentinel_instance(
                sentinel_host, sentinel_port, sentinel_info, len(masters), sentinel_raw_info
            )
            
            successful_connections = 1  # Sentinel itself
            failed_connections = 0
            total_instances_analyzed = 0
            
            # Analyze each master and its slaves
            for i, master_info in enumerate(masters):
                master_name = f"master_{i}"  # Initialize with default value
                try:
                    # Validate that master_info is a dictionary
                    if not isinstance(master_info, dict):
                        logger.error(f"Master {i} is not a dictionary: {master_info} (type: {type(master_info)})")
                        failed_connections += 1
                        continue
                    
                    master_name = master_info.get('name', f'unnamed_master_{i}')
                    master_ip = master_info.get('ip', '')
                    master_port_raw = master_info.get('port', 6379)
                    
                    # Safely convert port to int
                    try:
                        master_port = int(master_port_raw)
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid port for master {master_name}: {master_port_raw}, using default 6379")
                        master_port = 6379
                    
                    if not master_ip:
                        logger.warning(f"Master {master_name} has no IP address, skipping")
                        failed_connections += 1
                        continue
                    
                    logger.info(f"Processing master: {master_name} at {master_ip}:{master_port}")
                    
                    # Save monitored master info
                    monitored_master = self.save_monitored_master(sentinel_instance, master_info)
                    
                    # Use RedisAnalyzer to analyze the actual master and its slaves
                    redis_session = self.redis_analyzer.analyze_redis_cluster(
                        master_ip, master_port, password
                    )
                    
                    # Link the Redis instance to the monitored master
                    if redis_session and redis_session.status in ['completed', 'partial']:
                        redis_instance = RedisInstance.objects.filter(
                            analysis_session__user=self.user,
                            ip_address=master_ip,
                            port=master_port,
                            role='master'
                        ).first()
                        
                        if redis_instance:
                            monitored_master.redis_instance = redis_instance
                            monitored_master.save()
                            logger.info(f"Linked Redis instance for master {master_name}")
                    
                    # Update counters
                    if redis_session:
                        successful_connections += redis_session.successful_connections
                        failed_connections += redis_session.failed_connections
                        total_instances_analyzed += redis_session.total_instances_found
                        logger.info(f"Master {master_name} analysis: success={redis_session.successful_connections}, failed={redis_session.failed_connections}")
                    else:
                        failed_connections += 1
                        logger.warning(f"No Redis session returned for master {master_name}")
                    
                except Exception as e:
                    logger.error(f"Failed to analyze master {master_name}: {str(e)}")
                    import traceback
                    logger.error(f"Traceback: {traceback.format_exc()}")
                    failed_connections += 1
            
            # Update session
            self.session.total_sentinels_found = 1
            self.session.total_masters_found = len(masters)
            self.session.total_instances_analyzed = total_instances_analyzed
            self.session.successful_connections = successful_connections
            self.session.failed_connections = failed_connections
            self.session.analysis_end_time = timezone.now()
            
            if failed_connections == 0:
                self.session.status = 'completed'
            elif successful_connections > 0:
                self.session.status = 'partial'
            else:
                self.session.status = 'failed'
            
            sentinel_client.close()
            
        except Exception as e:
            logger.error(f"Sentinel master discovery analysis failed: {str(e)}")
            self.session.status = 'failed'
            self.session.error_message = str(e)
            self.session.analysis_end_time = timezone.now()
        
        self.session.save()
        return self.session
    
    def analyze_sentinel_full(self, sentinel_host: str, sentinel_port: int = 26379, password: str = None) -> SentinelAnalysisSession:
        """Full Sentinel analysis: configuration + master discovery"""
        
        # Create analysis session
        self.session = SentinelAnalysisSession.objects.create(
            user=self.user,
            sentinel_ip=sentinel_host,
            sentinel_port=sentinel_port,
            analysis_type='full',
            session_name=self.session_name,
            status='running'
        )
        
        try:
            # Connect to Sentinel
            sentinel_client = self.connect_to_sentinel(sentinel_host, sentinel_port, password)
            if not sentinel_client:
                self.session.status = 'failed'
                self.session.error_message = f"Failed to connect to Sentinel at {sentinel_host}:{sentinel_port}"
                self.session.analysis_end_time = timezone.now()
                self.session.save()
                return self.session
            
            # Get Sentinel information and configuration
            sentinel_info = self.get_sentinel_info(sentinel_client)
            sentinel_raw_info = self.get_sentinel_info_raw(sentinel_client)
            sentinel_config = self.get_sentinel_config(sentinel_client)
            masters = self.get_monitored_masters(sentinel_client)
            
            # Save Sentinel instance
            sentinel_instance = self.save_sentinel_instance(
                sentinel_host, sentinel_port, sentinel_info, len(masters), sentinel_raw_info
            )
            
            # Save Sentinel configurations
            self.save_sentinel_configurations(sentinel_instance, sentinel_config)
            
            successful_connections = 1  # Sentinel itself
            failed_connections = 0
            total_instances_analyzed = 0
            
            # Analyze each master and its slaves
            for i, master_info in enumerate(masters):
                master_name = f"master_{i}"  # Initialize with default value
                try:
                    # Validate that master_info is a dictionary
                    if not isinstance(master_info, dict):
                        logger.error(f"Master {i} is not a dictionary: {master_info} (type: {type(master_info)})")
                        failed_connections += 1
                        continue
                    
                    master_name = master_info.get('name', f'unnamed_master_{i}')
                    master_ip = master_info.get('ip', '')
                    master_port_raw = master_info.get('port', 6379)
                    
                    # Safely convert port to int
                    try:
                        master_port = int(master_port_raw)
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid port for master {master_name}: {master_port_raw}, using default 6379")
                        master_port = 6379
                    
                    if not master_ip:
                        logger.warning(f"Master {master_name} has no IP address, skipping")
                        failed_connections += 1
                        continue
                    
                    logger.info(f"Processing master: {master_name} at {master_ip}:{master_port}")
                    
                    # Save monitored master info
                    monitored_master = self.save_monitored_master(sentinel_instance, master_info)
                    
                    # Use RedisAnalyzer to analyze the actual master and its slaves
                    redis_session = self.redis_analyzer.analyze_redis_cluster(
                        master_ip, master_port, password
                    )
                    
                    # Link the Redis instance to the monitored master
                    if redis_session and redis_session.status in ['completed', 'partial']:
                        redis_instance = RedisInstance.objects.filter(
                            analysis_session__user=self.user,
                            ip_address=master_ip,
                            port=master_port,
                            role='master'
                        ).first()
                        
                        if redis_instance:
                            monitored_master.redis_instance = redis_instance
                            monitored_master.save()
                            logger.info(f"Linked Redis instance for master {master_name}")
                    
                    # Update counters
                    if redis_session:
                        successful_connections += redis_session.successful_connections
                        failed_connections += redis_session.failed_connections
                        total_instances_analyzed += redis_session.total_instances_found
                        logger.info(f"Master {master_name} analysis: success={redis_session.successful_connections}, failed={redis_session.failed_connections}")
                    else:
                        failed_connections += 1
                        logger.warning(f"No Redis session returned for master {master_name}")
                    
                except Exception as e:
                    logger.error(f"Failed to analyze master {master_name}: {str(e)}")
                    import traceback
                    logger.error(f"Traceback: {traceback.format_exc()}")
                    failed_connections += 1
            
            # Update session
            self.session.total_sentinels_found = 1
            self.session.total_masters_found = len(masters)
            self.session.total_instances_analyzed = total_instances_analyzed
            self.session.successful_connections = successful_connections
            self.session.failed_connections = failed_connections
            self.session.analysis_end_time = timezone.now()
            
            if failed_connections == 0:
                self.session.status = 'completed'
            elif successful_connections > 0:
                self.session.status = 'partial'
            else:
                self.session.status = 'failed'
            
            sentinel_client.close()
            
        except Exception as e:
            logger.error(f"Full Sentinel analysis failed: {str(e)}")
            self.session.status = 'failed'
            self.session.error_message = str(e)
            self.session.analysis_end_time = timezone.now()
        
        self.session.save()
        return self.session
    
    def discover_sentinel_topology(self, client: redis.Redis) -> List[Dict]:
        """Discover all Sentinels in the topology from one Sentinel"""
        discovered_sentinels = set()  # Use set to avoid duplicates
        
        try:
            # Get all masters monitored by this Sentinel
            masters = self.get_monitored_masters(client)
            
            for master_info in masters:
                if not isinstance(master_info, dict):
                    continue
                    
                master_name = master_info.get('name')
                if not master_name:
                    continue
                
                # Get other Sentinels monitoring this master
                other_sentinels = self.get_other_sentinels(client, master_name)
                
                for sentinel_info in other_sentinels:
                    if isinstance(sentinel_info, dict):
                        sentinel_ip = sentinel_info.get('ip')
                        sentinel_port = sentinel_info.get('port', 26379)
                        
                        if sentinel_ip and sentinel_port:
                            # Convert port to int if it's a string
                            try:
                                sentinel_port = int(sentinel_port)
                            except (ValueError, TypeError):
                                sentinel_port = 26379
                                
                            discovered_sentinels.add((sentinel_ip, sentinel_port))
            
            # Convert set to list of dictionaries
            result = []
            for ip, port in discovered_sentinels:
                result.append({
                    'ip': ip,
                    'port': port,
                    'source': 'topology_discovery'
                })
            
            logger.info(f"Discovered {len(result)} Sentinels in topology: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to discover Sentinel topology: {str(e)}")
            return []
    
    def analyze_sentinel_topology(self, sentinel_host: str, sentinel_port: int = 26379, password: str = None) -> SentinelAnalysisSession:
        """Discover and analyze all Sentinels in the topology starting from one Sentinel"""
        
        # Create analysis session
        self.session = SentinelAnalysisSession.objects.create(
            user=self.user,
            sentinel_ip=sentinel_host,
            sentinel_port=sentinel_port,
            analysis_type='topology',
            session_name=self.session_name,
            status='running'
        )
        
        try:
            # Connect to the initial Sentinel
            initial_client = self.connect_to_sentinel(sentinel_host, sentinel_port, password)
            if not initial_client:
                self.session.status = 'failed'
                self.session.error_message = f"Failed to connect to initial Sentinel at {sentinel_host}:{sentinel_port}"
                self.session.analysis_end_time = timezone.now()
                self.session.save()
                return self.session
            
            # Discover all Sentinels in the topology
            discovered_sentinels = self.discover_sentinel_topology(initial_client)
            
            # Add the initial Sentinel to the list if not already present
            initial_sentinel = {'ip': sentinel_host, 'port': sentinel_port, 'source': 'initial'}
            sentinel_exists = any(
                s['ip'] == sentinel_host and s['port'] == sentinel_port 
                for s in discovered_sentinels
            )
            if not sentinel_exists:
                discovered_sentinels.insert(0, initial_sentinel)
            
            logger.info(f"Total Sentinels to analyze: {len(discovered_sentinels)}")
            
            successful_connections = 0
            failed_connections = 0
            total_masters_found = 0
            total_instances_analyzed = 0
            
            # Analyze each discovered Sentinel
            for i, sentinel_info in enumerate(discovered_sentinels):
                sentinel_ip = sentinel_info['ip']
                sentinel_port = sentinel_info['port']
                source = sentinel_info.get('source', 'discovered')
                
                try:
                    logger.info(f"Analyzing Sentinel {i+1}/{len(discovered_sentinels)}: {sentinel_ip}:{sentinel_port} ({source})")
                    
                    # Use existing connection for initial Sentinel, create new for others
                    if sentinel_ip == sentinel_host and sentinel_port == int(sentinel_port) and source == 'initial':
                        sentinel_client = initial_client
                    else:
                        sentinel_client = self.connect_to_sentinel(sentinel_ip, sentinel_port, password)
                        if not sentinel_client:
                            logger.warning(f"Failed to connect to Sentinel {sentinel_ip}:{sentinel_port}")
                            failed_connections += 1
                            continue
                    
                    # Get Sentinel information and configuration
                    sentinel_info_data = self.get_sentinel_info(sentinel_client)
                    sentinel_raw_info = self.get_sentinel_info_raw(sentinel_client)
                    sentinel_config = self.get_sentinel_config(sentinel_client)
                    masters = self.get_monitored_masters(sentinel_client)
                    
                    # Save Sentinel instance
                    sentinel_instance = self.save_sentinel_instance(
                        sentinel_ip, sentinel_port, sentinel_info_data, len(masters), sentinel_raw_info
                    )
                    
                    # Save Sentinel configurations
                    self.save_sentinel_configurations(sentinel_instance, sentinel_config)
                    
                    successful_connections += 1
                    total_masters_found += len(masters)
                    
                    # Analyze each master and its slaves for this Sentinel
                    for j, master_info in enumerate(masters):
                        master_name = f"master_{j}"  # Initialize with default value
                        try:
                            # Validate that master_info is a dictionary
                            if not isinstance(master_info, dict):
                                logger.error(f"Master {j} is not a dictionary: {master_info} (type: {type(master_info)})")
                                continue
                            
                            master_name = master_info.get('name', f'unnamed_master_{j}')
                            master_ip = master_info.get('ip', '')
                            master_port_raw = master_info.get('port', 6379)
                            
                            # Safely convert port to int
                            try:
                                master_port = int(master_port_raw)
                            except (ValueError, TypeError):
                                logger.warning(f"Invalid port for master {master_name}: {master_port_raw}, using default 6379")
                                master_port = 6379
                            
                            if not master_ip:
                                logger.warning(f"Master {master_name} has no IP address, skipping")
                                continue
                            
                            logger.info(f"Processing master: {master_name} at {master_ip}:{master_port} (from Sentinel {sentinel_ip}:{sentinel_port})")
                            
                            # Save monitored master info
                            monitored_master = self.save_monitored_master(sentinel_instance, master_info)
                            
                            # Check if we've already analyzed this master in this session
                            existing_redis_instance = RedisInstance.objects.filter(
                                analysis_session__user=self.user,
                                ip_address=master_ip,
                                port=master_port,
                                role='master',
                                created_at__gte=self.session.analysis_start_time
                            ).first()
                            
                            if existing_redis_instance:
                                # Link to existing analysis and update master name
                                monitored_master.redis_instance = existing_redis_instance
                                monitored_master.save()
                                
                                # Update the Redis instance with master name if not already set
                                if not existing_redis_instance.master_name:
                                    existing_redis_instance.master_name = master_name
                                    existing_redis_instance.save()
                                
                                logger.info(f"Linked to existing Redis analysis for master {master_name}")
                            else:
                                # Use RedisAnalyzer to analyze the actual master and its slaves
                                redis_session = self.redis_analyzer.analyze_redis_cluster(
                                    master_ip, master_port, password
                                )
                                
                                # Link the Redis instance to the monitored master
                                if redis_session and redis_session.status in ['completed', 'partial']:
                                    redis_instance = RedisInstance.objects.filter(
                                        analysis_session__user=self.user,
                                        ip_address=master_ip,
                                        port=master_port,
                                        role='master'
                                    ).first()
                                    
                                    if redis_instance:
                                        # Update Redis instance with master name from Sentinel
                                        redis_instance.master_name = master_name
                                        redis_instance.save()
                                        
                                        monitored_master.redis_instance = redis_instance
                                        monitored_master.save()
                                        logger.info(f"Linked Redis instance for master {master_name}")
                                
                                # Update counters for new analysis
                                if redis_session:
                                    successful_connections += redis_session.successful_connections
                                    failed_connections += redis_session.failed_connections
                                    total_instances_analyzed += redis_session.total_instances_found
                                    logger.info(f"Master {master_name} analysis: success={redis_session.successful_connections}, failed={redis_session.failed_connections}")
                                else:
                                    failed_connections += 1
                                    logger.warning(f"No Redis session returned for master {master_name}")
                        
                        except Exception as e:
                            logger.error(f"Failed to analyze master {master_name}: {str(e)}")
                            failed_connections += 1
                    
                    # Close connection if it's not the initial one
                    if sentinel_client != initial_client:
                        sentinel_client.close()
                        
                except Exception as e:
                    logger.error(f"Failed to analyze Sentinel {sentinel_ip}:{sentinel_port}: {str(e)}")
                    failed_connections += 1
            
            # Close the initial connection
            initial_client.close()
            
            # Update session
            self.session.total_sentinels_found = len(discovered_sentinels)
            self.session.total_masters_found = total_masters_found
            self.session.total_instances_analyzed = total_instances_analyzed
            self.session.successful_connections = successful_connections
            self.session.failed_connections = failed_connections
            self.session.analysis_end_time = timezone.now()
            
            if failed_connections == 0:
                self.session.status = 'completed'
            elif successful_connections > 0:
                self.session.status = 'partial'
            else:
                self.session.status = 'failed'
            
        except Exception as e:
            logger.error(f"Sentinel topology analysis failed: {str(e)}")
            self.session.status = 'failed'
            self.session.error_message = str(e)
            self.session.analysis_end_time = timezone.now()
        
        self.session.save()
        return self.session