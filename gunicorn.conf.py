# Gunicorn configuration file for Redis Lens
# Optimized for long-running Redis analysis operations (5-10 minutes)
import multiprocessing
import os

# Server socket
bind = "0.0.0.0:8000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50

# Timeout - Set to 0 to disable worker timeout completely
# This allows Redis topology analysis operations to run for 5-10 minutes without being killed
timeout = 0
keepalive = 2
graceful_timeout = 60

# Restart workers after this many seconds of idle time
max_worker_age = 3600

# Worker memory management - restart workers that exceed memory usage
max_worker_memory_usage = 1024 * 1024 * 1024  # 1GB (increased for long-running operations)

# Logging
loglevel = "info"
accesslog = "/app/logs/gunicorn-access.log"
errorlog = "/app/logs/gunicorn-error.log"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "redislens"

# Preload app
preload_app = True

# Worker restarts - handled by the memory management above

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

def worker_abort(worker):
    """Called when a worker is aborted (SIGABRT)"""
    worker.log.error("Worker process aborted")

def worker_exit(server, worker):
    """Called when a worker exits"""
    worker.log.info("Worker process exiting")

def on_starting(server):
    """Called just before the master process is initialized"""
    server.log.info("Gunicorn server starting")

def on_reload(server):
    """Called to recycle workers during a reload via SIGHUP"""
    server.log.info("Gunicorn server reloading")

def when_ready(server):
    """Called just after the server is started"""
    server.log.info("Gunicorn server is ready")

def on_exit(server):
    """Called just before exiting"""
    server.log.info("Gunicorn server shutting down")
