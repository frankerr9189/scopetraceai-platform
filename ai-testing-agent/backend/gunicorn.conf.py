# Gunicorn configuration file
# This file is used to configure Gunicorn for production deployment

import multiprocessing

# Server socket
# Note: bind will be overridden by --bind flag in command line
# This is set for local development; Render uses $PORT environment variable
bind = "0.0.0.0:10000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout = 300  # 5 minutes - increased for OpenAI API calls that can take longer
keepalive = 5

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s - - [%(t)s] - "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = "ai-testing-agent"

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL (if needed)
keyfile = None
certfile = None
