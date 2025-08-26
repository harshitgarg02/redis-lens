# 🚀 RedisLens

RedisLens is a comprehensive web-based Redis analysis platform with intelligent anomaly detection, built with Django. This application provides deep insights into Redis instances, Sentinel configurations, and automated detection of configuration issues.

![RedisLens](https://img.shields.io/badge/RedisLens-Analytics-red?style=for-the-badge&logo=redis)
![Django](https://img.shields.io/badge/Django-4.x-green?style=for-the-badge&logo=django)
![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python)
![Anomaly Detection](https://img.shields.io/badge/Anomaly-Detection-orange?style=for-the-badge)

## ✨ Key Features

### 🔍 **Redis Instance Analysis**

- **Comprehensive Monitoring**: Real-time analysis of Redis instances with detailed metrics
- **Performance Metrics**: Memory usage, hit ratios, command processing statistics
- **Keyspace Analysis**: Database-wise key counts, expiration info, and TTL statistics
- **Configuration Analysis**: Detailed parameter inspection and categorization
- **Raw Data Access**: Complete `redis-cli INFO` command output for debugging

### 🛡️ **Sentinel Monitoring**

- **Full Sentinel Analysis**: Complete monitoring of Redis Sentinel configurations
- **Master Discovery**: Automatic detection and monitoring of all masters
- **Replication Topology**: Visual representation of master-slave relationships
- **Health Monitoring**: Connection status, failover configurations, and quorum settings
- **🕐 Long-Running Support**: Optimized for 5-10 minute topology analysis operations

### 🎯 **Intelligent Anomaly Detection**

- **33 Detection Rules**: Comprehensive rule set covering security, performance, and reliability
- **Real-time Analysis**: Automatic anomaly detection during Redis analysis
- **Multi-severity System**: Critical, Warning, and Notice level alerts
- **Visual Highlighting**: Configuration parameters with issues are highlighted in the UI
- **Detailed Context**: Each anomaly includes specific values and recommendations
- **Status Management**: Track anomaly acknowledgment and resolution

### 📊 **Advanced Reporting & Export**

- **Multiple Formats**: Export analysis data in CSV and JSON formats
- **Anomaly Reports**: Dedicated anomaly detection dashboards and exports
- **Historical Tracking**: Access to all previous analysis sessions and anomaly trends
- **User Isolation**: Each user can only access their own data

### 🔐 **Security & Multi-User Support**

- **User Authentication**: Multiple authentication methods (OAuth SSO, Local accounts)
- **User Registration**: Built-in signup system for local account creation
- **Data Privacy**: Complete separation of user data between accounts
- **Session Management**: Secure session handling and user management
- **Flexible Login**: OAuth for enterprise integration + local accounts for development

## 🔍 **Redis Commands & Operations**

RedisLens performs **read-only operations** exclusively, making it safe for production environments. Here are the specific Redis commands executed:

### **Connection & Health Check**

- **`PING`** - Verify Redis server connectivity and responsiveness

### **Information Gathering**

- **`INFO`** - Collect comprehensive server statistics, memory usage, and configuration
- **`INFO replication`** - Get detailed replication status and topology information

### **Configuration Analysis**

- **`CONFIG GET *`** - Retrieve all Redis configuration parameters for analysis

### **Sentinel-Specific Commands**

- **`SENTINEL MASTERS`** - Discover all masters monitored by Sentinel
- **`SENTINEL MASTER <name>`** - Get detailed information about specific masters
- **`SENTINEL SLAVES <name>`** - Discover slave instances for each master
- **`SENTINEL SENTINELS <name>`** - Find other Sentinels in the topology

### **Data Collected**

- **Server Metrics**: Version, uptime, memory usage, client connections
- **Performance Data**: Keyspace hits/misses, command processing statistics
- **Replication Info**: Master-slave relationships, lag, and synchronization status
- **Configuration**: All Redis parameters categorized by function
- **Topology**: Complete cluster structure and Sentinel monitoring setup

### **Security Notes**

- **No Write Operations**: RedisLens never modifies data or configuration
- **No Data Access**: Does not read or access your stored data/keys
- **Connection Security**: Supports password authentication and SSL connections
- **Audit Trail**: All operations are logged for security review

## 🛠️ Installation & Setup

### Prerequisites

- Python 3.9 or higher
- Redis instances (for analysis)
- Redis Sentinel (optional, for Sentinel analysis)
- Modern web browser
- **Database:** SQLite (default) or PostgreSQL (optional for production-like development)

### Quick Start with Docker

#### Option 1: Use Pre-built Image (Fastest)

Run RedisLens directly from Docker Hub without cloning the repository:

```bash
# Pull and run the latest image
docker pull harshitgarg02/redis-lens
docker run -d -p 8000:8000 --name redis-lens harshitgarg02/redis-lens

# Access at http://localhost:8000
```

**With custom environment variables:**

```bash
docker run -d -p 8000:8000 \
  -e DJANGO_DEBUG=False \
  -e DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0 \
  -e DJANGO_LOG_LEVEL=WARNING \
  --name redis-lens \
  harshitgarg02/redis-lens
```

**With persistent data (recommended):**

```bash
# Create a volume for persistent data
docker volume create redis-lens-data

# Run with persistent database
docker run -d -p 8000:8000 \
  -v redis-lens-data:/app \
  --name redis-lens \
  harshitgarg02/redis-lens
```

#### Option 2: Build from Source

For development or customization:

```bash
# Clone the repository
git clone https://github.com/yourusername/redislens.git
cd redislens

# Build with optimized production configuration
docker build -t redislens .

# Start with Docker Compose
docker-compose up -d

# Access at http://localhost:8000
```

**✨ Production Optimizations in Docker:**

- **No Worker Timeouts**: Supports 5-10 minute Redis analysis operations
- **Enhanced Error Handling**: Robust connection management and retry logic
- **Memory Management**: 1GB per worker for complex topology analysis
- **Comprehensive Logging**: Access and error logs in `/app/logs/`

### Manual Installation

#### 1. Clone & Setup Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/redislens.git
cd redislens

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### 2. Configure Environment

**Option A: Automated Setup (Recommended)**

```bash
# For development (includes OAuth setup option)
./setup-dev.sh

# For production
./setup-prod.sh
```

_The development setup will prompt you to choose database (SQLite or PostgreSQL) and configure OAuth/SSO for testing._

**Option B: Manual Setup**

```bash
# Copy environment template
cp env.example .env

# Edit .env with your configuration
nano .env
```

#### 3. Database Setup

```bash
# Apply database migrations
python manage.py migrate

# Import anomaly detection rules
python manage.py import_anomaly_rules

# Create admin user (optional)
python manage.py create_admin
```

#### 4. Start the Application

```bash
# Start development server
python manage.py runserver

# Access the application at http://localhost:8000
```

### Production Deployment

For production deployment:

1. **Set Environment Variables**:

   ```bash
   export DJANGO_DEBUG=False
   export DJANGO_SECRET_KEY=your-secret-key
   export DATABASE_ENGINE=postgresql
   export DB_PASSWORD=your-db-password
   ```

2. **Use Production Server**:

   ```bash
   # Recommended: Use the included Gunicorn configuration
   gunicorn --config gunicorn.conf.py redislens.wsgi:application

   # Or use basic Gunicorn command
   gunicorn --bind 0.0.0.0:8000 redislens.wsgi:application
   ```

3. **Or use Docker** (Recommended):
   ```bash
   docker build -t redislens .
   docker run -p 8000:8000 redislens
   ```

### 🕐 Long-Running Operations Support

RedisLens is optimized for **long-running Redis topology analysis operations** that can take **5-10 minutes** to complete. The application includes specialized configuration for handling extended operations:

#### **Production Configuration Features**

- **🚫 No Worker Timeouts**: Gunicorn workers can run indefinitely without being killed
- **💾 Extended Memory Limits**: Increased to 1GB for complex topology analysis
- **🔄 Smart Worker Management**: Automatic restarts based on memory usage, not time limits
- **📊 Enhanced Logging**: Comprehensive access and error logs for debugging

#### **Gunicorn Configuration** (`gunicorn.conf.py`)

The application includes a production-ready Gunicorn configuration:

```python
# Worker timeout disabled for long-running operations
timeout = 0  # No timeout - allows 5-10 minute Redis analysis

# Memory and performance settings
workers = multiprocessing.cpu_count() * 2 + 1
max_worker_memory_usage = 1024 * 1024 * 1024  # 1GB
max_requests = 1000
max_requests_jitter = 50

# Enhanced logging
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'
```

#### **Why This Matters**

- **Redis Topology Discovery**: Scanning large Redis clusters with multiple Sentinels
- **Master-Slave Analysis**: Deep analysis of replication chains
- **Anomaly Detection**: Running 33+ detection rules across multiple instances
- **Network Latency**: Operations across multiple data centers or cloud regions

## 🚀 Quick Start Guide

### 1. **Login & Dashboard**

- Navigate to `http://localhost:8000`
- **Multiple login options available:**
  - **OAuth/SSO**: Enterprise authentication (if configured)
  - **Local Login**: Username/password authentication
  - **Sign Up**: Create a new local account instantly
- View the main dashboard with overview statistics

### 2. **Redis Instance Analysis**

1. Click **"Start Analysis"** in the sidebar
2. Enter Redis connection details (host, port, password)
3. Choose analysis type:
   - **Single Instance**: Analyze one Redis instance
   - **Master-Slaves**: Discover and analyze replication setup
   - **Full Cluster**: Comprehensive cluster analysis
4. Click **"Start Analysis"**
5. **Anomaly detection runs automatically** during analysis

### 3. **View Anomaly Detection Results**

- **Dashboard**: Shows anomaly statistics and recent alerts
- **Anomaly Dashboard**: Dedicated anomaly management interface
- **Instance Detail**: Configuration parameters highlighted by anomaly status
- **Anomaly Rules**: Browse all 33 detection rules

### 4. **Manage Anomalies**

- **Acknowledge**: Mark anomalies as acknowledged
- **Resolve**: Mark issues as resolved
- **False Positive**: Flag incorrect detections
- **View Details**: See specific configuration values and recommendations

## 📋 Available Management Commands

### Core Application Commands

```bash
# Create admin user
python manage.py create_admin

# Database operations
python manage.py makemigrations
python manage.py migrate

# Start development server
python manage.py runserver
```

### Anomaly Detection Commands

```bash
# Import anomaly detection rules from CSV
python manage.py import_anomaly_rules

# Run anomaly detection on all instances
python manage.py shell
>>> from analyzer.anomaly_detector import AnomalyDetector
>>> detector = AnomalyDetector()
>>> results = detector.run_full_detection()
```

### Development & Debugging Commands

```bash
# Django shell for debugging
python manage.py shell

# Collect static files (production)
python manage.py collectstatic

# Create database backup
cp db.sqlite3 db_backup_$(date +%Y%m%d_%H%M%S).sqlite3
```

## 🎯 Anomaly Detection System

### Detection Rules Categories

1. **🔗 Client Management (CLIENT-001 to CLIENT-004)**

   - Buffer limit issues
   - Connection limits
   - Query buffer problems

2. **💾 Memory Management (MEM-001 to MEM-006)**

   - Memory policy issues
   - Fragmentation problems
   - Memory limits

3. **🔒 Security (SEC-001 to SEC-004)**

   - Authentication issues
   - Binding problems
   - Security configurations

4. **⚡ Performance (PERF-001 to PERF-005)**

   - Timeout configurations
   - Performance settings
   - Optimization issues

5. **🔄 Replication (REPL-001 to REPL-002)**

   - Replication settings
   - Sync configurations

6. **💿 Persistence (AOF-001 to RDB-002)**

   - Backup configurations
   - Durability settings

7. **📝 Logging (LOG-001 to LOG-002)**

   - Log level issues
   - Logging configurations

8. **🌐 Network (NET-001 to NET-002)**

   - Network settings
   - Connection configurations

9. **⚙️ Process Management (PROC-001 to PROC-002)**
   - Process configurations
   - System settings

### Severity Levels

- **🔴 Critical**: Issues that can cause data loss or service outages
- **🟡 Warning**: Issues that may impact performance or reliability
- **🔵 Notice**: Minor issues or optimization opportunities

### Example Detected Anomalies

```
CLIENT-001 (CRITICAL): Replica buffer limit smaller than replication backlog
MEM-005 (NOTICE): Active rehashing disabled
PROC-001 (WARNING): Daemonization enabled with modern supervisor
REPL-001 (CRITICAL): Network partition protection disabled
SEC-004 (CRITICAL): No authentication required
```

## 🖥️ User Interface

### Main Navigation

- **📊 Dashboard**: Overview and statistics
- **🔍 Analysis**: Start new Redis/Sentinel analysis
- **📋 Sessions**: View historical analysis sessions
- **⚠️ Anomaly Detection**: Anomaly management dashboard
- **📖 Rules**: Browse detection rules
- **⚙️ User Management**: Account settings

### Instance Detail Page Features

- **📊 Metrics Cards**: Key performance indicators
- **⚠️ Anomaly Summary**: Count of critical/warning/notice issues
- **📋 Configuration Table**: Parameters highlighted by anomaly status
- **🔗 Quick Actions**: Run detection, view all anomalies
- **📈 Visual Indicators**: Color-coded status and warning icons

### Anomaly Dashboard Features

- **📊 Statistics Cards**: Total, critical, unresolved anomaly counts
- **🔍 Filtering**: By severity, status, category, instance
- **📋 Anomaly List**: Sortable, paginated list with details
- **⚡ Bulk Actions**: Run detection on all instances
- **📈 Trend Analysis**: Historical anomaly data

## 🏗️ Architecture

### Backend Components

- **Django Framework**: Web application foundation
- **Redis Service**: Direct Redis connection and analysis
- **Sentinel Service**: Sentinel discovery and monitoring
- **Anomaly Detector**: 33-rule anomaly detection engine
- **Export Engine**: Multi-format data export system
- **User Management**: Authentication and data isolation

### Key Models

```python
# Core analysis models
- AnalysisSession: Historical tracking
- RedisInstance: Instance data and metrics
- RedisConfiguration: Parameter storage
- SentinelInstance: Sentinel configurations

# Anomaly detection models
- AnomalyRule: Detection rule definitions
- AnomalyDetection: Detected anomaly records
```

### Anomaly Detection Flow

1. **Redis Analysis**: Collect configuration and metrics
2. **Rule Evaluation**: Apply 33 detection rules
3. **Anomaly Creation**: Record detected issues
4. **UI Integration**: Highlight problematic configurations
5. **Status Management**: Track acknowledgment and resolution

## 📊 API Endpoints

### Analysis Endpoints

```
POST /analyze/                    # Start Redis analysis
POST /sentinel/analyze/           # Start Sentinel analysis
GET  /instance/<id>/              # Instance detail page
GET  /sentinel/<id>/              # Sentinel detail page
```

### Anomaly Detection Endpoints

```
GET  /anomalies/                  # Anomaly dashboard
GET  /anomalies/<id>/             # Anomaly detail
POST /anomalies/<id>/update-status/ # Update anomaly status
POST /anomalies/detect/           # Run detection manually
GET  /anomalies/rules/            # View detection rules
```

### Export Endpoints

```
GET /export/<session_id>/?format=csv   # CSV export
GET /export/<session_id>/?format=json  # JSON export
```

## 🔧 Environment Configuration

RedisLens uses environment variables for secure, flexible configuration across different deployments.

### 📋 Environment File Setup

**Development:**

```bash
# Quick setup
./setup-dev.sh

# Or manually create .env:
cp env.example .env
# Uses SQLite, debug enabled, local authentication
```

**Production:**

```bash
# Quick setup with template
./setup-prod.sh

# Edit .env with your values:
nano .env
```

### 🗝️ Configuration Options

#### **Core Django Settings**

```bash
DJANGO_SECRET_KEY=your-generated-secret-key
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
DJANGO_LOG_LEVEL=INFO
```

#### **Database Options**

```bash
# SQLite (Development)
DATABASE_ENGINE=sqlite

# PostgreSQL (Production)
DATABASE_ENGINE=postgresql
DB_NAME=redislens
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=localhost
DB_PORT=5432
```

#### **Logging Configuration**

```bash
# Control logging verbosity - Valid levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
DJANGO_LOG_LEVEL=INFO

# Logging Level Examples:
# Development (verbose): DJANGO_LOG_LEVEL=DEBUG
# Production (quiet): DJANGO_LOG_LEVEL=WARNING
# Silent mode: DJANGO_LOG_LEVEL=ERROR
```

#### **OAuth/SSO (Optional)**

**Minimum Required Configuration:**

```bash
OAUTH_AUTHN_URL=https://your-sso-provider.com
OAUTH_CLIENT_ID=redislens
OAUTH_CLIENT_SECRET=your-oauth-secret
```

**Full Configuration (with optional settings):**

```bash
OAUTH_AUTHN_URL=https://your-sso-provider.com
OAUTH_CLIENT_ID=redislens
OAUTH_CLIENT_SECRET=your-oauth-secret
OAUTH_TOKEN_URL=https://your-sso-provider.com/token  # Auto-detected if not set
OAUTH_REDIRECT_URI=/oauth/callback/  # Auto-detects current host if path-only
OAUTH_SCOPE=openid profile email
```

**🚀 Smart Features:**

- **Auto-Redirect URI**: Set `OAUTH_REDIRECT_URI=/oauth/callback/` and it automatically detects current domain and protocol (HTTP/HTTPS)
- **Auto-Token URL**: Determines token endpoint based on OAuth provider
- **DNS Support**: Works seamlessly with custom domains without manual configuration

📋 **OAuth Setup Guides:**

- **[DEV_OAUTH_SETUP.md](DEV_OAUTH_SETUP.md)** - OAuth setup for development environment (localhost)
- **[OAUTH_SETUP.md](OAUTH_SETUP.md)** - OAuth setup for production with multiple providers (Azure AD, Google, Okta, etc.)

### 🎯 Common Configurations

**Local Development (Local Accounts Only):**

```bash
DJANGO_DEBUG=True
DATABASE_ENGINE=sqlite
DJANGO_LOG_LEVEL=DEBUG
# No OAuth - use local signup/login
```

**Local Development (With OAuth):**

```bash
DJANGO_DEBUG=True
DATABASE_ENGINE=sqlite
DJANGO_LOG_LEVEL=DEBUG
OAUTH_AUTHN_URL=https://accounts.google.com/o/oauth2/v2/auth
OAUTH_CLIENT_ID=your-google-dev-client-id
OAUTH_CLIENT_SECRET=your-google-dev-client-secret
OAUTH_REDIRECT_URI=/oauth/callback/
OAUTH_SCOPE=openid profile email
# Note: OAUTH_REDIRECT_URI automatically becomes http://localhost:8000/oauth/callback/
```

**Local Development (PostgreSQL):**

```bash
DJANGO_DEBUG=True
DATABASE_ENGINE=postgresql
DB_NAME=redislens_dev
DB_USER=postgres
DB_PASSWORD=your-dev-password
DB_HOST=localhost
DB_PORT=5432
```

**Production with PostgreSQL:**

```bash
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=mycompany.com
DATABASE_ENGINE=postgresql
DB_PASSWORD=secure-password
DJANGO_LOG_LEVEL=WARNING
```

**Enterprise with SSO:**

```bash
DJANGO_DEBUG=False
DATABASE_ENGINE=postgresql
DJANGO_LOG_LEVEL=INFO
OAUTH_AUTHN_URL=https://login.microsoftonline.com/tenant/oauth2/v2.0
OAUTH_CLIENT_ID=redislens-enterprise
```

### Anomaly Detection Configuration

- Rules are imported from CSV file during setup (`Redis_Anomaly_Rules.csv`)
- Rules can be activated/deactivated via admin interface
- Severity levels and categories are configurable
- Detection logic is modular and extensible
- **Note**: CSV exports are automatically ignored by git (except the core rules file)

## 🐛 Troubleshooting

### Common Issues

#### Anomaly Detection Not Working

```bash
# Check if rules are imported
python manage.py shell
>>> from analyzer.models import AnomalyRule
>>> print(f"Rules imported: {AnomalyRule.objects.count()}")

# Run detection manually
>>> from analyzer.anomaly_detector import AnomalyDetector
>>> detector = AnomalyDetector()
>>> results = detector.run_full_detection()
```

#### Migration Issues

```bash
# Reset migrations if needed
python manage.py migrate analyzer zero
python manage.py makemigrations analyzer
python manage.py migrate
```

#### Connection Problems

- Verify Redis/Sentinel is running and accessible
- Check firewall settings and network connectivity
- Ensure correct host and port configuration
- Verify authentication credentials

#### Long-Running Operation Issues

**Worker Timeout Errors:**

```bash
# Check if using proper Gunicorn configuration
gunicorn --config gunicorn.conf.py redislens.wsgi:application

# Verify timeout is disabled in config
grep -n "timeout" gunicorn.conf.py
# Should show: timeout = 0
```

**Memory Issues During Analysis:**

```bash
# Monitor worker memory usage
ps aux | grep gunicorn

# Check logs for memory-related restarts
tail -f /app/logs/gunicorn-error.log

# Increase memory limit if needed (in gunicorn.conf.py):
max_worker_memory_usage = 2048 * 1024 * 1024  # 2GB
```

**Analysis Taking Too Long:**

```bash
# Check Redis connection latency
redis-cli --latency -h your-redis-host -p 6379

# Enable verbose logging for debugging
tail -f /app/logs/gunicorn-access.log

# Monitor active connections
python manage.py shell
>>> from analyzer.models import SentinelAnalysisSession
>>> print("Active sessions:", SentinelAnalysisSession.objects.filter(status='running').count())
```

#### Template Errors

```bash
# Check for template syntax issues
python manage.py check --deploy
```

#### Authentication Issues

**First and Last Names Not Saving:**

```bash
# Check current users and their name status
python manage.py check_users

# Attempt to fix missing names automatically
python manage.py check_users --fix-names

# Validate development setup
python3 test_dev_setup.py

# Run authentication debug guide
python3 debug_auth.py
```

**OAuth Issues:**

- Test OAuth configuration: `python3 test_oauth_dev.py`
- Verify `OAUTH_SCOPE` includes `profile` or `openid profile email`
- Check logs for: `OAuth user data received: [...]`
- Ensure OAuth provider returns name fields (`given_name`, `family_name`)
- Test with different OAuth providers
- Check redirect URI matches exactly: `http://localhost:8000/oauth/callback/`

**Signup Form Issues:**

- Check browser console (F12) for JavaScript errors
- Verify all form fields are properly filled
- Clear browser cache and cookies
- Test in different browsers

### Debug Commands

```bash
# Enable debug mode
export DJANGO_DEBUG=True

# Run with verbose logging
python manage.py runserver --verbosity=2

# PostgreSQL development setup
# macOS: brew install postgresql && brew services start postgresql
# Ubuntu: sudo apt install postgresql postgresql-contrib
# Create dev database: createdb -U postgres redislens_dev

# Check application logs
tail -f logs/redislens.log
```

## 🔒 Security Best Practices

### Production Deployment

- Use HTTPS in production environments
- Configure proper `ALLOWED_HOSTS` settings
- Use a production database (PostgreSQL recommended)
- Set up proper logging and monitoring
- Regular security updates

### User Data Protection

- Each user can only access their own analysis sessions
- Database-level filtering ensures complete data privacy
- Session-based authentication with secure cookies
- No Redis credentials are stored permanently

## 📈 Performance Optimization

### Large Deployments

- Use database indexing for large datasets
- Implement Redis connection pooling
- Consider pagination for large instance lists
- Archive old sessions periodically

### Long-Running Analysis Operations

**Production Configuration (gunicorn.conf.py)**:

- **Timeout Disabled**: `timeout = 0` allows indefinite operation time
- **Memory Management**: 1GB memory limit per worker for complex analyses
- **Worker Scaling**: Auto-scaling based on CPU cores for parallel processing
- **Smart Restarts**: Workers restart based on memory usage, not time limits

**Redis Connection Optimization**:

- Enhanced error handling with specific exception catching
- Automatic connection retry with `retry_on_timeout=True`
- Health check intervals for connection monitoring
- Proper client cleanup to prevent memory leaks

**Network Latency Handling**:

- Extended socket timeouts for cross-region deployments
- Connection pooling for multiple Redis instance analysis
- Graceful degradation when individual connections fail

### Anomaly Detection Optimization

- Rules are evaluated efficiently using categorization
- Detection runs asynchronously during analysis
- Results are cached to avoid repeated processing
- Bulk operations for multiple instances
- Parallel rule execution for large datasets

## 🤝 Contributing

### Development Setup

```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
python manage.py test

# Code style checking
flake8 analyzer/

# Run development server
python manage.py runserver
```

### Adding New Anomaly Rules

1. Add rule to CSV file or create via admin interface
2. Implement detection logic in `AnomalyDetector._evaluate_*_rules()`
3. Add tests for the new rule
4. Update documentation

### Contribution Guidelines

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 File Structure

```
redis-analysis-scripts/
├── README.md                          # This file
├── requirements.txt                   # Python dependencies
├── manage.py                         # Django management script
├── db.sqlite3                        # SQLite database
├── gunicorn.conf.py                  # Production Gunicorn configuration
├── Redis_Anomaly_Rules.csv           # Anomaly detection rules
├── Dockerfile                        # Docker container configuration
├── docker-compose.yml                # Docker Compose configuration
├── redislens/                        # Django project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
└── analyzer/                        # Main application
    ├── models.py                     # Database models
    ├── views.py                      # Web views and logic
    ├── urls.py                       # URL routing
    ├── redis_service.py              # Redis analysis engine
    ├── sentinel_service.py           # Sentinel analysis engine
    ├── anomaly_detector.py           # Anomaly detection engine
    ├── management/commands/          # Custom management commands
    │   ├── create_admin.py           # Admin user creation
    │   └── import_anomaly_rules.py   # Rule import command
    ├── templates/                    # HTML templates
    │   └── analyzer/
    │       ├── dashboard.html        # Main dashboard
    │       ├── instance_detail.html  # Instance details
    │       ├── anomaly_dashboard.html # Anomaly management
    │       └── [other templates]
    └── migrations/                   # Database migrations
```

## 🧪 Quick Start Verification

Test your RedisLens setup with these commands:

### **Environment Verification**

```bash
# Check your environment configuration
python manage.py shell
>>> import os
>>> print(f"Debug mode: {os.getenv('DJANGO_DEBUG', 'False')}")
>>> print(f"Database: {os.getenv('DATABASE_ENGINE', 'sqlite')}")
>>> print(f"OAuth enabled: {'Yes' if os.getenv('OAUTH_CLIENT_ID') else 'No'}")
```

### **Database & Application Setup**

```bash
# Automated setup for development
./setup-dev.sh

# Or manual setup
python manage.py migrate
python manage.py import_anomaly_rules
python manage.py create_admin

# Test the application
python manage.py runserver
# Visit http://localhost:8000
```

### **Docker Setup**

```bash
docker-compose up -d
# Visit http://localhost:8000
```

### **Verify OAuth Configuration (if enabled)**

```bash
# Check OAuth settings
python manage.py shell
>>> from django.conf import settings
>>> print("OAuth Config:", settings.OAUTH_CONFIG)
>>> print("Auth Backends:", settings.AUTHENTICATION_BACKENDS)
```

## 📞 Support & Resources

### Getting Help

- 📖 **Documentation**: This README and in-app help
- 🐛 **Issues**: Create issues in the repository
- 💬 **Discussions**: Use repository discussions for questions
- 📧 **Support**: Contact maintainers for critical issues

### Useful Resources

- [Redis Documentation](https://redis.io/documentation)
- [Django Documentation](https://docs.djangoproject.com/)
- [Bootstrap Documentation](https://getbootstrap.com/docs/)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**🚀 RedisLens** - Making Redis monitoring intelligent, comprehensive, and actionable.

_Built with ❤️ for the Redis community_
