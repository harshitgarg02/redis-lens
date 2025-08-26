# 🐳 RedisLens Docker Image

![Docker Pulls](https://img.shields.io/docker/pulls/harshitgarg02/redis-lens)
![Docker Image Size](https://img.shields.io/docker/image-size/harshitgarg02/redis-lens)
![Docker Stars](https://img.shields.io/docker/stars/harshitgarg02/redis-lens)

**RedisLens** is a comprehensive Redis analysis and monitoring platform that provides deep insights into your Redis infrastructure. This Docker image allows you to quickly deploy RedisLens in any environment.

## 🚀 Quick Start

### Pull and Run

```bash
# Pull the latest image
docker pull harshitgarg02/redis-lens:latest

# Run with default settings
docker run -d -p 8000:8000 --name redis-lens harshitgarg02/redis-lens:latest

# Access at http://localhost:8000
```

### With Custom Configuration

```bash
docker run -d -p 8000:8000 \
  -e DJANGO_SECRET_KEY="your-secret-key-here" \
  -e DJANGO_DEBUG=False \
  -e DJANGO_ALLOWED_HOSTS="yourdomain.com,localhost" \
  -e DJANGO_LOG_LEVEL=INFO \
  --name redis-lens \
  harshitgarg02/redis-lens:latest
```

## 🏷️ Available Tags

| Tag      | Description             | Usage               |
| -------- | ----------------------- | ------------------- |
| `latest` | Latest stable release   | Production use      |
| `v1.0.0` | Specific version 1.0.0  | Version pinning     |
| `1.0.0`  | Same as v1.0.0          | Alternative format  |
| `main`   | Latest from main branch | Development/testing |

```bash
# Use specific version
docker pull harshitgarg02/redis-lens:v1.0.0

# Use latest development build
docker pull harshitgarg02/redis-lens:main
```

## ⚙️ Environment Variables

### **Required Variables**

```bash
# Security (Required for production)
DJANGO_SECRET_KEY=your-unique-secret-key-minimum-50-chars

# Host Configuration (Required for non-localhost access)
DJANGO_ALLOWED_HOSTS=yourdomain.com,192.168.1.100,localhost
```

### **Optional Configuration**

```bash
# Application Settings
DJANGO_DEBUG=False                    # Enable debug mode (default: False)
DJANGO_LOG_LEVEL=INFO                # Logging level (DEBUG,INFO,WARNING,ERROR)

# Database (SQLite by default)
DATABASE_ENGINE=sqlite3               # Database engine
DB_NAME=/app/db.sqlite3              # Database name/path
DB_HOST=localhost                    # Database host
DB_PORT=5432                         # Database port
DB_USER=postgres                     # Database user
DB_PASSWORD=password                 # Database password

# OAuth/SSO Authentication (Optional)
OAUTH_AUTHN_URL=https://your-sso.com
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
OAUTH_REDIRECT_URI=/oauth/callback/   # Auto-detects host
OAUTH_SCOPE=openid profile email
```

## 📁 Volume Mounts

### **Data Persistence**

```bash
# Persist database and logs
docker run -d -p 8000:8000 \
  -v redis-lens-data:/app/db \
  -v redis-lens-logs:/app/logs \
  --name redis-lens \
  harshitgarg02/redis-lens:latest
```

### **Custom Configuration**

```bash
# Mount custom configuration
docker run -d -p 8000:8000 \
  -v /host/path/to/.env:/app/.env:ro \
  --name redis-lens \
  harshitgarg02/redis-lens:latest
```

## 🐙 Docker Compose

### **Basic Setup**

```yaml
version: "3.8"
services:
  redis-lens:
    image: harshitgarg02/redis-lens:latest
    ports:
      - "8000:8000"
    environment:
      - DJANGO_SECRET_KEY=your-secret-key-here
      - DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
      - DJANGO_LOG_LEVEL=INFO
    volumes:
      - redis-lens-data:/app/db
      - redis-lens-logs:/app/logs
    restart: unless-stopped

volumes:
  redis-lens-data:
  redis-lens-logs:
```

### **With PostgreSQL Database**

```yaml
version: "3.8"
services:
  redis-lens:
    image: harshitgarg02/redis-lens:latest
    ports:
      - "8000:8000"
    environment:
      - DJANGO_SECRET_KEY=your-secret-key-here
      - DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
      - DATABASE_ENGINE=postgresql
      - DB_NAME=redislens
      - DB_HOST=postgres
      - DB_USER=redislens
      - DB_PASSWORD=secure-password
    depends_on:
      - postgres
    restart: unless-stopped

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=redislens
      - POSTGRES_USER=redislens
      - POSTGRES_PASSWORD=secure-password
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  postgres-data:
```

### **Production with OAuth**

```yaml
version: "3.8"
services:
  redis-lens:
    image: harshitgarg02/redis-lens:v1.0.0
    ports:
      - "8000:8000"
    environment:
      - DJANGO_SECRET_KEY=${DJANGO_SECRET_KEY}
      - DJANGO_DEBUG=False
      - DJANGO_ALLOWED_HOSTS=${DOMAIN_NAME},localhost
      - DJANGO_LOG_LEVEL=WARNING
      - OAUTH_AUTHN_URL=${OAUTH_AUTHN_URL}
      - OAUTH_CLIENT_ID=${OAUTH_CLIENT_ID}
      - OAUTH_CLIENT_SECRET=${OAUTH_CLIENT_SECRET}
      - OAUTH_REDIRECT_URI=/oauth/callback/
    volumes:
      - redis-lens-data:/app/db
      - redis-lens-logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/elb-healthcheck/"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  redis-lens-data:
  redis-lens-logs:
```

## 🌐 Network Configuration

### **Custom Network**

```bash
# Create network
docker network create redis-network

# Run with custom network
docker run -d \
  --network redis-network \
  -p 8000:8000 \
  --name redis-lens \
  harshitgarg02/redis-lens:latest
```

### **Connect to Redis Instances**

```bash
# Run in same network as Redis instances
docker run -d \
  --network redis-network \
  -p 8000:8000 \
  -e DJANGO_ALLOWED_HOSTS=localhost,redis-lens \
  --name redis-lens \
  harshitgarg02/redis-lens:latest
```

## 🔧 Configuration Examples

### **Development Environment**

```bash
docker run -d -p 8000:8000 \
  -e DJANGO_DEBUG=True \
  -e DJANGO_LOG_LEVEL=DEBUG \
  -e DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0 \
  --name redis-lens-dev \
  harshitgarg02/redis-lens:latest
```

### **Production Environment**

```bash
docker run -d -p 8000:8000 \
  -e DJANGO_SECRET_KEY="$(openssl rand -base64 64)" \
  -e DJANGO_DEBUG=False \
  -e DJANGO_ALLOWED_HOSTS=redis-lens.company.com \
  -e DJANGO_LOG_LEVEL=WARNING \
  -v redis-lens-prod-data:/app/db \
  -v redis-lens-prod-logs:/app/logs \
  --restart unless-stopped \
  --name redis-lens-prod \
  harshitgarg02/redis-lens:v1.0.0
```

### **Behind Reverse Proxy**

```bash
# For use with nginx, traefik, etc.
docker run -d \
  -e DJANGO_ALLOWED_HOSTS=redis-lens.company.com \
  -e DJANGO_USE_TZ=True \
  -e DJANGO_TIME_ZONE=America/New_York \
  --network proxy-network \
  --name redis-lens \
  harshitgarg02/redis-lens:latest
```

## 🏥 Health Checks

### **Built-in Health Check**

```bash
# Check application health
curl http://localhost:8000/elb-healthcheck/

# Docker health check
docker run -d -p 8000:8000 \
  --health-cmd="curl -f http://localhost:8000/elb-healthcheck/ || exit 1" \
  --health-interval=30s \
  --health-timeout=10s \
  --health-retries=3 \
  --name redis-lens \
  harshitgarg02/redis-lens:latest
```

### **Version Information**

```bash
# Get version info
curl http://localhost:8000/version/

# Response example:
{
  "version": "1.0.0",
  "version_display": "v1.0.0",
  "application": "RedisLens",
  "build_date": "2024-01-15 14:30:25 UTC"
}
```

## 📊 Monitoring Integration

### **With Prometheus**

```yaml
version: "3.8"
services:
  redis-lens:
    image: harshitgarg02/redis-lens:latest
    ports:
      - "8000:8000"
    environment:
      - DJANGO_LOG_LEVEL=INFO
    labels:
      - "prometheus.io/scrape=true"
      - "prometheus.io/path=/metrics"
      - "prometheus.io/port=8000"
```

### **Log Aggregation**

```bash
# Forward logs to external system
docker run -d -p 8000:8000 \
  --log-driver=gelf \
  --log-opt gelf-address=udp://logstash:12201 \
  --log-opt tag="redis-lens" \
  --name redis-lens \
  harshitgarg02/redis-lens:latest
```

## 🔐 Security Best Practices

### **Secure Configuration**

```bash
# Use secrets for sensitive data
echo "your-secret-key" | docker secret create django_secret -

# Run with secrets
docker service create \
  --name redis-lens \
  --secret django_secret \
  -p 8000:8000 \
  -e DJANGO_SECRET_KEY_FILE=/run/secrets/django_secret \
  harshitgarg02/redis-lens:latest
```

### **Non-root User**

```dockerfile
# Image runs as non-root user by default
USER 1000:1000
```

### **Read-only Operations**

```bash
# RedisLens only performs read-only Redis operations
# No data modification or write commands
# Safe for production Redis instances
```

## 🛠️ Troubleshooting

### **Common Issues**

#### **Permission Errors**

```bash
# Fix file permissions
docker run --rm -v redis-lens-data:/data \
  alpine chown -R 1000:1000 /data
```

#### **Database Issues**

```bash
# Initialize database
docker exec -it redis-lens python manage.py migrate

# Create admin user
docker exec -it redis-lens python manage.py create_admin
```

#### **Network Connectivity**

```bash
# Test Redis connectivity from container
docker exec -it redis-lens redis-cli -h your-redis-host ping
```

### **Debug Mode**

```bash
# Run with debug output
docker run -d -p 8000:8000 \
  -e DJANGO_DEBUG=True \
  -e DJANGO_LOG_LEVEL=DEBUG \
  --name redis-lens-debug \
  harshitgarg02/redis-lens:latest

# View logs
docker logs -f redis-lens-debug
```

### **Shell Access**

```bash
# Access container shell
docker exec -it redis-lens /bin/bash

# Run management commands
docker exec -it redis-lens python manage.py --help
```

## 📚 Additional Resources

- **GitHub Repository**: [https://github.com/username/redis-lens](https://github.com/username/redis-lens)
- **Documentation**: Comprehensive guides in the repository
- **Issue Tracker**: Report bugs and feature requests
- **Docker Hub**: [https://hub.docker.com/r/harshitgarg02/redis-lens](https://hub.docker.com/r/harshitgarg02/redis-lens)

## 🏷️ Image Information

- **Base Image**: Python 3.11 Alpine
- **Architecture**: AMD64, ARM64
- **Exposed Port**: 8000
- **Working Directory**: `/app`
- **User**: Non-root (UID 1000)
- **Build Frequency**: Automated on every release

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Need help?** Open an issue on GitHub or check the troubleshooting section above.

**Found a bug?** Please report it with your Docker configuration and logs.

**Want to contribute?** Pull requests are welcome!
