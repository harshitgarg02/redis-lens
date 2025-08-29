# Use Python 3.11 slim image
FROM python:3.11-slim

# Build arguments for versioning
ARG BUILD_DATE
ARG BUILD_COMMIT
ARG BUILD_BRANCH=master
ARG APP_VERSION

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set build information as environment variables
ENV BUILD_DATE=${BUILD_DATE}
ENV BUILD_COMMIT=${BUILD_COMMIT}
ENV BUILD_BRANCH=${BUILD_BRANCH}
ENV APP_VERSION=${APP_VERSION}

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-client \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . /app/

# Create logs directory
RUN mkdir -p /app/logs

# Collect static files
RUN python manage.py migrate --noinput && \
    python manage.py import_anomaly_rules && \
    python manage.py collectstatic --noinput

# Create a non-root user
RUN adduser --disabled-password --gecos '' appuser
RUN chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Run the application
CMD ["gunicorn", "--config", "gunicorn.conf.py", "redislens.wsgi:application"]
