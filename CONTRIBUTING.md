# Contributing to RedisLens

Thank you for your interest in contributing to RedisLens! This document provides guidelines and information for contributors.

## 🚀 Getting Started

### Prerequisites

- Python 3.9 or higher
- Node.js (for frontend development, if needed)
- Git
- PostgreSQL (optional, SQLite works for development)

### Development Setup

1. **Fork and Clone**

   ```bash
   git clone https://github.com/yourusername/redislens.git
   cd redislens
   ```

2. **Set up Virtual Environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment**

   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

5. **Set up Database**

   ```bash
   python manage.py migrate
   python manage.py import_anomaly_rules
   python manage.py create_admin
   ```

6. **Run Development Server**
   ```bash
   python manage.py runserver
   ```

### Docker Development

For a quick development setup with Docker:

```bash
docker-compose up -d
```

## 📋 How to Contribute

### Reporting Issues

- Use the [GitHub Issues](https://github.com/yourusername/redislens/issues) tracker
- Search existing issues before creating a new one
- Provide detailed information:
  - Steps to reproduce
  - Expected vs actual behavior
  - Environment details (OS, Python version, etc.)
  - Screenshots if relevant

### Suggesting Features

- Open a GitHub Issue with the label "enhancement"
- Clearly describe the feature and its benefits
- Include examples or mockups if possible

### Code Contributions

1. **Create a Branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**

   - Follow the coding standards (see below)
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**

   ```bash
   python manage.py test
   ```

4. **Commit Your Changes**

   ```bash
   git add .
   git commit -m "feat: add new anomaly detection rule for memory optimization"
   ```

5. **Push and Create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then create a Pull Request on GitHub.

## 📝 Coding Standards

### Python Code Style

- Follow [PEP 8](https://pep8.org/) style guide
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Maximum line length: 88 characters (Black formatter standard)

### Commit Message Format

Use [Conventional Commits](https://conventionalcommits.org/) format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or modifying tests
- `chore`: Maintenance tasks

Examples:

```
feat(anomaly): add new CPU usage detection rule
fix(dashboard): resolve memory leak in instance list
docs: update installation instructions
```

### Code Structure

- **Models**: Keep in `analyzer/models.py` or split into logical modules
- **Views**: Organize by functionality, use class-based views where appropriate
- **Templates**: Follow Django template naming conventions
- **Static Files**: Organize CSS, JS, and images logically
- **Tests**: Write tests for all new functionality

## 🧪 Testing

### Running Tests

```bash
# Run all tests
python manage.py test

# Run specific test module
python manage.py test analyzer.tests

# Run with coverage
coverage run --source='.' manage.py test
coverage report
coverage html
```

### Writing Tests

- Write unit tests for models and utility functions
- Write integration tests for views and complex workflows
- Mock external dependencies (Redis connections, etc.)
- Test both success and failure scenarios

### Test Structure

```python
from django.test import TestCase
from analyzer.models import RedisInstance

class RedisInstanceTestCase(TestCase):
    def setUp(self):
        self.instance = RedisInstance.objects.create(
            ip_address='127.0.0.1',
            port=6379,
            role='master'
        )

    def test_hit_ratio_calculation(self):
        # Test implementation
        pass
```

## 📚 Documentation

### Code Documentation

- Add docstrings to all public functions and classes
- Include parameter descriptions and return values
- Use type hints where applicable

```python
def analyze_redis_instance(host: str, port: int, password: str = None) -> Dict[str, Any]:
    """
    Analyze a Redis instance and return configuration data.

    Args:
        host: Redis server hostname or IP
        port: Redis server port
        password: Optional Redis password

    Returns:
        Dictionary containing instance analysis results

    Raises:
        ConnectionError: If unable to connect to Redis instance
    """
```

### README Updates

- Keep README.md up to date with new features
- Update installation instructions if needed
- Add examples for new functionality

## 🔧 Adding New Features

### Anomaly Detection Rules

To add a new anomaly detection rule:

1. **Update CSV File**: Add rule to the anomaly rules CSV
2. **Implement Logic**: Add detection logic in `anomaly_detector.py`
3. **Add Tests**: Write tests for the new rule
4. **Update Documentation**: Document the new rule

### New Analysis Types

For new types of analysis (beyond Redis and Sentinel):

1. **Create Service Module**: Add new service in `analyzer/`
2. **Add Models**: Define database models for new data types
3. **Create Views**: Implement analysis views and templates
4. **Add Navigation**: Update base template with new options
5. **Write Tests**: Comprehensive test coverage

## 🔐 Security Considerations

- Never commit sensitive data (passwords, API keys, etc.)
- Use environment variables for configuration
- Validate all user inputs
- Follow Django security best practices
- Run security checks: `python manage.py check --deploy`

## 📋 Pull Request Guidelines

### Before Submitting

- [ ] Code follows project style guidelines
- [ ] Tests pass locally
- [ ] New functionality has tests
- [ ] Documentation is updated
- [ ] Commit messages follow convention
- [ ] No sensitive data in code

### PR Description Template

```markdown
## Description

Brief description of changes

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing

- [ ] Tests pass
- [ ] New tests added
- [ ] Manual testing completed

## Checklist

- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Changelog updated (if applicable)
```

## 🎯 Development Priorities

Current areas where contributions are most welcome:

1. **Anomaly Detection Rules**: New detection rules for Redis configurations
2. **Performance Optimization**: Improve analysis speed for large deployments
3. **UI/UX Improvements**: Better visualization and user experience
4. **Export Formats**: Additional export formats (PDF, Excel, etc.)
5. **Integration**: APIs for external system integration
6. **Testing**: Increase test coverage
7. **Documentation**: Examples, tutorials, and guides

## 📞 Getting Help

- **GitHub Discussions**: For questions and community discussions
- **GitHub Issues**: For bug reports and feature requests
- **Documentation**: Check the README and inline documentation

## 📜 Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect differing viewpoints
- Show empathy towards community members

Thank you for contributing to RedisLens! 🎉
