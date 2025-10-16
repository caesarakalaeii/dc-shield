# 🧪 DC-Shield Test Suite

## Overview

Comprehensive test suite implemented to prevent deployment failures and ensure code quality before Docker image builds.

## ✅ Test Coverage

### Unit Tests
- **device_tracker.py**: 98% coverage (17 tests)
  - Fingerprint generation and consistency
  - Device recognition and identity tracking
  - Visit history and statistics
  - Data persistence and sanitization

- **surveillance_embeds.py**: 82% coverage (42 tests)
  - Discord embed generation
  - Threat level indicators
  - Security lessons
  - Device recognition displays
  - Educational content

### Smoke Tests
- **test_smoke.py**: 15 critical tests
  - Module imports
  - Core functionality
  - Configuration validation
  - Error handling
  - Data validation

### Total Results
- **74 passing tests**
- **35% overall code coverage** (focusing on critical modules)
- **~0.5 second execution time**

## 🚀 Running Tests

### Run All Tests (Default)
```bash
pytest
```
This runs all unit and smoke tests, skipping integration tests by default.

### Run Specific Test Files
```bash
# Device tracker tests only
pytest tests/test_device_tracker.py

# Surveillance embeds tests only
pytest tests/test_surveillance_embeds.py

# Smoke tests only
pytest tests/test_smoke.py
```

### Run With Coverage Report
```bash
pytest --cov=. --cov-report=html
```
Open `htmlcov/index.html` to view detailed coverage report.

### Run Integration Tests (Requires Full Setup)
```bash
pytest -m integration
```
Note: Integration tests are skipped by default as they require full application initialization.

### Run Tests With Verbose Output
```bash
pytest -v
```

## 📁 Test Structure

```
tests/
├── __init__.py                    # Test package init
├── conftest.py                    # Shared fixtures and configuration
├── test_device_tracker.py         # Device tracking unit tests (17 tests)
├── test_surveillance_embeds.py    # Discord embed unit tests (42 tests)
├── test_smoke.py                  # Critical smoke tests (15 tests)
└── test_main.py                   # Integration tests (23 tests, skipped by default)
```

## ⚙️ Configuration Files

### pytest.ini
Main pytest configuration:
- Test discovery patterns
- Default options (verbose, coverage)
- Marker definitions
- Skips integration tests by default

### .coveragerc
Coverage configuration:
- Excludes tests/ and venv/ from coverage
- Defines coverage report options

### .flake8
Linting configuration:
- Line length limits
- Ignored rules
- File exclusions

## 🔄 CI/CD Integration

### GitHub Actions Workflow

The CI/CD pipeline now includes automated testing **before** Docker build:

```yaml
jobs:
  test:
    - Install Python dependencies
    - Run Black formatting check
    - Run flake8 linting
    - Run pytest with coverage
    - Upload coverage reports

  publish:
    needs: test  # Only runs if tests pass
    - Build Docker image
    - Push to GHCR
```

### What This Prevents

✅ **Syntax errors** - Caught by import tests
✅ **Logic errors** - Caught by unit tests
✅ **Regressions** - Caught by comprehensive test suite
✅ **Breaking changes** - Tests must pass before deployment
✅ **Code quality issues** - Caught by linting

### Deployment Protection

- **Tests MUST pass** before Docker image is built
- **Linting failures** are logged but don't block (continue-on-error)
- **Coverage reports** are uploaded to Codecov (if configured)

## 📊 Test Markers

Tests are organized using pytest markers:

- `@pytest.mark.unit` - Fast unit tests (default)
- `@pytest.mark.integration` - Requires full app setup (skipped by default)
- `@pytest.mark.slow` - Long-running tests

## 🛠️ Development Workflow

### Before Committing
```bash
# Run tests
pytest

# Check formatting
black --check .

# Run linting
flake8 .
```

### After Pushing to Main
- GitHub Actions automatically runs full test suite
- Build only proceeds if all tests pass
- Check Actions tab for detailed results

## 🧰 Test Dependencies

Added to `requirements.txt`:

```
pytest>=7.4.0              # Test framework
pytest-asyncio>=0.21.0     # Async test support
pytest-cov>=4.1.0          # Coverage reporting
pytest-mock>=3.11.1        # Mocking utilities
httpx>=0.24.1              # HTTP client for testing

black>=23.7.0              # Code formatter
flake8>=6.1.0              # Linting
mypy>=1.5.0                # Type checking
```

## 📈 Coverage Goals

### Current Coverage
- `device_tracker.py`: **98%** ✅
- `surveillance_embeds.py`: **82%** ✅
- Overall project: **35%**

### Priority Modules (Well Tested)
- Device tracking logic
- Discord embed generation
- Fingerprinting algorithms
- Data sanitization

### Lower Priority (Not Tested)
- `main.py` - Complex web app (integration tests skipped)
- `ip_locator.py` - External API calls
- `logger.py` - Utility module
- `json_handler.py` - Simple file I/O

## 🐛 Debugging Failed Tests

### View Full Error Output
```bash
pytest -v --tb=long
```

### Run Single Test
```bash
pytest tests/test_device_tracker.py::TestDeviceTracker::test_initialization -v
```

### Debug With Print Statements
```bash
pytest -s  # Don't capture stdout
```

### Check Coverage for Specific Module
```bash
pytest --cov=device_tracker --cov-report=term-missing
```

## ✨ Key Features

### Automatic Test Discovery
- Pytest automatically finds all `test_*.py` files
- No manual test registration needed

### Shared Fixtures
- Common test data defined in `conftest.py`
- Reusable across all test files
- Includes sample device info, advanced data, mocks

### Fast Execution
- Unit tests run in ~0.5 seconds
- Integration tests skipped by default
- Parallel execution possible with `pytest-xdist`

### Comprehensive Assertions
- Tests verify exact behavior
- Edge cases covered (empty data, malformed input)
- Error handling validated

## 🔒 Educational Use

Like the main project, this test suite demonstrates:

### Security Testing Best Practices
- Input validation testing
- Data sanitization verification
- Error handling coverage
- Edge case testing

### CI/CD Security
- Automated testing prevents vulnerabilities
- Code quality gates
- Coverage requirements
- Linting standards

## 📚 Further Reading

- [Pytest Documentation](https://docs.pytest.org/)
- [Testing Best Practices](https://docs.pytest.org/en/stable/goodpractices.html)
- [Python Testing Tutorial](https://realpython.com/pytest-python-testing/)
- [CI/CD Testing Strategies](https://www.atlassian.com/continuous-delivery/software-testing/types-of-software-testing)

---

**Version**: 1.0
**Last Updated**: 2025-10-16
**Test Suite Status**: ✅ All Critical Tests Passing
