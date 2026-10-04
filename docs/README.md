# Upstream Healer API Documentation

## Overview

This directory contains comprehensive API documentation and test cases for the Upstream Healer application.

## Documentation Structure

- `api_documentation.rst` - Complete REST API specification
- `test_api_endpoints.py` - Unit tests for all API endpoints

## How to Use This Documentation

### Reading the API Specification

The main API documentation is in `api_documentation.rst`. It provides:

1. **Endpoint descriptions** with HTTP methods and URLs
2. **Request/response examples** in JSON format
3. **Parameter specifications** 
4. **Error handling** information
5. **Test coverage** details

### Running Tests

To run the API tests:

```bash
cd /mnt/Aquaman/upstream-healer
python -m pytest tests/test_api_endpoints.py -v
```

### Test Coverage

The test suite validates:
- HTTP status codes (200, 404, etc.)
- Response structure and data types
- Parameter validation where applicable
- Error handling scenarios
- Basic functionality of all endpoints

## Contributing Documentation Updates

When adding or modifying API endpoints:

1. Update the `api_documentation.rst` file with new endpoints
2. Add corresponding test cases in `test_api_endpoints.py`
3. Run tests to ensure no regressions
4. Verify that all documented endpoints are covered by tests

## Versioning

API documentation follows semantic versioning:
- Major versions: Breaking changes
- Minor versions: New features
- Patch versions: Bug fixes and documentation updates

## Support

For questions about the API or documentation, please refer to the main project README or file an issue in the repository.