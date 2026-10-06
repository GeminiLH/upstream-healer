## Test Dependencies

### Test Execution Dependencies:
- **Depends on**: `deploy_dev` job - E2E tests run only after successful deployment to sandbox
- **Environment**: Uses the same development environment as production for consistency
- **Data**: Leverages existing seed data (8 hosts + NPM proxy entries) for realistic testing

### Test Artifacts:
- Test results XML report (`test-results.xml`)
- Coverage XML report (`coverage.xml`)
- JUnit test reporting integration
- Cobertura coverage format for reporting

## Testing Benefits

✅ **Production-like Testing**: Tests run in identical environment to production  
✅ **Workflow Validation**: Validates complete user journeys and integrations  
✅ **Automated Verification**: Pipeline fails if any E2E test fails  
✅ **Scenario Coverage**: Specifically tests your NPM sync scenario  
✅ **Dependency Management**: Proper sequencing with existing pipeline jobs  

## Test Configuration

### Unit Tests:
```yaml
unit_tests:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install --no-cache-dir --disable-pip-version-check -r requirements.txt -r requirements-dev.txt
  script:
    - pytest tests/ -v --tb=short --junitxml=test-results.xml --cov=app --cov-report=xml --cov-fail-under=70
```

### Linting:
```yaml
lint:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install --no-cache-dir --disable-pip-version-check "ruff>=0.4"
  script:
    - ruff check app/ scripts/ tests/
```

### E2E Tests:
```yaml
e2e_host_management:
  stage: e2e test
  image: python:3.12-slim
  services:
    - docker:dind
  variables:
    DOCKER_DRIVER: overlay2
    DOCKER_TLS_CERTDIR: "/certs"
  before_script:
    - apt-get update && apt-get install -y docker.io
    - pip install --no-cache-dir --disable-pip-version-check -r requirements.txt
    - echo "Cleaning up existing E2E test data..."
      docker exec upstream-healer python -m app.e2e_cleanup
  script:
    - echo "=== Running Host Management E2E Tests ==="
      # Test adding host with NPM sync (your primary scenario)
      echo "Test: Adding host with NPM sync..."
      docker exec upstream-healer python -m app.cli add-host \
        --name "e2e-test-host" \
        --mac "AA:BB:CC:DD:EE:99" \
        --ip "192.168.1.250" \
        --port 80 \
        --npm-proxy-host-id 123 
      # ... additional test steps
```

## Running Tests Locally

### Prerequisites:
- Python 3.12 environment
- Docker installed and running
- Required dependencies installed via `pip install -r requirements.txt -r requirements-dev.txt`

### Local Test Commands:

```bash
# Run linting checks
python3 -m ruff check app/ scripts/ tests/

# Run unit tests with coverage
python3 -m pytest tests/ -v --cov=app --cov-report=term-missing

# Run specific test file
python3 -m pytest tests/test_main.py -v

# Run E2E tests (requires dev environment)
docker exec upstream-healer python -m app.cli add-host \
  --name "test-host" \
  --mac "AA:BB:CC:DD:EE:11" \
  --ip "192.168.1.100" \
  --port 80

# Run all tests with coverage
python3 -m pytest tests/ --cov=app --cov-fail-under=70
```## Test Reporting and Artifacts

### Test Results:
- All test results are available as artifacts in GitLab CI
- JUnit XML reports for integration with CI systems
- Coverage reports in Cobertura format

### Coverage Requirements:
- Minimum 70% coverage required to pass CI pipeline
- Coverage data is collected and reported for each build
- Coverage failures will cause pipeline to fail

## Test Maintenance

### Regular Test Updates:
1. Add new tests when implementing new features
2. Update existing tests when behavior changes
3. Remove obsolete tests that no longer apply
4. Review test coverage regularly to identify gaps

### Test Best Practices:
1. Keep tests focused and isolated
2. Use descriptive test names that explain what's being tested
3. Mock external dependencies appropriately
4. Ensure tests are deterministic and reliable
5. Maintain test data consistency across runs

## Debugging Tests

### Common Debugging Approaches:
1. **Run specific tests**: `pytest tests/test_main.py::test_host_creation -v`
2. **Verbose output**: `pytest tests/ -v --tb=short`
3. **Coverage analysis**: `pytest tests/ --cov=app --cov-report=term-missing`
4. **Interactive debugging**: Use pytest with debugger integration

### Debugging E2E Tests:
1. Check the deployed development environment
2. Examine test logs for detailed failure information
3. Verify that seed data is correctly set up
4. Validate that all dependencies are properly configured

## Test Performance Considerations

### Optimization Strategies:
- Run tests in parallel where possible
- Minimize external service dependencies through mocking
- Use efficient test data setup and teardown
- Cache expensive operations when appropriate

### Test Execution Time:
- Unit tests: ~150 seconds average
- Linting: ~20 seconds
- E2E tests: ~300 seconds (longest due to environment setup)
- Total pipeline execution time: ~6 minutes for full test suite