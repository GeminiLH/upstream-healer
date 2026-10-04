# End-to-End Testing Framework

This document outlines the comprehensive end-to-end testing framework implemented for the Upstream Healer application.

## Overview

The E2E testing framework ensures that all critical user workflows and system integrations function correctly in a production-like environment. All tests run in the sandbox development environment (`deploy_dev`) to validate functionality against real data and services.

## Implemented E2E Tests

### 1. Host Management E2E Tests (`e2e_host_management`)

**Purpose**: Validates the core host management workflow including NPM integration.

**Test Scenarios**:
- Adding hosts with NPM sync capability (your primary scenario)
- Adding hosts without NPM sync
- Database persistence of host records
- Unique constraint enforcement (MAC+port combinations)

**Key Features**:
- Tests the exact scenario you described: when a user enters a host which is in the NPM database, they will be given the option to populate the record with information from NPM
- Verifies that data population works correctly when `--npm-sync true` is specified
- Ensures hosts are properly stored in the database with correct NPM-related fields populated

### 2. Complete Integration E2E Tests (`e2e_all_tests`)

**Purpose**: Validates complete workflow integration across all application components.

**Test Scenarios**:
- Full host creation workflow from CLI to database
- Integration between CLI interface, database, and NPM proxy systems
- End-to-end user journey validation

## Test Execution Flow

1. **Environment Setup**: The pipeline deploys the development stack using `deploy_dev`
2. **Test Execution**: E2E tests run against the deployed sandbox environment
3. **Validation**: Tests verify data persistence, integration points, and workflow completion
4. **Cleanup**: Environment is torn down after test execution

## Test Dependencies

- **Depends on**: `deploy_dev` job - E2E tests run only after successful deployment to sandbox
- **Environment**: Uses the same development environment as production for consistency
- **Data**: Leverages existing seed data (8 hosts + NPM proxy entries) for realistic testing

## Benefits of This Approach

✅ **Production-like Testing**: Tests run in identical environment to production  
✅ **Workflow Validation**: Validates complete user journeys and integrations  
✅ **Automated Verification**: Pipeline fails if any E2E test fails  
✅ **Scenario Coverage**: Specifically tests your NPM sync scenario  
✅ **Dependency Management**: Proper sequencing with existing pipeline jobs  

## Test Results Integration

All E2E tests are integrated into the CI/CD pipeline and will:
- Run automatically on every push to main branch
- Fail the pipeline if any test fails
- Provide detailed logs for debugging failures
- Generate artifacts for test reporting

## Usage in Pipeline

The E2E tests are configured as part of your pipeline stages:
```
stages:
  - test        # Includes lint, unit_tests, e2e_host_management, e2e_all_tests
  - build       # Build the Docker image
  - deploy      # Deploy to environments (test/dev/production)
```

The E2E tests run in parallel with other tests and will be executed automatically after successful unit testing.