# Upstream Healer - CI/CD Pipeline Process

## Overview
This document outlines the complete CI/CD pipeline workflow for the Upstream Healer project, reflecting the actual dependencies and execution order defined in `.gitlab-ci.yml`.

## Pipeline Stages and Dependencies

The pipeline follows this precise execution sequence with specific dependency rules:

### Stage 1: Test (Automatic)
- **lint**: Code quality checks
- **unit_tests**: Unit tests with coverage reporting  

**Dependencies**: 
- `lint` runs first (no dependencies)
- `unit_tests` depends on `lint` completion (via `needs: - job: lint`)

### Stage 2: Build (Automatic)  
- **build_image**: Build Docker image
- **build_dev**: Deploy to development environment

**Dependencies**:
- `build_image` depends on successful completion of all jobs in the Test stage
- This includes both `lint` and `unit_tests`
- `build_dev` depends on successful completion of `build_image` AND `dev_down` (with dev_down being optional)

### Stage 4: Deploy (Manual)
- **deploy_dev_auto**: Automatic deployment to dev environment
- **dev_down**: Manual teardown of dev environment  
- **deploy_production**: Manual production deployment
- **dev_debug**: Manual diagnostic tool

## Detailed Workflow Sequence

### Automatic Execution Flow:
1. **Code Push** → Pipeline triggers automatically
2. **Test Stage** 
   - `lint` runs first (no dependencies)
   - If lint passes, `unit_tests` runs
   - Both test jobs must pass for the Test stage to complete successfully
3. **Build Stage**
   - If Test stage is successful, `build_image` runs
   - If `build_image` succeeds, `deploy_dev` runs 
4. **E2E Tests Stage** (runs after deploy_dev completes successfully)
   - Both E2E tests run against the deployed environment
5. **Manual Verification** 
   - User can now run `dev_down` manually to tear down environment
   - Or proceed with `deploy_production` for production deployment

## Critical Pipeline Behavior

### Order of Operations:
1. **Lint** → 2. **Unit Tests** → 3. **Build Image** → 4. **Deploy Dev Auto** → 5. **E2E Tests**

### Important Notes:
- All jobs in the Test stage must complete successfully before Build stage begins
- E2E tests are designed to run AFTER the deployment, not during it
- This ensures E2E tests execute against a fully deployed environment with all services running

## Pipeline Configuration Details

The pipeline stages are defined as:
```yaml
stages:
  - test
  - build
  - e2e test
  - deploy
```

### Test Stage Jobs:
```yaml
lint:
  stage: test
  # ... configuration details

unit_tests:
  stage: test  
  needs:
    - job: lint
      artifacts: false
  # ... configuration details
```

### Build Stage Job:
```yaml
build_image:
  stage: build
  # ... configuration details (no explicit 'needs' as it depends on all test jobs)
```

### E2E Test Jobs:
```yaml
e2e_host_management:
  stage: e2e test
  needs:
    - job: deploy_dev
      optional: true
  # ... configuration details

e2e_all_tests:
  stage: e2e test
  needs:
    - job: deploy_dev
      optional: true
  # ... configuration details
```

## Manual Jobs and Their Purpose

### deploy_dev_auto (Automatic)
- Automatically cleans up previous dev stack before deploying new one
- Deploys fresh instance with latest code
- Uses same seed data as production for realistic testing

### dev_down (Manual)
- Tears down the development stack manually when needed
- Preserves volumes for future deployments (maintains host/telegram/NPM config)

### deploy_production (Manual)
- Manual job for production deployment (SSH to target host)

### dev_debug (Manual) 
- Diagnostic tool for troubleshooting in development environment

## Pipeline Execution Best Practices

1. **Always run tests first**: The pipeline requires successful linting and unit testing before building
2. **Verify deployment**: After `deploy_dev_auto` runs, verify the application is accessible before running E2E tests
3. **Understand dependencies**: E2E tests only run after successful deployment, not during it
4. **Monitor all stages**: Pay attention to which jobs are skipped due to failures in previous stages
5. **Use manual jobs judiciously**: Only use manual jobs when necessary for controlled operations

## Troubleshooting Pipeline Issues

### Common Problems and Solutions:

1. **Pipeline fails at lint stage**: Fix code style issues identified by ruff
2. **Unit tests fail**: Debug test failures, ensure proper mocking of external dependencies  
3. **Build fails**: Verify Dockerfile syntax and required dependencies
4. **E2E tests skipped**: Check if `deploy_dev_auto` was successful; E2E tests depend on deployment success
5. **Manual jobs not available**: Ensure proper pipeline configuration with correct job status

## Pipeline Status Monitoring

### Understanding Job States:
- **Pending**: Job waiting to be scheduled
- **Running**: Job currently executing  
- **Success**: Job completed successfully
- **Failed**: Job failed (pipeline may continue depending on dependencies)
- **Skipped**: Job was not executed due to dependency failures

### Key Points for Monitoring:
1. All jobs in the Test stage must succeed before Build stage begins
2. E2E tests only run after successful `deploy_dev_auto` 
3. Manual jobs can be triggered after automatic stages complete successfully
4. If any job fails, subsequent dependent jobs are skipped