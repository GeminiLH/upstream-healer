# Upstream Healer CI/CD Pipeline Workflow

This document outlines the complete pipeline workflow that ensures proper sequential execution with automatic deployment and testing.

## Pipeline Stages

The pipeline follows this execution sequence:

1. **Test Stage** (Automatic)
   - `lint`: Code quality checks
   - `unit_tests`: Unit tests with coverage reporting  
   - `e2e_host_management`: Host management E2E tests
   - `e2e_all_tests`: Complete integration E2E tests

2. **Build Stage** (Automatic)
   - `build_image`: Build Docker image

3. **Deploy Stage** (Automatic + Manual)
   - `deploy_dev_auto`: Automatic deployment to dev environment
   - `dev_down`: Manual teardown of dev environment  
   - `deploy_production`: Manual production deployment
   - `dev_debug`: Manual diagnostic tool

## Workflow Sequence

### Automatic Execution Flow:
1. **Code Push** → Pipeline triggers automatically
2. **Test Stage** 
   - Linting and unit tests run
   - All E2E tests execute in sandbox environment
3. **Build Stage**
   - Docker image is built
4. **Deploy Stage**
   - `deploy_dev_auto` runs automatically (cleans up old stack, deploys new)
   - Environment is ready for manual verification
5. **Manual Verification** 
   - User can now run `dev_down` manually to tear down environment
   - Or proceed with `deploy_production` for production deployment

## Key Improvements

### 1. Automated Deployment Process
- **`deploy_dev_auto`** now runs automatically (`when: always`) instead of manually
- Automatically cleans up previous dev stack before deploying new one
- Ensures latest code is always deployed to sandbox environment

### 2. Proper Sequential Flow  
- **`dev_down`** remains manual as intended for controlled cleanup
- **`deploy_dev_auto`** runs after all tests and builds complete
- **All automatic jobs** depend on successful completion of previous stages

### 3. E2E Test Integration
- All E2E tests run in the same environment where final deployment occurs
- Tests validate that the exact scenario you described works correctly:
  - Adding hosts with NPM sync capability  
  - Verifying data population from NPM when `--npm-sync true` is specified

## Pipeline Dependencies

### Test Stage Depends On:
- Unit tests passing (383 tests, 70% coverage minimum)
- All E2E tests passing
- Linting successful

### Build Stage Depends On:
- Test stage completion (all tests pass)

### Deploy Stage Depends On:
- Build stage completion  
- All previous stages successful

## Environment Management

### Automatic Deployment (`deploy_dev_auto`):
- Cleans up existing dev stack before deployment
- Deploys fresh instance with latest code
- Uses same seed data as production for realistic testing
- Ensures the environment always has the latest version

### Manual Cleanup (`dev_down`):
- Tears down the development stack manually when needed
- Preserves volumes for future deployments (maintains host/telegram/NPM config)
- Allows for controlled environment management

## Verification Process

After pipeline completion:
1. **Environment Ready**: The dev environment is running with latest code
2. **E2E Tests Passed**: All integration tests validated functionality  
3. **Manual Options Available**:
   - Run `dev_down` to tear down the environment
   - Proceed to production deployment if needed
   - Debug using `dev_debug` job

This workflow ensures that:
✅ The latest code is always deployed to the dev environment  
✅ All functionality is tested end-to-end before deployment  
✅ Environment management is controlled and predictable  
✅ Your specific NPM sync scenario is validated automatically  
✅ Manual jobs remain available for operator control