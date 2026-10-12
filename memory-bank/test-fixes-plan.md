# Test Fix Plan for Upstream Healer

## Category 1: Wrong URL Paths

### tests/test_api_endpoints.py

| Line | Change |
|------|--------|
| 85 | `client.get("/add-host")` → `client.get("/hosts/add")` |
| 61 | `client.post("/settings/subnets")` → `client.post("/settings/subnets/add")` |

### tests/test_e2e_notifications.py

| Test | Change |
|------|--------|
| `test_notification_add_form_renders` (lines 17-23) | Remove the `GET /notifications/add/telegram` and `GET /notifications/add/email` assertions — these endpoints don't exist. Replace with just verifying the main page renders. |
| `test_telegram_notification_add_and_view` (lines 32, 37) | `GET /notifications/add/telegram` → remove; `POST /notifications/add/telegram` → `POST /notifications/channel/telegram` |
| `test_email_notification_add_and_view` (lines 58, 63) | `GET /notifications/add/email` → remove; `POST /notifications/add/email` → `POST /notifications/channel/email` |

### tests/test_e2e_subnet_management.py

| Line | Change |
|------|--------|
| 34 | `POST /settings/subnets` → `POST /settings/subnets/add` |
| 56 | `POST /settings/subnets/1/toggle` → `POST /subnets/1/toggle` | - do not do this one
| 65 | `POST /settings/subnets/1/delete` → `POST /subnets/1/delete` | - do not do this one

### tests/test_e2e_error_conditions.py

| Line | Change |
|------|--------|
| 69 | `POST /hosts/add` → `POST /hosts/validate` | - do not do this one

## Category 3: Wrong Form Field Names

### tests/test_e2e_notifications.py

| Test | Wrong Fields | Correct Fields (from notifications.py) |
|------|-------------|----------------------------------------|
| `test_telegram_notification_add_and_view` (line 38-40) | `bot_token`, `chat_id` | `name`, `token`, `chat_ids` |

### tests/test_e2e_subnet_management.py

| Line | Wrong Field | Correct Field |
|------|------------|---------------|
| 86 | `subnet_id` | `cidr` (settings.py:167) |

## Category 2: Endpoints that Don't Exist (Potential Removals) - do not do this category as i need to determine if the route needs to be implemented

The following tests reference endpoints that do not exist in the current router implementation:

### tests/test_api_endpoints.py
- `test_get_diagnostic_scan_by_mac` - No GET endpoint at `/api/diagnostic/scan/{mac}`
- `test_get_diagnostic_scan_by_mac_port` - No GET endpoint at `/api/diagnostic/scan/{mac}/{port}`  
- `test_get_diagnostic_debug` - No GET endpoint at `/api/diagnostic/debug`

### tests/test_e2e_host_management.py
- `test_host_bulk_operations` - No POST endpoints at `/hosts/bulk-delete`, `/hosts/bulk-toggle`
- `test_host_search_and_filter` - No GET endpoint at `/hosts/search`
- `test_host_import_from_file` - No GET endpoint at `/hosts/import`

### tests/test_e2e_notifications.py
- `test_notification_channel_edit_form` - No GET endpoint at `/notifications/channel/1/edit`
- `test_notification_channel_edit_form_submission` - No GET endpoint at `/notifications/channel/1/edit`
- `test_notification_rule_edit_form` - No GET endpoint at `/notifications/rule/1/unreachable/edit`

### tests/test_e2e_subnet_management.py
- `test_subnet_bulk_operations` - No POST endpoints at `/settings/subnets/bulk-delete`, `/settings/subnets/bulk-toggle`
- `test_subnet_validation_scenarios` - No POST endpoint at `/settings/subnets/validate`
- `test_subnet_reordering` - No POST endpoint at `/settings/subnets/reorder`
- `test_configuration_backup_restore` - No GET endpoint at `/settings/backup`, no POST endpoint at `/settings/restore`
- `test_environment_variable_override` - No GET endpoint at `/settings/env`
- `test_subnet_edit_form` - No GET endpoint at `/settings/subnets/1/edit`
- `test_subnet_edit_form_submission` - No GET endpoint at `/settings/subnets/1/edit`

These may be candidates for removal if they are not critical to the core functionality being tested.