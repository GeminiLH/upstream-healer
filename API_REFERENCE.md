### NPM Integration Endpoints

#### GET /api/npm/hosts
- **Method**: GET
- **Authentication**: None
- **Description**: List available NPM proxy hosts
- **Response**: Array of NPM host objects

#### GET /api/npm/hosts/{host_id}
- **Method**: GET
- **Authentication**: None
- **Description**: Get specific NPM proxy host details
- **Response**: NPM host object

### Notification Endpoints

#### GET /api/notifications/channels
- **Method**: GET
- **Authentication**: None
- **Description**: List notification channels
- **Response**: Array of channel objects

#### POST /api/notifications/channels
- **Method**: POST
- **Authentication**: None
- **Description**: Create new notification channel
- **Request Body**:
```json
{
  "type": "string",
  "name": "string",
  "config": "object"
}
```
- **Response**: Channel object with created ID

### Event Endpoints

#### GET /api/events
- **Method**: GET
- **Authentication**: None
- **Description**: List events
- **Query Parameters**:
  - `host_id` (integer): Filter by host
  - `limit` (integer): Limit results
  - `days` (integer): Days back to look
- **Response**: Array of event objects

#### GET /api/events/{event_id}
- **Method**: GET
- **Authentication**: None
- **Description**: Get specific event details
- **Response**: Event object

### Settings Endpoints

#### GET /api/settings
- **Method**: GET
- **Authentication**: None
- **Description**: Get application settings
- **Response**: Settings object

#### PUT /api/settings
- **Method**: PUT
- **Authentication**: None
- **Description**: Update application settings
- **Request Body**: Settings object
- **Response**: Updated settings object## HTML Routes (Web UI)

### GET /
- **Method**: GET
- **Response Type**: HTML
- **Description**: Main dashboard page showing monitored hosts and status

### GET /hosts/{host_id}/edit
- **Method**: GET
- **Response Type**: HTML
- **Description**: Host edit form

### GET /notifications
- **Method**: GET
- **Response Type**: HTML
- **Description**: Notifications configuration page

### GET /settings
- **Method**: GET
- **Response Type**: HTML
- **Description**: Application settings page

### GET /diagnostic
- **Method**: GET
- **Response Type**: HTML
- **Description**: Diagnostic tools and scan interface

## Error Responses

All API endpoints may return standard HTTP error codes:
- **400 Bad Request**: Invalid request parameters or body
- **404 Not Found**: Resource not found
- **500 Internal Server Error**: Server-side errors

Common error response format:
```json
{
  "error": "string",
  "message": "string"
}
```

## Authentication and Security

The API currently uses no authentication for endpoints, as designed for the specific use case. All data is stored in a local SQLite database within a Docker volume.

## Rate Limiting

No rate limiting is implemented at this time. The application is designed to run in controlled environments where API access is restricted by network configuration.

## Versioning

API versioning is not currently implemented. Future versions may introduce a version prefix in endpoint paths.

## Examples

### Add a new host via API:
```bash
curl -X POST http://localhost:8787/api/hosts \
  -H "Content-Type: application/json" \
  -d '{
    "name": "vault",
    "mac": "AA:BB:CC:DD:EE:11",
    "ip": "192.168.1.100",
    "port": 80,
    "enabled": true
  }'
```

### Trigger a diagnostic scan:
```bash
curl -X POST http://localhost:8787/api/diagnostic/scan \
  -H "Content-Type: application/json" \
  -d '{
    "method": "arp-scan"
  }'
```

### Get scan progress:
```bash
curl -X GET http://localhost:8787/api/diagnostic/scan-progress/12345
```