# Upstream Healer - API Reference

## Web Interface Endpoints

### Main Dashboard
- **GET /** 
  - **Response Type**: HTML
  - **Description**: Main dashboard page showing monitored hosts and status

### Host Management
- **GET /hosts/add**
  - **Response Type**: HTML
  - **Description**: Form to add a new host

- **GET /hosts/{host_id}/edit**
  - **Response Type**: HTML
  - **Description**: Host edit form

### Subnet Management
- **GET /subnets/**
  - **Response Type**: HTML
  - **Description**: Subnet management page

- **POST /subnets/add**
  - **Method**: POST
  - **Description**: Add a new subnet

- **POST /subnets/{subnet_id}/toggle**
  - **Method**: POST
  - **Description**: Toggle a subnet's enabled state

- **POST /subnets/{subnet_id}/delete**
  - **Method**: POST
  - **Description**: Delete a subnet

- **GET /subnets/suppressed**
  - **Response Type**: HTML
  - **Description**: Suppressed hosts page

- **POST /subnets/suppressed/add**
  - **Method**: POST
  - **Description**: Add a host to the suppressed list

- **POST /subnets/suppressed/{host_id}/delete**
  - **Method**: POST
  - **Description**: Delete a suppressed host

### Scan Control
- **GET /scan/**
  - **Response Type**: HTML
  - **Description**: Scan control page

- **POST /scan/run-scan**
  - **Method**: POST
  - **Description**: Run a full scan

- **POST /scan/run-port-scan**
  - **Method**: POST
  - **Description**: Run a port scan

### Notification Management
- **GET /notifications/**
  - **Response Type**: HTML
  - **Description**: Notification settings page

- **POST /notifications/channel/telegram**
  - **Method**: POST
  - **Description**: Add a new Telegram notification channel

- **POST /notifications/channel/email**
  - **Method**: POST
  - **Description**: Add a new email notification channel

- **POST /notifications/channel/{channel_id}/toggle**
  - **Method**: POST
  - **Description**: Toggle a notification channel's enabled state

- **POST /notifications/rule/{channel_id}/{event_type}/toggle**
  - **Method**: POST
  - **Description**: Toggle a notification rule's enabled state

- **POST /notifications/channel/{channel_id}/delete**
  - **Method**: POST
  - **Description**: Delete a notification channel

### Settings and Configuration
- **GET /settings/**
  - **Response Type**: HTML
  - **Description**: Application settings page

- **POST /settings/**
  - **Method**: POST
  - **Description**: Save application settings

- **GET /settings/health**
  - **Response Type**: HTML
  - **Description**: Health status page

- **GET /settings/logs**
  - **Response Type**: HTML
  - **Description**: Logs page

### Dashboard Views
- **GET /dashboard/**
  - **Response Type**: HTML
  - **Description**: Main dashboard page showing all hosts

- **GET /dashboard/pinned-subnet/{subnet_id}**
  - **Response Type**: HTML
  - **Description**: Dashboard page with a specific subnet pinned

## API Endpoints

### Health Check
- **GET /api/health**
  - **Method**: GET
  - **Authentication**: None
  - **Description**: Health check endpoint for service monitoring
  - **Response**: 
    ```json
    {
      "status": "ok",
      "service": "upstream-healer"
    }
    ```

## Error Responses

All endpoints may return standard HTTP error codes:
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

The web interface currently uses no authentication for endpoints, as designed for the specific use case. All data is stored in a local SQLite database within a Docker volume.

## Rate Limiting

No rate limiting is implemented at this time. The application is designed to run in controlled environments where access is restricted by network configuration.

## Versioning

API versioning is not currently implemented. Future versions may introduce a version prefix in endpoint paths.

## Examples

### Health check:
```bash
curl -X GET http://localhost:8787/api/health
```