# Upstream Healer API Documentation

This document provides comprehensive documentation for the Upstream Healer RESTful API endpoints.

## Overview

The Upstream Healer API provides programmatic access to all core functionality including:
- Host monitoring management
- Diagnostic scanning capabilities
- Notification configuration
- System settings and health checks

All API endpoints are accessible under the `/api` base path, with additional endpoints available at the root level for web interface integration.

## Authentication

Most API endpoints require authentication. The application uses session-based authentication through cookies that are automatically handled by the web browser.

## Base URL

```
http://<upstream-healer-host>:8787/api
```

## Error Handling

All API responses follow standard HTTP status codes:
- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request parameters
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

## API Endpoints

### Host Management

#### Get All Hosts
```
GET /hosts
```

**Response:**
```json
[
  {
    "id": 1,
    "name": "vault",
    "mac_address": "00:11:22:33:44:55",
    "port": 80,
    "npm_proxy_host_id": 123,
    "grace_period_minutes": 10,
    "enabled": true,
    "subnet_id": 1
  }
]
```

#### Get Specific Host
```
GET /hosts/{host_id}
```

**Parameters:**
- `host_id` (integer) - The host identifier

**Response:**
```json
{
  "id": 1,
  "name": "vault",
  "mac_address": "00:11:22:33:44:55",
  "port": 80,
  "npm_proxy_host_id": 123,
  "grace_period_minutes": 10,
  "enabled": true,
  "subnet_id": 1
}
```

#### Get Host Events
```
GET /hosts/{host_id}/events
```

**Parameters:**
- `host_id` (integer) - The host identifier

**Response:**
```json
[
  {
    "id": 1,
    "host_id": 1,
    "event_type": "unreachable",
    "message": "Host became unreachable",
    "timestamp": "2023-01-01T12:00:00Z",
    "status": "completed"
  }
]
```

### Diagnostic Endpoints

#### Scan for Host by MAC
```
GET /diagnostic/scan/{mac_address}
```

**Parameters:**
- `mac_address` (string) - The MAC address to scan for

**Response:**
```json
{
  "mac_address": "00:11:22:33:44:55",
  "found": true,
  "ip_address": "192.168.1.100",
  "port": 80,
  "timestamp": "2023-01-01T12:00:00Z"
}
```

#### Scan for Host by MAC and Port
```
GET /diagnostic/scan/{mac_address}/{port}
```

**Parameters:**
- `mac_address` (string) - The MAC address to scan for
- `port` (integer) - The port number to check

**Response:**
```json
{
  "mac_address": "00:11:22:33:44:55",
  "port": 80,
  "reachable": true,
  "ip_address": "192.168.1.100",
  "timestamp": "2023-01-01T12:00:00Z"
}
```

#### Run Full Diagnostic Scan
```
GET /diagnostic/scan
```

**Response:**
```json
{
  "status": "scanning",
  "progress": 0,
  "total_hosts": 5,
  "completed_hosts": 0
}
```

### Events

#### Get Recent Events
```
GET /events
```

**Query Parameters:**
- `limit` (integer, optional) - Maximum number of events to return (default: 10)
- `days` (integer, optional) - Number of days to look back (default: 1)
- `host_id` (integer, optional) - Filter by specific host

**Response:**
```json
[
  {
    "id": 1,
    "host_id": 1,
    "event_type": "recovered",
    "message": "Host recovered after 15 minutes",
    "timestamp": "2023-01-01T12:00:00Z",
    "status": "completed"
  }
]
```

### Subnets

#### Get All Subnets
```
GET /subnets
```

**Response:**
```json
[
  {
    "id": 1,
    "name": "LAN",
    "cidr": "192.168.1.0/24",
    "interface": "eth0",
    "enabled": true
  }
]
```

### Health Check

#### System Health
```
GET /health
```

**Response:**
```json
{
  "status": "ok",
  "service": "upstream-healer"
}
```

## Web Interface Endpoints

The application also exposes web interface endpoints that return HTML responses:

### Dashboard
```
GET /
```
Returns the main dashboard page with host monitoring information.

### Host Management
```
GET /add-host
POST /add-host
GET /hosts/{host_id}/edit
POST /hosts/{host_id}/edit
```

### Notifications
```
GET /notifications
POST /notifications/channel/telegram
POST /notifications/channel/email
```

### Settings
```
GET /settings
POST /settings/subnets
```

## Testing

All API endpoints are tested with unit tests that validate:
- Correct HTTP status codes
- Proper response structure
- Parameter validation
- Error handling
- Data consistency

### Example Test Case

```python
def test_get_hosts():
    client = TestClient(app)
    response = client.get("/api/hosts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
```

## Version History

### v1.0.0 (Initial Release)
- All core endpoints implemented
- Basic host monitoring functionality
- Diagnostic scanning capabilities
- Notification system
- Settings management