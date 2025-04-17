# API Documentation

This document provides comprehensive documentation for the FreeRADIUS TOTP Management System API.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Response Format](#response-format)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Endpoints](#endpoints)
  - [System Endpoints](#system-endpoints)
    - [Health Check](#health-check)
    - [System Status](#system-status)
  - [User Management Endpoints](#user-management-endpoints)
    - [List Users](#list-users)
    - [Get User](#get-user)
    - [Create User](#create-user)
    - [Update User](#update-user)
    - [Delete User](#delete-user)
  - [TOTP Management Endpoints](#totp-management-endpoints)
    - [Setup TOTP](#setup-totp)
    - [Verify TOTP](#verify-totp)
  - [Client Management Endpoints](#client-management-endpoints)
    - [List Clients](#list-clients)
    - [Get Client](#get-client)
    - [Create Client](#create-client)
    - [Update Client](#update-client)
    - [Delete Client](#delete-client)
    - [Rotate Client Secret](#rotate-client-secret)
  - [Log Access Endpoints](#log-access-endpoints)
    - [Authentication Logs](#authentication-logs)
    - [Audit Logs](#audit-logs)
- [Examples](#examples)
  - [cURL Examples](#curl-examples)
  - [Python Examples](#python-examples)
  - [JavaScript Examples](#javascript-examples)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

The FreeRADIUS TOTP Management System API provides programmatic access to manage users, TOTP tokens, RADIUS clients, and view logs. The API follows RESTful principles and uses JSON for request and response bodies.

## Authentication

All API requests (except the health check endpoint) require authentication using an API key. You can create API keys in the Web UI under "API Keys".

Include your API key in one of the following ways:

1. **HTTP Header**: Add an `X-API-Key` header to your request
   ```
   X-API-Key: your-api-key
   ```

2. **Query Parameter**: Add an `api_key` parameter to the URL
   ```
   ?api_key=your-api-key
   ```

Example:
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/users
```

## Response Format

All API responses are in JSON format. Successful responses typically include:

- For single resource requests: The resource object
- For collection requests: An object with metadata and an array of resources
- For action requests: A success message and relevant data

Example successful response:
```json
{
  "username": "user1",
  "attributes": {
    "Cleartext-Password": {
      "value": "password",
      "op": ":="
    }
  },
  "has_totp": true,
  "totp_enabled": true,
  "groups": ["users", "vpn"]
}
```

## Error Handling

The API uses standard HTTP status codes to indicate the success or failure of a request:

- `200 OK`: The request was successful
- `201 Created`: The resource was created successfully
- `400 Bad Request`: The request was invalid
- `401 Unauthorized`: Authentication failed
- `403 Forbidden`: The authenticated user doesn't have permission
- `404 Not Found`: The requested resource was not found
- `409 Conflict`: The request conflicts with the current state
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: An error occurred on the server

Error responses include a JSON object with an error message:

```json
{
  "error": "Invalid username format",
  "status": 400
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse. Rate limits are applied per API key and vary by endpoint:

- Standard endpoints: 100 requests per minute
- Write operations (POST, PUT, DELETE): 30 requests per minute
- Log access endpoints: 10 requests per minute

Rate limit headers are included in all responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1619123456
```

If you exceed the rate limit, you'll receive a `429 Too Many Requests` response.

## Endpoints

### System Endpoints

#### Health Check

Check if the API is running. This endpoint does not require authentication.

```
GET /api/health
```

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2025-04-16 20:30:00",
  "components": {
    "database": {
      "status": "healthy",
      "error": null
    },
    "radius": {
      "status": "healthy",
      "error": null
    }
  },
  "system": {
    "cpu_usage": 12.5,
    "memory_usage": 45.2,
    "disk_usage": 32.1,
    "uptime": 86400
  }
}
```

#### System Status

Get system status information including user counts, client counts, and authentication statistics.

```
GET /api/status
```

**Response:**

```json
{
  "users": {
    "total": 10,
    "with_totp": 5
  },
  "clients": {
    "total": 3
  },
  "authentication": {
    "total": 150,
    "successful": 145,
    "failed": 5
  },
  "recent_auth": [
    {
      "username": "user1",
      "nasipaddress": "192.168.1.1",
      "acctstarttime": "2025-04-16 20:25:00",
      "acctstoptime": "2025-04-16 20:25:10"
    }
  ],
  "database": {
    "size_mb": 2.5,
    "path": "/data/sqlite/radius.db"
  },
  "timestamp": "2025-04-16 20:30:00"
}
```

### User Management Endpoints

#### List Users

Get a list of users with optional filtering.

```
GET /api/users
```

**Parameters:**

- `search` (optional): Filter users by username
- `limit` (optional, default: 100): Maximum number of users to return
- `offset` (optional, default: 0): Number of users to skip

**Response:**

```json
{
  "total": 10,
  "limit": 100,
  "offset": 0,
  "users": [
    {
      "username": "user1"
    },
    {
      "username": "user2"
    }
  ]
}
```

#### Get User

Get detailed information about a specific user.

```
GET /api/users/<username>
```

**Response:**

```json
{
  "username": "user1",
  "attributes": {
    "Cleartext-Password": {
      "value": "password",
      "op": ":="
    }
  },
  "has_totp": true,
  "totp_enabled": true,
  "groups": ["users", "vpn"]
}
```

#### Create User

Create a new user.

```
POST /api/users
```

**Request Body:**

```json
{
  "username": "newuser",
  "password": "password123",
  "totp_enabled": true,
  "groups": ["users", "vpn"]
}
```

**Response:**

```json
{
  "username": "newuser",
  "attributes": {
    "Cleartext-Password": {
      "value": "password123",
      "op": ":="
    },
    "TOTP-Secret": {
      "value": "JBSWY3DPEHPK3PXP",
      "op": ":="
    }
  },
  "has_totp": true,
  "totp_enabled": true,
  "groups": ["users", "vpn"],
  "totp_secret": "JBSWY3DPEHPK3PXP",
  "totp_qrcode": "data:image/png;base64,..."
}
```

#### Update User

Update an existing user.

```
PUT /api/users/<username>
```

**Request Body:**

```json
{
  "password": "newpassword",
  "totp_enabled": false,
  "groups": ["users"]
}
```

**Response:**

```json
{
  "username": "user1",
  "attributes": {
    "Cleartext-Password": {
      "value": "newpassword",
      "op": ":="
    }
  },
  "has_totp": false,
  "totp_enabled": false,
  "groups": ["users"]
}
```

#### Delete User

Delete a user.

```
DELETE /api/users/<username>
```

**Response:**

```json
{
  "success": true,
  "message": "User user1 deleted successfully"
}
```

### TOTP Management Endpoints

#### Setup TOTP

Setup or reset TOTP for a user.

```
POST /api/totp/<username>/setup
```

**Parameters:**

- `reset` (optional, default: false): Whether to reset the TOTP secret if it already exists

**Response:**

```json
{
  "username": "user1",
  "secret": "JBSWY3DPEHPK3PXP",
  "qrcode": "data:image/png;base64,..."
}
```

#### Verify TOTP

Verify a TOTP token for a user.

```
POST /api/totp/verify
```

**Request Body:**

```json
{
  "username": "user1",
  "token": "123456"
}
```

**Response:**

```json
{
  "success": true,
  "message": "TOTP verification successful"
}
```

### Client Management Endpoints

#### List Clients

Get a list of all RADIUS clients.

```
GET /api/clients
```

**Response:**

```json
[
  {
    "id": 1,
    "nasname": "192.168.1.1",
    "shortname": "router1",
    "type": "cisco",
    "ports": 1812,
    "secret": "secret123",
    "server": null,
    "community": null,
    "description": "Main router"
  }
]
```

#### Get Client

Get detailed information about a specific RADIUS client.

```
GET /api/clients/<client_id>
```

**Response:**

```json
{
  "id": 1,
  "nasname": "192.168.1.1",
  "shortname": "router1",
  "type": "cisco",
  "ports": 1812,
  "secret": "secret123",
  "server": null,
  "community": null,
  "description": "Main router"
}
```

#### Create Client

Create a new RADIUS client.

```
POST /api/clients
```

**Request Body:**

```json
{
  "nasname": "192.168.1.2",
  "shortname": "router2",
  "type": "cisco",
  "secret": "secret456",
  "ports": 1812,
  "description": "Backup router"
}
```

**Response:**

```json
{
  "id": 2,
  "nasname": "192.168.1.2",
  "shortname": "router2",
  "type": "cisco",
  "ports": 1812,
  "secret": "secret456",
  "server": null,
  "community": null,
  "description": "Backup router"
}
```

#### Update Client

Update an existing RADIUS client.

```
PUT /api/clients/<client_id>
```

**Request Body:**

```json
{
  "description": "Updated description"
}
```

**Response:**

```json
{
  "id": 1,
  "nasname": "192.168.1.1",
  "shortname": "router1",
  "type": "cisco",
  "ports": 1812,
  "secret": "secret123",
  "server": null,
  "community": null,
  "description": "Updated description"
}
```

#### Delete Client

Delete a RADIUS client.

```
DELETE /api/clients/<client_id>
```

**Response:**

```json
{
  "success": true,
  "message": "Client router1 deleted successfully"
}
```

#### Rotate Client Secret

Generate and set a new random secret for a RADIUS client.

```
POST /api/clients/<client_id>/rotate-secret
```

**Response:**

```json
{
  "success": true,
  "client_id": 1,
  "shortname": "router1",
  "new_secret": "newrandomsecret"
}
```

### Log Access Endpoints

#### Authentication Logs

Get authentication logs with optional filtering.

```
GET /api/logs/auth
```

**Parameters:**

- `username` (optional): Filter logs by username
- `status` (optional): Filter logs by status (success/failure)
- `start_date` (optional): Filter logs by start date
- `end_date` (optional): Filter logs by end date
- `limit` (optional, default: 100): Maximum number of logs to return
- `offset` (optional, default: 0): Number of logs to skip

**Response:**

```json
{
  "total": 150,
  "limit": 100,
  "offset": 0,
  "logs": [
    {
      "radacctid": 1,
      "acctsessionid": "12345",
      "acctuniqueid": "abcdef",
      "username": "user1",
      "nasipaddress": "192.168.1.1",
      "acctstarttime": "2025-04-16 20:25:00",
      "acctstoptime": "2025-04-16 20:25:10"
    }
  ]
}
```

#### Audit Logs

Get audit logs with optional filtering.

```
GET /api/logs/audit
```

**Parameters:**

- `admin` (optional): Filter logs by admin username
- `action` (optional): Filter logs by action
- `start_date` (optional): Filter logs by start date
- `end_date` (optional): Filter logs by end date
- `limit` (optional, default: 100): Maximum number of logs to return
- `offset` (optional, default: 0): Number of logs to skip

**Response:**

```json
{
  "total": 50,
  "limit": 100,
  "offset": 0,
  "logs": [
    {
      "id": 1,
      "admin_username": "admin",
      "action": "create_user",
      "details": "Created user user1 with TOTP: true",
      "timestamp": "2025-04-16 20:20:00"
    }
  ]
}
```

## Examples

### cURL Examples

#### Get Users

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/users
```

#### Create User

```bash
curl -X POST \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"username":"newuser","password":"password123","totp_enabled":true,"groups":["users"]}' \
  http://localhost:8080/api/users
```

#### Update User

```bash
curl -X PUT \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"password":"newpassword","totp_enabled":false}' \
  http://localhost:8080/api/users/user1
```

#### Delete User

```bash
curl -X DELETE \
  -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/users/user1
```

### Python Examples

#### Get Users

```python
import requests

api_key = "your-api-key"
url = "http://localhost:8080/api/users"

headers = {
    "X-API-Key": api_key
}

response = requests.get(url, headers=headers)
users = response.json()

print(f"Total users: {users['total']}")
for user in users['users']:
    print(user['username'])
```

#### Create User

```python
import requests

api_key = "your-api-key"
url = "http://localhost:8080/api/users"

headers = {
    "X-API-Key": api_key,
    "Content-Type": "application/json"
}

data = {
    "username": "newuser",
    "password": "password123",
    "totp_enabled": True,
    "groups": ["users"]
}

response = requests.post(url, headers=headers, json=data)
new_user = response.json()

print(f"User created: {new_user['username']}")
if new_user['has_totp']:
    print(f"TOTP Secret: {new_user['totp_secret']}")
```

### JavaScript Examples

#### Get Users

```javascript
const apiKey = "your-api-key";
const url = "http://localhost:8080/api/users";

fetch(url, {
  headers: {
    "X-API-Key": apiKey
  }
})
.then(response => response.json())
.then(data => {
  console.log(`Total users: ${data.total}`);
  data.users.forEach(user => {
    console.log(user.username);
  });
})
.catch(error => console.error("Error:", error));
```

#### Create User

```javascript
const apiKey = "your-api-key";
const url = "http://localhost:8080/api/users";

const data = {
  username: "newuser",
  password: "password123",
  totp_enabled: true,
  groups: ["users"]
};

fetch(url, {
  method: "POST",
  headers: {
    "X-API-Key": apiKey,
    "Content-Type": "application/json"
  },
  body: JSON.stringify(data)
})
.then(response => response.json())
.then(newUser => {
  console.log(`User created: ${newUser.username}`);
  if (newUser.has_totp) {
    console.log(`TOTP Secret: ${newUser.totp_secret}`);
  }
})
.catch(error => console.error("Error:", error));
```

## Best Practices

1. **API Key Security**
   - Store API keys securely
   - Use different API keys for different applications
   - Rotate API keys regularly
   - Use the minimum required permissions

2. **Error Handling**
   - Handle API errors gracefully
   - Implement retry logic with exponential backoff for transient errors
   - Log API errors for troubleshooting

3. **Rate Limiting**
   - Respect rate limits
   - Implement caching where appropriate
   - Batch operations when possible

4. **Data Validation**
   - Validate input data before sending to the API
   - Handle validation errors gracefully

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Ensure the API key is valid and active
   - Check that the API key is included in the request
   - Verify the API key has the necessary permissions

2. **Rate Limiting**
   - Check the rate limit headers in the response
   - Implement backoff and retry logic
   - Consider batching requests

3. **Data Validation Errors**
   - Check the error message for details
   - Validate input data before sending
   - Refer to the API documentation for required fields and formats

### Getting Help

If you encounter issues not covered in this documentation:

1. Check the logs for error messages
2. Review the API documentation for the specific endpoint
3. Contact the system administrator for assistance