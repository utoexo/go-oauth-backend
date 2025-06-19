# iShare Task Management API

A secure, production-grade REST API built in Go that implements OAuth 2.0 authorization with JSON Web Signatures (JWS) for task management. This API follows industry best practices for authentication, authorization, and secure task management.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [API Documentation](#api-documentation)
- [Comprehensive Testing Guide](#comprehensive-testing-guide)
  - [Swagger UI Testing](#swagger-ui-testing)
  - [Postman Testing](#postman-testing)
  - [Shell Script Testing](#shell-script-testing)
- [Troubleshooting](#troubleshooting)

## Overview

This project implements a secure task management API with the following features:
- OAuth 2.0 Authorization Code Flow for secure authentication
- JWS token signing using RS256 for enhanced security
- Complete CRUD operations for task management
- Comprehensive API documentation with Swagger/OpenAPI
- Multiple testing methods for thorough verification

## Features

### Authentication & Security
- **OAuth 2.0 Implementation**
  - Client registration endpoint (`POST /register`)
  - Authorization endpoint (`GET /authorize`)
  - Token endpoint (`POST /token`)
  - Client listing endpoint (`GET /clients`)
  - JWS token signing with RS256
  - Token validation middleware
  - Secure client secret handling

### Task Management
- **Complete CRUD Operations**
  - Create new tasks with validation
  - Retrieve task details by ID
  - Update existing tasks with partial updates
  - Delete tasks with proper authorization
  - List all tasks with authentication

### Data Models

#### Task Model
```go
type Task struct {
    ID          uuid.UUID `json:"id"`
    Title       string    `json:"title"`
    Description string    `json:"description"`
    Status      string    `json:"status"` // pending, completed
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}
```

#### OAuth Client Model
```go
type Client struct {
    ID                      uuid.UUID `json:"id"`
    ClientName              string    `json:"client_name"`
    ClientSecret            string    `json:"client_secret"`
    RedirectURIs            []string  `json:"redirect_uris"`
    GrantTypes              []string  `json:"grant_types"`
    ResponseTypes           []string  `json:"response_types"`
    TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method"`
    Scope                   string    `json:"scope"`
    CreatedAt               time.Time `json:"created_at"`
    UpdatedAt               time.Time `json:"updated_at"`
}
```

## Project Structure

```
iShare/
├── cmd/
│   └── server/          # Main application entry point
├── internal/
│   ├── api/            # API handlers and middleware
│   │   ├── handlers/   # Request handlers
│   │   └── errors.go   # Error handling
│   ├── auth/           # OAuth2 and JWT implementation
│   │   ├── oauth_handler.go    # OAuth endpoints
│   │   └── jwt_middleware.go   # JWT validation
│   ├── config/         # Configuration management
│   ├── db/            # Database operations
│   └── models/         # Data models
├── docs/              # API documentation
├── tests/             # Testing utilities
├── go.mod            # Go module definition
└── go.sum            # Go module checksums
```

## Getting Started

### Prerequisites
- Go 1.23.0 or later
- PostgreSQL
- RSA key pair for JWT signing
- cURL (for shell script testing)
- Postman (for API testing)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/utoexo/go-oauth-backend.git
   cd go-oauth-backend
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

### Configuration

1. Create a `.env` file:
```env
# Server Configuration
PORT=your-port-number

# Database connection
DATABASE_URL=your-database-url

# JWT Configuration
JWT_ISSUER=your-jwt-issuer
JWT_AUDIENCE=your-jwt-audience

# OAuth Configuration
OAUTH_CLIENT_ID=your-client
OAUTH_CLIENT_SECRET=your-client-secret
OAUTH_REDIRECT_URL=your-redirect-url
```

2. Generate RSA keys for JWT signing:

```bash
# Generate private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Generate public key
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

Place both files in the project root directory.

### Running the Server

```bash
go run cmd/server/main.go
```

The server will start at `http://localhost:8080` and automatically open the Swagger UI.

## API Documentation

### Task Endpoints

#### Create Task
```http
POST /tasks
Authorization: Bearer {token}
Content-Type: application/json

{
  "title": "Task Title",
  "description": "Task Description",
  "status": "pending"
}

Response (201 Created):
{
  "id": "uuid-string",
  "title": "Task Title",
  "description": "Task Description",
  "status": "pending",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

#### Get Task
```http
GET /tasks/{id}
Authorization: Bearer {token}

Response (200 OK):
{
  "id": "uuid-string",
  "title": "Task Title",
  "description": "Task Description",
  "status": "pending",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

#### Update Task
```http
PUT /tasks/{id}
Authorization: Bearer {token}
Content-Type: application/json

{
  "title": "Updated Title",
  "description": "Updated Description",
  "status": "completed"
}

Response (200 OK):
{
  "id": "uuid-string",
  "title": "Updated Title",
  "description": "Updated Description",
  "status": "completed",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

#### Delete Task
```http
DELETE /tasks/{id}
Authorization: Bearer {token}

Response (204 No Content)
```

#### List Tasks
```http
GET /tasks
Authorization: Bearer {token}

Response (200 OK):
[
  {
    "id": "uuid-string",
    "title": "Task 1",
    "description": "Description 1",
    "status": "pending",
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
]
```

### OAuth 2.0 Endpoints

#### Register Client
```http
POST /register
Content-Type: application/json

{
  "client_name": "Test Client",
  "redirect_uris": ["http://localhost:8081/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "tasks"
}

Response (201 Created):
{
  "client_id": "uuid-string",
  "client_secret": "generated-secret",
  "client_name": "Test Client",
  "redirect_uris": ["http://localhost:8081/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "tasks"
}
```

#### Authorization Request
```http
GET /authorize?
    response_type=code&
    client_id={client_id}&
    redirect_uri=http://localhost:8081/callback&
    state={state}

Response (302 Found):
Location: http://localhost:8081/callback?code={authorization_code}&state={state}
```

#### Token Exchange
```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code={code}&
redirect_uri={redirect_uri}&
client_id={client_id}&
client_secret={client_secret}

Response (200 OK):
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Error Response Format
```json
{
  "error": "error_code",
  "code": 400,
  "message": "Error message"
}
```

## Comprehensive Testing Guide

### Swagger UI Testing

#### Setup
1. Start the server:
   ```bash
   go run cmd/server/main.go
   ```
2. Open Swagger UI at `http://localhost:8080/swagger/index.html`

#### Testing Workflow

1. **Client Registration**
   - Expand the "OAuth2" section
   - Find `POST /register` endpoint
   - Click "Try it out"
   - Input the client registration request:
     ```json
     {
       "client_name": "Swagger Test Client",
       "redirect_uris": ["http://localhost:8081/callback"],
       "grant_types": ["authorization_code"],
       "response_types": ["code"],
       "token_endpoint_auth_method": "client_secret_basic",
       "scope": "tasks"
     }
     ```
   - Click "Execute"
   - Save the `client_id` and `client_secret` from the response

2. **Authorization Code**
   - Find `GET /authorize` endpoint
   - Click "Try it out"
   - Fill in parameters:
     - client_id: (from step 1)
     - redirect_uri: http://localhost:8081/callback
     - response_type: code
     - state: test123
   - Click "Execute"
   - Copy the authorization code from the redirect URL

3. **Token Exchange**
   - Find `POST /token` endpoint
   - Click "Try it out"
   - Input form parameters:
     - grant_type: authorization_code
     - code: (from step 2)
     - redirect_uri: http://localhost:8081/callback
     - client_id: (from step 1)
     - client_secret: (from step 1)
   - Click "Execute"
   - Copy the access token from the response

4. **Task Operations**
   - Click the "Authorize" button at the top
   - Enter: Bearer {access_token}
   - Test each task endpoint:
     a. Create Task (`POST /tasks`)
     b. List Tasks (`GET /tasks`)
     c. Get Task (`GET /tasks/{id}`)
     d. Update Task (`PUT /tasks/{id}`)
     e. Delete Task (`DELETE /tasks/{id}`)

### Postman Testing

#### Setup
1. Import the collection:
   - Open Postman
   - Click "Import"
   - Select `docs/iShare-API.postman_collection.json`

2. Create environment:
   - Click "Environments" → "New"
   - Name: "iShare Local"
   - Add variables:
     ```
     base_url: http://localhost:8080
     redirect_uri: http://localhost:8081/callback
     client_id: (leave empty)
     client_secret: (leave empty)
     code: (leave empty)
     access_token: (leave empty)
     task_id: (leave empty)
     ```
   - Save and select the environment

#### Testing Workflow

1. **Client Registration**
   - Find "Register Client" request
   - Review request body
   - Send request
   - Verify environment variables are automatically set:
     - client_id
     - client_secret

2. **Get Authorization Code**
   - Find "Get Authorization Code" request
   - Send request
   - Verify code is saved to environment

3. **Exchange Token**
   - Find "Exchange Token" request
   - Send request
   - Verify access_token is saved to environment

4. **Task Management**
   - Execute requests in order:
     a. "Create Task"
        - Verify task_id is saved
     b. "List Tasks"
        - Verify created task appears
     c. "Get Task"
        - Use saved task_id
     d. "Update Task"
        - Verify changes are saved
     e. "Delete Task"
        - Verify 204 response

### Shell Script Testing

#### Setup
1. Make the script executable:
   ```bash
   chmod +x tests/oauth_flow.sh
   ```

2. Verify dependencies:
   ```bash
   command -v curl >/dev/null 2>&1 || echo "curl required"
   command -v jq >/dev/null 2>&1 || echo "jq required"
   ```

#### Running Tests
```bash
./tests/oauth_flow.sh
```

#### Test Flow
1. **Health Check**
   - Verifies server is running
   - Checks database connection

2. **OAuth Flow**
   - Registers new client
   - Gets authorization code
   - Exchanges code for token
   - Validates token format

3. **Task Operations**
   - Creates test task
   - Retrieves task details
   - Updates task status
   - Lists all tasks
   - Deletes test task

4. **Error Cases**
   - Invalid token
   - Missing fields
   - Invalid task ID

#### Monitoring Output
- Green ✅: Test passed
- Red ❌: Test failed
- Yellow ⚠️: Warning/Info

## Troubleshooting

### Common Issues

1. **Database Connection**
   ```bash
   # Check connection
   psql $DATABASE_URL -c "SELECT 1"
   ```

2. **RSA Keys**
   ```bash
   # Verify key permissions
   ls -l private_key.pem public_key.pem
   # Should show: -rw-r--r--
   ```

3. **Port Conflicts**
   ```bash
   # Check if port is in use
   lsof -i :8080
   ```

4. **OAuth Errors**
   - Invalid redirect_uri: Check exact match
   - Invalid client credentials: Verify client_id and secret
   - Token validation: Check RSA key pair

### Testing Issues

1. **Swagger UI**
   - CORS issues: Check browser console
   - Authorization header: Include "Bearer" prefix
   - Invalid token format: Verify JWT structure

2. **Postman**
   - Environment variables not set: Check collection scripts
   - Request failures: Verify pre-request scripts
   - Token expiration: Re-run OAuth flow

3. **Shell Script**
   - Permission denied: Check script executable flag
   - jq not found: Install jq package
   - Callback errors: Verify PORT setting

## Project Requirements Status

✅ **API Implementation**
- [x] Create Task (POST /tasks)
- [x] Get Task (GET /tasks/{id})
- [x] Update Task (PUT /tasks/{id})
- [x] Delete Task (DELETE /tasks/{id})
- [x] List Tasks (GET /tasks)

✅ **Task Model**
- [x] UUID-based ID
- [x] Title field
- [x] Description field
- [x] Status field
- [x] Timestamps

✅ **Authentication**
- [x] OAuth 2.0 Authorization Code Flow
- [x] JWS token signing (RS256)
- [x] Client registration
- [x] Token validation

✅ **Documentation**
- [x] OpenAPI/Swagger
- [x] Postman collection
- [x] Integration test script 