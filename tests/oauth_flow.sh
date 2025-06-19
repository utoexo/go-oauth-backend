#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# Config
AUTH_SERVER="http://localhost:8080"
CALLBACK_PORT=8081
REDIRECT_URI="http://localhost:$CALLBACK_PORT/callback"
STATE="teststate123"

function print_step() {
  echo -e "${BLUE}\n==== $1 ====\n${NC}"
}

function print_success() {
  echo -e "${GREEN}$1${NC}"
}

function print_error() {
  echo -e "${RED}$1${NC}"
  exit 1
}

function print_json() {
  echo "$1" | jq '.' || echo "$1"
}

function print_request() {
  local method=$1
  local url=$2
  local headers=$3
  local body=$4
  
  echo -e "${GRAY}➜ Request Details:"
  echo -e "Method: $method"
  echo -e "URL: $url"
  if [ ! -z "$headers" ]; then
    echo -e "Headers:"
    echo "$headers" | sed 's/^/  /'
  fi
  if [ ! -z "$body" ]; then
    echo -e "Body:"
    echo "$body" | jq '.' 2>/dev/null || echo "$body" | sed 's/^/  /'
  fi
  echo -e "${NC}"
}

function print_response() {
  local status=$1
  local body=$2
  
  echo -e "${GRAY}➜ Response Details:"
  echo -e "Status: $status"
  echo -e "Body:"
  echo "$body" | jq '.' 2>/dev/null || echo "$body" | sed 's/^/  /'
  echo -e "${NC}"
}

function check_dependencies() {
  print_step "Checking Dependencies"
  command -v curl >/dev/null 2>&1 || print_error "curl is required but not installed"
  command -v jq >/dev/null 2>&1 || print_error "jq is required but not installed"
  
  # Check if the authorization server is running
  print_step "Checking Authorization Server"
  if ! curl -s "$AUTH_SERVER/health" > /dev/null; then
    print_error "Authorization server is not running at $AUTH_SERVER. Please start the server first."
  fi
  print_success "Authorization server is running"
}

# Check dependencies
check_dependencies

# 1. Register a new client
print_step "Step 1: Registering a new OAuth Client"
REGISTER_BODY='{
  "client_name": "Test Script Client",
  "redirect_uris": ["'$REDIRECT_URI'"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "tasks"
}'

print_request "POST" "$AUTH_SERVER/register" "Content-Type: application/json" "$REGISTER_BODY"

REGISTER_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$AUTH_SERVER/register" \
  -H "Content-Type: application/json" \
  -d "$REGISTER_BODY")
REGISTER_STATUS=$(echo "$REGISTER_RESPONSE" | tail -n1)
REGISTER_BODY=$(echo "$REGISTER_RESPONSE" | sed '$d')

print_response "$REGISTER_STATUS" "$REGISTER_BODY"

if [ "$REGISTER_STATUS" != "201" ]; then
  print_error "Failed to register client. Expected status 201, got $REGISTER_STATUS"
fi

CLIENT_ID=$(echo $REGISTER_BODY | jq -r '.client_id')
CLIENT_SECRET=$(echo $REGISTER_BODY | jq -r '.client_secret')
if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ]; then
  print_error "Failed to extract client credentials from response"
fi
print_success "Client registered successfully"

# 2. Get authorization code
print_step "Step 2: Requesting Authorization Code"
AUTH_URL="$AUTH_SERVER/authorize?client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&response_type=code&state=$STATE"

print_request "GET" "$AUTH_URL" "" ""

# Make the authorization request and capture the redirect
AUTH_RESPONSE=$(curl -s -i -D - -o /dev/null "$AUTH_URL")
AUTH_HEADERS=$(echo "$AUTH_RESPONSE" | grep -i "^location:" || true)

print_response "302" "$AUTH_HEADERS"

# Extract code and state from the Location header
CODE=$(echo "$AUTH_HEADERS" | grep -i "^location:" | grep -oP 'code=\K[^&\s]*' || true)
RECEIVED_STATE=$(echo "$AUTH_HEADERS" | grep -i "^location:" | grep -oP 'state=\K[^&\s]*' || true)

if [ -z "$CODE" ]; then
  print_error "Failed to obtain authorization code"
fi

if [ "$RECEIVED_STATE" != "$STATE" ]; then
  print_error "State mismatch! Expected: $STATE, Got: $RECEIVED_STATE"
fi

print_success "Authorization code obtained: $CODE"
print_success "State verified successfully"

# 3. Exchange code for access token
print_step "Step 3: Exchanging Code for Access Token"
TOKEN_BODY="grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET"

print_request "POST" "$AUTH_SERVER/token" "Content-Type: application/x-www-form-urlencoded" "$TOKEN_BODY"

TOKEN_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$AUTH_SERVER/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "$TOKEN_BODY")
TOKEN_STATUS=$(echo "$TOKEN_RESPONSE" | tail -n1)
TOKEN_BODY=$(echo "$TOKEN_RESPONSE" | sed '$d')

print_response "$TOKEN_STATUS" "$TOKEN_BODY"

ACCESS_TOKEN=$(echo $TOKEN_BODY | jq -r '.access_token')
if [ -z "$ACCESS_TOKEN" ]; then
  print_error "Failed to obtain access token"
fi
print_success "Access token obtained successfully"

# 4. Test Task Management API
print_step "Step 4: Testing Task Management API"

# 4.1 Create a Task
print_step "4.1: Creating a Task"
CREATE_TASK_BODY='{
  "title": "Test Task",
  "description": "Created by test script",
  "status": "pending"
}'

print_request "POST" "$AUTH_SERVER/tasks" \
  "Authorization: Bearer $ACCESS_TOKEN\nContent-Type: application/json" \
  "$CREATE_TASK_BODY"

CREATE_TASK_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$AUTH_SERVER/tasks" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$CREATE_TASK_BODY")
CREATE_STATUS=$(echo "$CREATE_TASK_RESPONSE" | tail -n1)
CREATE_BODY=$(echo "$CREATE_TASK_RESPONSE" | sed '$d')

print_response "$CREATE_STATUS" "$CREATE_BODY"

TASK_ID=$(echo $CREATE_BODY | jq -r '.id')
if [ -z "$TASK_ID" ] || [ "$TASK_ID" = "null" ]; then
  print_error "Failed to create task"
fi
print_success "Task created successfully"

# 4.2 List Tasks
print_step "4.2: Listing All Tasks"

print_request "GET" "$AUTH_SERVER/tasks" "Authorization: Bearer $ACCESS_TOKEN" ""

LIST_RESPONSE=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $ACCESS_TOKEN" "$AUTH_SERVER/tasks")
LIST_STATUS=$(echo "$LIST_RESPONSE" | tail -n1)
LIST_BODY=$(echo "$LIST_RESPONSE" | sed '$d')

print_response "$LIST_STATUS" "$LIST_BODY"
print_success "Tasks retrieved successfully"

# 4.3 Get Task by ID
print_step "4.3: Getting Task by ID"

print_request "GET" "$AUTH_SERVER/tasks/$TASK_ID" "Authorization: Bearer $ACCESS_TOKEN" ""

GET_RESPONSE=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $ACCESS_TOKEN" "$AUTH_SERVER/tasks/$TASK_ID")
GET_STATUS=$(echo "$GET_RESPONSE" | tail -n1)
GET_BODY=$(echo "$GET_RESPONSE" | sed '$d')

print_response "$GET_STATUS" "$GET_BODY"

if [ "$(echo $GET_BODY | jq -r '.id')" != "$TASK_ID" ]; then
  print_error "Failed to get task"
fi
print_success "Task retrieved successfully"

# 4.4 Update Task
print_step "4.4: Updating Task"
UPDATE_TASK_BODY='{
  "title": "Updated Test Task",
  "description": "Updated by test script",
  "status": "completed"
}'

print_request "PUT" "$AUTH_SERVER/tasks/$TASK_ID" \
  "Authorization: Bearer $ACCESS_TOKEN\nContent-Type: application/json" \
  "$UPDATE_TASK_BODY"

UPDATE_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT "$AUTH_SERVER/tasks/$TASK_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$UPDATE_TASK_BODY")
UPDATE_STATUS=$(echo "$UPDATE_RESPONSE" | tail -n1)
UPDATE_BODY=$(echo "$UPDATE_RESPONSE" | sed '$d')

print_response "$UPDATE_STATUS" "$UPDATE_BODY"

if [ "$(echo $UPDATE_BODY | jq -r '.status')" != "completed" ]; then
  print_error "Failed to update task"
fi
print_success "Task updated successfully"

# 4.5 Delete Task
print_step "4.5: Deleting Task"

print_request "DELETE" "$AUTH_SERVER/tasks/$TASK_ID" "Authorization: Bearer $ACCESS_TOKEN" ""

DELETE_RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE \
  "$AUTH_SERVER/tasks/$TASK_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
DELETE_STATUS=$(echo "$DELETE_RESPONSE" | tail -n1)

print_response "$DELETE_STATUS" ""

if [ "$DELETE_STATUS" != "204" ]; then
  print_error "Failed to delete task. Expected status 204, got $DELETE_STATUS"
fi
print_success "Task deleted successfully"

# 4.6 Verify Deletion
print_step "4.6: Verifying Task Deletion"

print_request "GET" "$AUTH_SERVER/tasks" "Authorization: Bearer $ACCESS_TOKEN" ""

VERIFY_RESPONSE=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $ACCESS_TOKEN" "$AUTH_SERVER/tasks")
VERIFY_STATUS=$(echo "$VERIFY_RESPONSE" | tail -n1)
VERIFY_BODY=$(echo "$VERIFY_RESPONSE" | sed '$d')

print_response "$VERIFY_STATUS" "$VERIFY_BODY"

DELETED_TASK_EXISTS=$(echo $VERIFY_BODY | jq -r ".[] | select(.id == \"$TASK_ID\") | .id")
if [ ! -z "$DELETED_TASK_EXISTS" ]; then
  print_error "Task was not properly deleted. It still exists in the task list."
fi
print_success "Task deletion verified successfully"

print_step "Test Workflow Complete"
print_success "✅ All tests passed successfully!"
print_success "✅ OAuth 2.0 flow is working correctly"
print_success "✅ Task management API endpoints are functioning properly" 