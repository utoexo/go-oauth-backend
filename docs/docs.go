// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/authorize": {
            "get": {
                "description": "Initiates the OAuth2 Authorization Code Flow. Redirects with code and state.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "OAuth2"
                ],
                "summary": "OAuth2 Authorization Endpoint",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Client ID",
                        "name": "client_id",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Redirect URI",
                        "name": "redirect_uri",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Response Type (must be 'code')",
                        "name": "response_type",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "CSRF State",
                        "name": "state",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "302": {
                        "description": "Redirects to client redirect_uri with code and state",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/clients": {
            "get": {
                "description": "Returns the list of registered OAuth clients (excluding secrets) for testing/demo purposes.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "OAuth2"
                ],
                "summary": "List available OAuth clients",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "array",
                            "items": {
                                "$ref": "#/definitions/auth.OAuthClientPublic"
                            }
                        }
                    }
                }
            }
        },
        "/register": {
            "post": {
                "description": "Register a new OAuth client following iSHARE specifications",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "OAuth2"
                ],
                "summary": "Register a new OAuth client",
                "parameters": [
                    {
                        "description": "Client Registration Request",
                        "name": "request",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/auth.ClientRegistrationRequest"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/auth.ClientRegistrationResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/tasks": {
            "get": {
                "security": [
                    {
                        "BearerAuth": []
                    }
                ],
                "description": "Retrieves all tasks. Requires JWT access token.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Tasks"
                ],
                "summary": "List all tasks",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "array",
                            "items": {
                                "$ref": "#/definitions/models.Task"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            },
            "post": {
                "security": [
                    {
                        "BearerAuth": []
                    }
                ],
                "description": "Creates a new task. Requires JWT access token.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Tasks"
                ],
                "summary": "Create a new task",
                "parameters": [
                    {
                        "description": "Task to create",
                        "name": "task",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/models.CreateTaskRequest"
                        }
                    }
                ],
                "responses": {
                    "201": {
                        "description": "Created",
                        "schema": {
                            "$ref": "#/definitions/models.Task"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/tasks/{id}": {
            "get": {
                "security": [
                    {
                        "BearerAuth": []
                    }
                ],
                "description": "Retrieves a task by its ID. Requires JWT access token.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Tasks"
                ],
                "summary": "Get a task by ID",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Task ID",
                        "name": "id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/models.Task"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            },
            "put": {
                "security": [
                    {
                        "BearerAuth": []
                    }
                ],
                "description": "Updates an existing task. Requires JWT access token.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Tasks"
                ],
                "summary": "Update a task",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Task ID",
                        "name": "id",
                        "in": "path",
                        "required": true
                    },
                    {
                        "description": "Task fields to update",
                        "name": "task",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/models.UpdateTaskRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/models.Task"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            },
            "delete": {
                "security": [
                    {
                        "BearerAuth": []
                    }
                ],
                "description": "Deletes a task by ID. Requires JWT access token.",
                "tags": [
                    "Tasks"
                ],
                "summary": "Delete a task",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Task ID",
                        "name": "id",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "204": {
                        "description": "No Content",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "/token": {
            "post": {
                "description": "Exchanges an authorization code for a JWT access token",
                "consumes": [
                    "application/x-www-form-urlencoded"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "OAuth2"
                ],
                "summary": "OAuth2 Token Endpoint",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Grant Type",
                        "name": "grant_type",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Authorization Code",
                        "name": "code",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Redirect URI",
                        "name": "redirect_uri",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Client ID",
                        "name": "client_id",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Client Secret",
                        "name": "client_secret",
                        "in": "formData",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/auth.TokenResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "auth.ClientRegistrationRequest": {
            "type": "object",
            "required": [
                "client_name",
                "grant_types",
                "redirect_uris",
                "response_types",
                "scope",
                "token_endpoint_auth_method"
            ],
            "properties": {
                "client_name": {
                    "type": "string"
                },
                "grant_types": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "redirect_uris": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "response_types": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "scope": {
                    "type": "string"
                },
                "token_endpoint_auth_method": {
                    "type": "string"
                }
            }
        },
        "auth.ClientRegistrationResponse": {
            "type": "object",
            "properties": {
                "client_id": {
                    "type": "string"
                },
                "client_name": {
                    "type": "string"
                },
                "client_secret": {
                    "type": "string"
                },
                "grant_types": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "redirect_uris": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "response_types": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "scope": {
                    "type": "string"
                },
                "token_endpoint_auth_method": {
                    "type": "string"
                }
            }
        },
        "auth.OAuthClientPublic": {
            "type": "object",
            "properties": {
                "client_id": {
                    "type": "string",
                    "example": "demo-client"
                },
                "redirect_uri": {
                    "type": "string",
                    "example": "http://localhost:8081/callback"
                }
            }
        },
        "auth.TokenResponse": {
            "type": "object",
            "properties": {
                "access_token": {
                    "type": "string",
                    "example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                },
                "expires_in": {
                    "type": "integer",
                    "example": 3600
                },
                "token_type": {
                    "type": "string",
                    "example": "Bearer"
                }
            }
        },
        "models.CreateTaskRequest": {
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "example": "Task 1 description"
                },
                "status": {
                    "type": "string",
                    "example": "pending"
                },
                "title": {
                    "type": "string",
                    "example": "Task 1"
                }
            }
        },
        "models.Task": {
            "type": "object",
            "properties": {
                "created_at": {
                    "type": "string",
                    "example": "2025-06-18T10:00:00Z"
                },
                "description": {
                    "type": "string",
                    "example": "Write Swagger docs for the API"
                },
                "id": {
                    "type": "string",
                    "example": "123e4567-e89b-12d3-a456-426614174000"
                },
                "status": {
                    "description": "e.g., pending, completed",
                    "type": "string",
                    "example": "pending"
                },
                "title": {
                    "type": "string",
                    "example": "Write documentation"
                },
                "updated_at": {
                    "type": "string",
                    "example": "2025-06-18T10:00:00Z"
                }
            }
        },
        "models.UpdateTaskRequest": {
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "example": "Updated Task 1 description"
                },
                "status": {
                    "type": "string",
                    "example": "completed"
                },
                "title": {
                    "type": "string",
                    "example": "Updated Task 1"
                }
            }
        }
    },
    "securityDefinitions": {
        "BearerAuth": {
            "description": "Type \"Bearer\" followed by a space and JWT token.\"",
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "",
	BasePath:         "",
	Schemes:          []string{},
	Title:            "iShare Task Management API",
	Description:      "Professional, production-quality RESTful API for task management with OAuth2 and iSHARE compliance.",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
