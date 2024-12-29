# Chirpy

## Overview

Chirpy is a modern, lightweight microblogging platform designed for simplicity, scalability, and secure user interactions. It enables users to post short messages called "chirps," interact with other users, and manage their accounts with robust authentication and security features. Built with Go, Chirpy is a practical project for those looking to understand backend development and RESTful APIs.

### Features
- **Post Chirps**: Users can create, retrieve, update, and delete chirps.
- **User Management**: Secure user registration, login, and profile updates.
- **JWT Authentication**: Implements JSON Web Tokens for secure session management.
- **Admin Monitoring**: Includes metrics and reset functionality for administrators.
- **Token Management**: Handles access tokens, refresh tokens, and token revocation.
- **RESTful API**: Well-structured API for seamless integration.

## Why Use Chirpy?

Chirpy is more than just a microblogging platform; it’s a playground for learning modern backend development. Whether you’re a student, a developer, or a tech enthusiast, Chirpy offers:
- **Learning Opportunity**: Explore Go programming, PostgreSQL integration, and authentication practices.
- **Scalability**: Use Chirpy as a base for building scalable and secure web applications.
- **Customizability**: A clear and modular codebase makes it easy to adapt Chirpy to your needs.

## Installation and Setup

### Prerequisites
- **Go 1.17+**: Ensure you have Go installed. [Download Go](https://golang.org/dl/)
- **PostgreSQL**: Install and configure a PostgreSQL database.
- **Environment Variables**: Create a `.env` file with the following keys:
  - `DB_URL`: Database connection string.
  - `PLATFORM`: Set to `dev` for development mode.
  - `JWT_SECRET`: Secret key for JWT signing.
  - `POLKA_KEY`: API key for webhook integrations.

### Steps to Run Chirpy
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd chirpy
   ```
2. Install dependencies:
   ```bash
   go mod tidy
   ```
3. Set up the database:
   - Run the provided SQL migrations.
   - Update your `.env` file with the database URL.
4. Start the application:
   ```bash
   go run main.go
   ```
5. Access the platform:
   - API Health Check: `http://localhost:8080/api/healthz`
   - API Endpoints: Use tools like Postman or cURL to interact with the REST API.

### Testing
To run the test suite:
```bash
go test ./internal/...
```

## API Endpoints

### Public Endpoints
- `POST /api/users`: Register a new user.
- `POST /api/login`: Authenticate and get a token.

### Protected Endpoints
- `GET /api/chirps`: Retrieve all chirps.
- `POST /api/chirps`: Create a new chirp.
- `GET /api/chirps/{chirpID}`: Get a specific chirp.
- `PUT /api/users`: Update user details.
- `POST /api/refresh`: Refresh authentication tokens.

### Admin Endpoints
- `GET /admin/metrics`: View metrics.
- `POST /admin/reset`: Reset application state (dev mode only).

## How It Works

1. **Authentication**:
   - Users register with an email and password.
   - Passwords are hashed securely before storage.
   - JWTs are issued upon login and refreshed via secure tokens.

2. **Chirping**:
   - Chirps are capped at 140 characters.
   - Offensive words are sanitized automatically.

3. **Admin Controls**:
   - Metrics display the number of visits.
   - Admins can reset user and chirp data in development mode.

## Contribution Guidelines

We welcome contributions! To contribute:
1. Fork the repository.
2. Create a feature branch.
3. Submit a pull request describing your changes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

Enjoy using Chirpy! If you have questions, suggestions, or feedback, please get in touch.