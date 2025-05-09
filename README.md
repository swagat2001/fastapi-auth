# FastAPI Authentication System

A robust, production-ready authentication system built with FastAPI. This project demonstrates secure user authentication, JWT-based authorization, password management, rate limiting, and security best practices. Ideal for real-world applications and as a portfolio/interview showcase.

---

## Features

- **User Registration** with strong password validation
- **User Login** with JWT access token generation
- **Protected User Profile** endpoint
- **Change Password** (authenticated)
- **Password Reset** (request and confirm, with secure token)
- **Rate Limiting** per IP
- **Comprehensive Logging**
- **Async/await** for high performance
- **Robust Error Handling** with proper HTTP status codes
- **Pydantic Models** for request/response validation
- **In-memory user store** (easy to swap for a real database)

---

## Technology Stack

- [FastAPI](https://fastapi.tiangolo.com/)
- [Pydantic](https://pydantic-docs.helpmanual.io/)
- [python-jose](https://python-jose.readthedocs.io/) (JWT)
- [passlib](https://passlib.readthedocs.io/) (Password hashing)
- [Uvicorn](https://www.uvicorn.org/) (ASGI server)

---

## Setup & Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/swagat2001/fastapi-auth.git
   cd fastapi-auth
   ```

2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

3. **Run the FastAPI server:**
   ```sh
   uvicorn auth:app --reload
   ```

4. **Open the interactive API docs:**
   - Visit [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) in your browser.

---

## API Endpoints

### Authentication

- `POST /auth/register`  
  Register a new user.  
  **Body:**  
  ```json
  {
    "username": "yourusername",
    "password": "StrongPassword123!"
  }
  ```

- `POST /auth/login`  
  Authenticate and receive a JWT token.  
  **Body:**  
  ```json
  {
    "username": "yourusername",
    "password": "StrongPassword123!"
  }
  ```

- `GET /auth/me`  
  Get current user info (JWT required in `Authorization: Bearer <token>` header).

- `POST /auth/change-password`  
  Change password (JWT required).  
  **Body:**  
  ```json
  {
    "old_password": "OldPassword123!",
    "new_password": "NewStrongPassword123!"
  }
  ```

### Password Reset

- `POST /auth/request-password-reset`  
  Request a password reset token.  
  **Body:**  
  ```json
  {
    "username": "yourusername"
  }
  ```
  *In production, the token would be emailed. Here, it's returned in the response.*

- `POST /auth/confirm-password-reset`  
  Reset password using the token.  
  **Body:**  
  ```json
  {
    "reset_token": "<token>",
    "new_password": "NewStrongPassword123!"
  }
  ```

---

## Example Usage

### Register a User

```sh
curl -X POST "http://127.0.0.1:8000/auth/register" -H "Content-Type: application/json" -d "{\"username\": \"alice\", \"password\": \"SuperSecret123!\"}"
```

### Login

```sh
curl -X POST "http://127.0.0.1:8000/auth/login" -H "Content-Type: application/json" -d "{\"username\": \"alice\", \"password\": \"SuperSecret123!\"}"
```

### Access Protected Route

```sh
curl -X GET "http://127.0.0.1:8000/auth/me" -H "Authorization: Bearer <access_token>"
```

---

## Security Notes

- **Do not use the default `SECRET_KEY` in production.** Replace it with a strong, random value.
- The in-memory user store is for demonstration only. Use a persistent database in production.
- Rate limiting is in-memory and per-process. For distributed systems, use Redis or similar.
- Password reset tokens are JWTs with a short expiry for demo purposes.

---

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

---

## License

This project is licensed under the MIT License.
