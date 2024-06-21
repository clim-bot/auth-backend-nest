# Auth Backend with NestJS, SQLite, and MailHog

This project is an authentication backend built with NestJS, Sequelize, SQLite, and MailHog for email testing. It includes registration, login, password reset, and email verification functionalities.

## Features

- User registration with email verification
- User login with JWT authentication
- Password reset via email
- Profile management
- Change password functionality
- Email capture with MailHog

## Prerequisites

- Docker
- Docker Compose

## Environment Variables

Create a `.env` file in the root of the project with the following content:

```env
JWT_SECRET=yourjwtsecret
CLIENT_URL=http://localhost:3000
SMTP_HOST=mailhog
SMTP_PORT=1025
EMAIL_USER=
EMAIL_PASS=
SQLITE_STORAGE=/data/database.sqlite
```

## Getting Started
1. Clone the repostiory
```bash
git clone https://github.com/clim-bot/auth-backend-nest.git
cd auth-backend-node
```

2. Create a `data` directory
```bash
mkdir data
```

3. Build and run the Docker containers
```bash
docker-compose up --build
```

4. Access the services
- Node.js application: `http://localhost:8080`
- MailHog web interface: `http://localhost:8025`

## Project Structure
```js
auth-backend-node/
├── config/
│   └── database.js
├── controllers/
│   ├── authController.js
├── middleware/
│   └── authMiddleware.js
├── models/
│   └── user.js
├── routes/
│   └── routes.js
├── data/
│   └── database.sqlite
├── .env
├── app.js
├── Dockerfile
├── docker-compose.yml
├── package.json
├── package-lock.json
└── nodemon.json
```

## API Endpoints

### Authentication
- POST /auth/register
    - Register a new user
    - Request body: { "name": "John Doe", "email": "john@example.com", "password": "password123" }

- POST /auth/activate-account
    - Activate user account
    - Request body: { "token": "activation_token" }

- POST /auth/login
    - User login
    - Request body: { "email": "john@example.com", "password": "password123" }

- POST /auth/forgot-password
    - Request password reset
    - Request body: { "email": "john@example.com" }

- POST /auth/reset-password
    - Reset password
    - Request body: { "token": "reset_token", "newPassword": "newpassword123", "confirmPassword": "newpassword123" }

### Profile
- GET /profile
    - Get user profile
    - Requires JWT token

- POST /profile/change-password
    - Change user password
    - Requires JWT token
    - Request body: { "oldPassword": "oldpassword123", "newPassword": "newpassword123", "confirmPassword": "newpassword123" }

## License
This project is licensed under the MIT License.

