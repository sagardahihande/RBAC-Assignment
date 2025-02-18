# RBAC-Assignment
RBAC Authentication System
A secure Role-Based Access Control (RBAC) system built with Node.js, Express, and MongoDB. This project implements authentication, authorization, and role-based access to ensure users can register, log in, and access resources based on their roles (Admin, User, Moderator).

Features
User Authentication: Secure registration and login with password hashing.
JWT-Based Authorization: JSON Web Tokens (JWT) for secure session management.
Role-Based Access Control (RBAC): Access control based on user roles (Admin, User, Moderator).
Secure Routes: Protection of endpoints to ensure only authorized users can access them.
Environment Configuration: Use of .env files for storing environment variables securely.


Installation
Clone the repository:

git clone https://github.com/your-username/rbac-assignment.git
cd rbac-assignment


Install dependencies:

npm install

Set up environment variables: Create a .env file in the root directory and add:

PORT=5000
MONGO_URI=mongodb://localhost:27017/rbac_db      # Or your MongoDB Atlas connection string
JWT_SECRET=your_jwt_secret                       # Replace with a strong secret


Start the server:
node server.js
The server will run at http://localhost:5000.



API Endpoints
User Registration
POST /api/auth/register

Body:

{
  "username": "example",
  "password": "password123",
  "role": "User"  // Optional (default is 'User')
}

Response: User registration confirmation.

User Login

POST /api/auth/login
Body:
{
  "username": "example",
  "password": "password123"
}

Response: JWT token.

GET /api/auth/admin
Header:
Authorization: Bearer <JWT token>

Response: Access granted message for Admins.


Technologies Used
Node.js: JavaScript runtime environment.
Express.js: Web framework for Node.js.
MongoDB: NoSQL database for data storage.
Mongoose: ODM for MongoDB.
JWT: For token-based authentication.
bcrypt.js: Password hashing.

