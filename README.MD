# Project Management API

This project is a backend API built with Python using Django, FastAPI, PostgreSQL, and several other essential libraries like Pydantic, PyJWT, bcrypt, and more. The project supports user authentication via JWT and role-based access control (RBAC). It handles tasks such as creating, updating, and managing projects, along with providing functionality for users to interact with tasks and comments.

## Technologies Used

- **Python 3.x**
- **Django ORM**: For database management and interactions.
- **FastAPI**: A modern web framework for building APIs with Python.
- **PostgreSQL**: A relational database to store user data, projects, and tasks.
- **Uvicorn**: ASGI server for serving the FastAPI application.
- **Pydantic**: Data validation and settings management.
- **PyJWT**: JSON Web Token (JWT) for authentication.
- **bcrypt**: Password hashing library for secure password storage.

## Features

- JWT-based Authentication.
- Role-Based Access Control (RBAC) for user roles.
- CRUD operations for managing projects and tasks.
- Task and comment management for users.
- Secure password hashing using bcrypt.

## Setup Instructions

### 1. Clone the Repository

Clone the repository to your local machine using the following command:

```bash
git clone https://github.com/shoaibchauhan/project_management.git
```


### 2. Activate the virtual environment

On Windows:
```bash
venv\Scripts\activate
```

### 3.  Set Up PostgreSQL Database
Ensure PostgreSQL is installed and running on your system. Create a new database for the project:


CREATE DATABASE project_management_db;
Update your database settings in settings.py:

```bash
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'project_management_db',
        'USER': 'your_db_user',
        'PASSWORD': 'your_db_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```
### 4.  Run Migrations
Apply migrations to set up the database schema:

```bash
python manage.py makemigrations
python manage.py migrate
```
### 5. Start the Development Server
To run the server, use the following command:

```bash
uvicorn myapp.main:app --reload
```
This will start the FastAPI server at http://127.0.0.1:8000.

### 6. Access the API

Using swagger docs
http://127.0.0.1:8000/docs

## Dependencies
The following dependencies are used in this project:

- **Django**: Web framework for building backend applications.
- **FastAPI**: Web framework for building APIs.
- **Uvicorn**: ASGI server for running FastAPI applications.
- **PostgreSQL**: Relational database for storage.
- **Pydantic**: Data validation and settings management.
- **bcrypt**: Password hashing library.
- **PyJWT**: For encoding and decoding JWT tokens.
