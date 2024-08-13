# IReporter App

## Overview

The IReporter App is a Flask-based server for managing redflags and interventions. It includes features for user authentication, token verification, and role-based access control. The application integrates with Cloudinary for media uploads and uses JSON Web Tokens (JWT) for secure API access.

## Features

- User authentication and JWT-based session management
- User and admin roles with specific access permissions
- Upload and management of redflags and interventions with media support
- Token-based verification for user accounts
- Admin functionality for updating user roles and status

## Setup

### Prerequisites

- Python 3.8 or higher
- Virtualenv
- Flask
- SQLAlchemy
- Cloudinary

### Installation

1. **Clone the repository:**

    ```bash
    git clone git@github.com:john7319/IReporter-server.git
    cd ireporter-app
    ```

2. **Create and activate a virtual environment:**

    ```Terminal
    pipenv --python /usr/bin/python
    pipenv shell
    ```

3. **Install the dependencies:**

    ```
    pipenv install
    ```

4. **Set up environment variables:**

    Create a `.env` file in the root directory and add the following:

    ```env
    DATABASE_URI=your_database_uri
    CLOUD_NAME=your_cloud_name
    API_KEY=your_api_key
    API_SECRET=your_api_secret
    ```

5. **Initialize the database:**

    ```bash
    flask db upgrade
    ```

6. **Run the application:**

    ```bash
    flask run
    ```


## API Endpoints

### Authentication

- **Login**

  `POST /login`

  Request body:
    ```json
    {
        "email": "user@example.com",
        "password": "your_password"
    }

    Response:
    {
    "access_token": "your_jwt_token"
    }
-  **Check Session**

    `GET /check_session`

    Requires JWT in the Authorization header.
    ``` json
    Response:
    
    {
        "id": 1,
        "name": "User Name",
        "email": "user@example.com",
        "image": "image_url",
        "role": "user",
        "intervention": [/* ... */],
        "redflags": [/* ... */],
        "token_verified": true,
        "is_active": true,
        "requesting_admin": false
    }
    ```

    ### Users

    `GET /users`
    ```json
    Response:
    
        [
        {
            "id": 1,
            "name": "User Name",
            "email": "user@example.com",
            "role": "user",
            "token_verified": true,
            "is_active": true,
            "requesting_admin": false
        }
        ]
    ```
    ### Create User

    `POST /users`
    ```json
    Request body:

        {
        "name": "New User",
        "email": "newuser@example.com",
        "password": "new_password"
        }


    Response:

        {
        "success": "User created successfully! Verification token sent to email.",
        "user": {
            "id": 2,
            "name": "New User",
            "email": "newuser@example.com",
            "role": "user",
            "token_verified": false,
            "is_active": true
        }
        }
    ```

    ### Update User

    `PATCH /users/<int:user_id>`
    ```json
    Request body:

        {
        "email": "updateduser@example.com",
        "image": "new_image_url",
        "old_password": "current_password",
        "new_password": "new_password"
        }
    Response:

        {
        "success": "User updated successfully.",
        "user": {
            "id": 1,
            "name": "Updated User",
            "email": "updateduser@example.com",
            "role": "user",
            "token_verified": true,
            "is_active": true
        }
        }
    ```

    ## Admin Endpoints
    ### Update Token Verification

    `PATCH /admin/users/<int:user_id>/update-token`
    ```json
    Request body:
        {
        "token_verified": true
        }
    Response:
        {
        "success": "User token verification status updated successfully."
        }
    ```
    
    ### Update User Status

    `PATCH /admin/users/<int:user_id>/update-status`
    ```json
    Request body:
    {
    "is_active": false
    }
    Response:
    {
    "success": "User status updated successfully."
    }
    ```


## Contributing

We welcome contributions to the IReporter App! If you'd like to contribute, please follow these guidelines:

1. **Fork the Repository**
   - Click on the "Fork" button at the top right of the repository page to create your own copy of the project.

2. **Create a New Branch**
   - Navigate to your forked repository and create a new branch for your feature or bug fix. Use a descriptive name for your branch, e.g., `feature/new-feature`.

3. **Make Your Changes**
   - Implement your changes and make sure to write clear and concise commit messages. Follow the existing code style and conventions of the project.

4. **Test Thoroughly**
   - Ensure that your changes are well-tested. Run all existing tests and write new tests if necessary to cover your modifications.

5. **Submit a Pull Request**
   - Go to the "Pull Requests" section of the original repository and click "New Pull Request." Select your branch and provide a detailed description of your changes. Explain why the changes are necessary and how they improve the project.

6. **Review Process**
   - Your pull request will be reviewed. Be prepared to make additional changes if requested.

Thank you for contributing to the IReporter App!
    
