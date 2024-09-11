# Apps Management System (AutonomousTech Test)

## Overview

The Apps Management System is a Django-based application designed to manage subscriptions for various applications. It provides functionalities for user registration, application creation, subscription management, and plan assignment. The system supports different subscription plans (Free, Standard, Pro) and allows users to subscribe their applications to these plans.

## Features

- **User Authentication**: Users can register, log in, and log out.
- **Application Management**: Users can create, update, view, and delete their applications.
- **Subscription Plans**: The system supports multiple subscription plans (Free, Standard, Pro), each with different pricing.
- **Subscription Management**: Users can subscribe their applications to available plans and manage these subscriptions.
- **Automated Plan Assignment**: New applications are automatically assigned to the Free plan upon creation.
- **API Integration**: RESTful APIs are provided for interacting with the system's resources, including applications, subscriptions, and plans.

## Installation

### Prerequisites

- Python 3.x
- Django 4.x
- Django REST Framework

### Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Anas-KhanWP/autonomoustech_test.git
   cd autonomoustech_test

2. **Create a Virtual Environment**
   ```bash
    python3 -m venv venv
    source venv/bin/activate   # On Windows, use `venv\Scripts\activate`

3. **Install Dependencies**
    ```bash
    pip install -r requirements.txt

4. **Apply Migrations**
    ```bash
    python manage.py makemigrations
    python manage.py migrate

5. **Create Superuser**
    ```bash
    python manage.py createsuperuser

6. **Run the Tests**
    ```bash
    python manage.py test
    ```
    ![image](https://github.com/user-attachments/assets/bc626185-983f-408f-a79f-bcff7e941df7)

7. **Run the Server**
    ```bash
    python manage.py runserver

8. **Access the Application**
   - Open your browser and navigate to http://127.0.0.1:8000/api/login
  
## API Endpoints

The application provides the following RESTful API endpoints:

### User Authentication
- **Register:** `POST /api/register/`
- **Login:** `POST /api/login/`
- **Logout:** `POST /api/logout/`

### Application Management
- **List/Create Applications:** `GET/POST /api/apps/`
- **Retrieve/Update/Delete Application:** `GET/PUT/DELETE /api/apps/<id>/`

### Subscription Management
- **Create Subscription:** `POST /api/subscriptions/`
- **Retrieve/Update Subscription:** `GET/PUT /api/subscriptions/<id>/`

### Plan Management
- **List Plans:** `GET /api/plans/`

## Models

### Plan
Represents a subscription plan with different tiers:
- `name`: Name of the plan (e.g., Free, Standard, Pro).
- `price`: Price of the plan.

### App
Represents an application owned by a user:
- `name`: Name of the application.
- `description`: Brief description of the application.
- `user`: The user who owns the application.

### Subscriptions
Represents a subscription relationship between an application and a plan:
- `app`: The application being subscribed.
- `plan`: The subscription plan.
- `active`: Boolean indicating if the subscription is active.

## Signals

### `create_subscriptions`
Automatically assigns a free plan to a new application upon creation.

### `create_default_plans`
Creates default plans (Free, Standard, Pro) when the system is migrated.

## Docker Deployment
This project is Docker-ready, making deployment simple and consistent across different environments. Follow the steps below to deploy the application using Docker:
- ```bash
    docker-compose run web python manage.py migrate
    ```

- ```bash
    docker-compose up
    ```

The application will now be accessible at http://localhost:8000/.

## Contact

For any inquiries or feedback, please contact [Email](mailto:anaskhanwp@gmail.com) or [WhatsApp](https://api.whatsapp.com/send?phone=+923152460477&text=Hello).
