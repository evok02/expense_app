# Expense Sharing Application

## Overview

This project is a web-based application designed to help users manage and share their expense statistics. Users can log their expenses, view statistics, and share these statistics with other users. The application uses Flask as the web framework and SQLAlchemy for database management.

## Features

- User authentication (login and registration)
- Expense logging and management
- Viewing expense statistics by category
- Sharing expense statistics with other users

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/evok02/expense_app.git
    ```

2. Create a virtual environment and activate it:

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```
4. Initialize the Databease:

    Open a Python shell and run the following commands to create the database tables:

   ```bash
    from app import app
    from app import db
    with app.app_context():
        db.create_all()
   
## Running the Application

To run the application, use the Flask development server:

```bash
flask run
```

The application will be accessible at http://127.0.0.1:5000/.
