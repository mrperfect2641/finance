# Personal Finance Tracker

A web-based personal finance tracking application built with Python Flask and SQLite.

## Features

- User authentication (login/register)
- Track income and expenses
- Categorize transactions
- View transaction history
- Responsive design

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd finance-tracker
```

2. Create a virtual environment (optional but recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

## Running the Application

1. Make sure you're in the project directory and your virtual environment is activated (if using one)

2. Run the Flask application:
```bash
python app.py
```

3. Open your web browser and navigate to:
```
http://localhost:5000
```

## Usage

1. Register a new account or login with existing credentials
2. Add transactions using the form on the dashboard
3. View your transaction history in the table
4. Track your income and expenses by category

## Project Structure

```
finance-tracker/
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── static/            # Static files (CSS, JS)
│   └── style.css
├── templates/         # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
└── finance.db         # SQLite database (created automatically)
```

## Security Features

- Password hashing
- User session management
- Form validation
- SQL injection protection (using SQLAlchemy)

## Contributing

Feel free to submit issues and enhancement requests! 