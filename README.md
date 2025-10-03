# Redis-based Authentication System with Flask Web Interface

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)  
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?logo=flask&logoColor=black)  
![Redis](https://img.shields.io/badge/Redis-5.0-red?logo=redis&logoColor=white)  
![License: MIT](https://img.shields.io/badge/License-MIT-green)  

This project implements a secure user authentication and management system using **Redis** as the backend database and **Flask** for the web interface.  

It was developed as part of a database programming course and awarded **40/40 (High Distinction)**.  

---

## 🚀 Features

- User registration with email validation and security questions  
- Secure password storage using salted bcrypt hashing  
- Password recovery via security questions  
- Rate limiting to prevent brute force attacks  
- Admin functionality for exporting login logs (CSV)  
- CSV import for test data  
- Flask-based GUI with session management  

---

## 📦 Installation

### 1. Clone the repository
```bash
git clone https://github.com/joshpilcher/redis-auth-system.git
cd redis-auth-system
```

### 2. Create a virtual environment & install dependencies
```bash
python -m venv venv
source venv/bin/activate   # Mac/Linux
venv\Scripts\activate      # Windows

pip install -r requirements.txt
```

### 3. Configure environment variables
Copy the example file and update as needed:
```bash
cp .env.example .env
```

Default `.env.example` values:
```ini
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_USER=default
REDIS_PASSWORD=changeme
```

### 4. Run Redis
Local install or Docker:
```bash
docker run -d -p 6379:6379 redis
```

### 5. Start the app
```bash
python app.py
```

The app will run at: [http://localhost:5000](http://localhost:5000)  

---

## 🧪 Testing

A smoke test suite (`smoke_test.py`) is included to verify:  

- Registration & duplicate prevention  
- Login & session management  
- Password recovery flow  
- Rate limiting (login & security questions)  
- Admin login & CSV export  

Run with:
```bash
python smoke_test.py
```

---

## 📂 Project Structure

```text
redis-auth-system/
│
├── app.py              # Main Flask app
├── smoke_test.py       # Automated smoke tests
├── sample_data.csv     # Example CSV data template
├── requirements.txt    # Project dependencies
├── .env.example        # Example environment config
├── .gitignore
└── templates/          # HTML templates
    ├── base.html
    ├── dashboard.html
    ├── forgot_password.html
    ├── index.html
    ├── login.html
    └── register.html
```

---

## 🏆 Achievement

- Awarded **40/40 (High Distinction)** in Database Programming  

---

## ⚖️ License

MIT License – feel free to use and adapt for learning purposes.  
