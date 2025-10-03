Redis-based Authentication System with Flask Web Interface

This project implements a secure user authentication and management system using Redis as the backend database and Flask for the web interface.

It was developed as part of a database programming course and awarded 40/40 (High Distinction) with feedback highlighting it as “skilfully constructed, efficient, with a flawless GUI and faultless documentation.”

🚀 Features

🔐 User registration with email validation and security questions

🔑 Secure password storage using salted bcrypt hashing

🔄 Password recovery via security questions

⏳ Rate limiting to prevent brute force attacks

🛠️ Admin functionality for exporting login logs (CSV)

📂 CSV import for test data

🌐 Flask-based GUI with session management

📦 Installation
1. Clone the repository

git clone https://github.com/joshpilcher/redis-auth-system.git

cd redis-auth-system

2. Create a virtual environment & install dependencies

python -m venv venv
source venv/bin/activate # Mac/Linux
venv\Scripts\activate # Windows

pip install -r requirements.txt

3. Configure environment variables

Copy the example file and update as needed:
cp .env.example .env

Default .env.example values:
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_USER=default
REDIS_PASSWORD=changeme

4. Run Redis

Local install or Docker:
docker run -d -p 6379:6379 redis

5. Start the app

python app.py

The app will run at: http://localhost:5000

🧪 Testing

A smoke test suite (smoke_test.py) is included to verify:

Registration & duplicate prevention

Login & session management

Password recovery flow

Rate limiting (login & security questions)

Admin login & CSV export

Run with:
python smoke_test.py

📂 Project Structure

redis-auth-system/
├── app.py # Main Flask app
├── smoke_test.py # Automated smoke tests
├── sample_data.csv # Example CSV data template
├── .env.example # Example environment config
├── .gitignore
└── templates/ # HTML templates

⚖️ License

MIT License – feel free to use and adapt for learning purposes.
