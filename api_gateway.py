from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, validator
import secrets
import hashlib
import sqlite3
import os
from typing import Optional
import uvicorn
import bcrypt
import random
from datetime import datetime, timedelta

app = FastAPI(title="PRAC API Gateway")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
def init_db():
    conn = sqlite3.connect('prac.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            wallet_usd REAL DEFAULT 1000.00,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            type TEXT NOT NULL,
            description TEXT,
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'USD',
            recipient TEXT,
            status TEXT DEFAULT 'Completed',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# Password hashing with bcrypt
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

# Data models with validation
class LoginData(BaseModel):
    username: str
    password: str

class SendData(BaseModel):
    username: str
    amount: float
    recipient: str
    currency: str = "USD"
    
    @validator('amount')
    def validate_amount(cls, v):
        if v <= 0:
            raise ValueError('Amount must be positive')
        if v > 1000000:  # Reasonable limit
            raise ValueError('Amount too large')
        return round(v, 2)

class SignupData(BaseModel):
    username: str
    password: str
    email: EmailStr
    full_name: str
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters')
        if len(v) > 100:
            raise ValueError('Password too long')
        return v
    
    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        if not v.isalnum():
            raise ValueError('Username must contain only letters and numbers')
        return v
    
    @validator('full_name')
    def validate_full_name(cls, v):
        if len(v) < 2:
            raise ValueError('Full name must be at least 2 characters')
        if len(v) > 100:
            raise ValueError('Full name too long')
        return v.strip()

# Database helper functions
def get_user(username: str):
    conn = sqlite3.connect('prac.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {
            'id': user[0],
            'username': user[1],
            'password_hash': user[2],
            'email': user[3],
            'full_name': user[4],
            'wallet_usd': user[5]
        }
    return None

def get_user_by_email(email: str):
    conn = sqlite3.connect('prac.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {
            'id': user[0],
            'username': user[1],
            'password_hash': user[2],
            'email': user[3],
            'full_name': user[4],
            'wallet_usd': user[5]
        }
    return None

def create_user(username: str, password_hash: str, email: str, full_name: str):
    conn = sqlite3.connect('prac.db')
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash, email, full_name) VALUES (?, ?, ?, ?)',
            (username, password_hash, email, full_name)
        )
        user_id = cursor.lastrowid
        conn.commit()
        
        # Add welcome transaction
        cursor.execute(
            'INSERT INTO transactions (username, type, description, amount, currency) VALUES (?, ?, ?, ?, ?)',
            (username, 'welcome', 'Welcome bonus', 1000.00, 'USD')
        )
        conn.commit()
        return user_id
    except sqlite3.IntegrityError as e:
        return None
    finally:
        conn.close()

def update_wallet(username: str, new_balance: float):
    conn = sqlite3.connect('prac.db')
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET wallet_usd = ? WHERE username = ?',
        (round(new_balance, 2), username)
    )
    conn.commit()
    conn.close()

def add_transaction(username: str, transaction_data: dict):
    conn = sqlite3.connect('prac.db')
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO transactions (username, type, description, amount, currency, recipient, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (username, transaction_data['type'], transaction_data.get('description'), 
         transaction_data['amount'], transaction_data.get('currency', 'USD'),
         transaction_data.get('recipient'), transaction_data.get('status', 'Completed'))
    )
    conn.commit()
    conn.close()

def get_transactions(username: str):
    conn = sqlite3.connect('prac.db')
    cursor = conn.cursor()
    cursor.execute(
        'SELECT type, description, amount, currency, recipient, status, created_at FROM transactions WHERE username = ? ORDER BY created_at DESC LIMIT 50',
        (username,)
    )
    transactions = cursor.fetchall()
    conn.close()
    
    return [
        {
            'type': t[0],
            'description': t[1],
            'amount': t[2],
            'currency': t[3],
            'recipient': t[4],
            'status': t[5],
            'date': t[6]
        }
        for t in transactions
    ]

# Session management
def create_session(user_id: int):
    conn = sqlite3.connect('prac.db')
    cursor = conn.cursor()
    session_token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(days=7)
    
    cursor.execute(
        'INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)',
        (user_id, session_token, expires_at)
    )
    conn.commit()
    conn.close()
    return session_token

def validate_session(session_token: str):
    conn = sqlite3.connect('prac.db')
    cursor = conn.cursor()
    cursor.execute(
        'SELECT user_id FROM sessions WHERE session_token = ? AND expires_at > ?',
        (session_token, datetime.now())
    )
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

# --- AUTH -------------------------------------------------

@app.post("/auth/login")
async def login(data: LoginData, response: Response):
    user = get_user(data.username)
    
    if user and verify_password(data.password, user['password_hash']):
        session_token = create_session(user['id'])
        response.set_cookie(
            key="session_token",
            value=session_token,
            httponly=True,
            max_age=7*24*60*60,  # 7 days
            samesite="lax"
        )
        
        return {
            "message": "Success", 
            "user": user['username'],
            "user_data": {
                "full_name": user['full_name'],
                "email": user['email']
            }
        }

    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/auth/signup")
async def signup(data: SignupData):
    # Check if username or email already exists
    if get_user(data.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    
    if get_user_by_email(data.email):
        raise HTTPException(status_code=400, detail="Email already exists")
    
    password_hash = hash_password(data.password)
    user_id = create_user(data.username, password_hash, data.email, data.full_name)
    
    if user_id is None:
        raise HTTPException(status_code=400, detail="Registration failed")
    
    return {
        "message": "User created successfully",
        "user": data.username,
        "user_data": {
            "full_name": data.full_name,
            "email": data.email
        }
    }

@app.post("/auth/logout")
async def logout(response: Response, request: Request):
    session_token = request.cookies.get("session_token")
    if session_token:
        # Remove session from database
        conn = sqlite3.connect('prac.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
        conn.commit()
        conn.close()
    
    response.delete_cookie("session_token")
    return {"message": "Logged out successfully"}

# --- LIVE RATES --------------------------------------------

@app.get("/rates")
async def get_rates():
    base_rates = {
        "USD_EUR": 0.93,
        "USD_GBP": 0.79,
        "USD_MAD": 10.25,
        "EUR_USD": 1.08,
        "USD_JPY": 148.5,
        "USD_CAD": 1.35,
        "USD_AUD": 1.52
    }
    
    varied_rates = {}
    for pair, rate in base_rates.items():
        variation = random.uniform(-0.01, 0.01)
        varied_rates[pair] = round(rate + (rate * variation), 4)
    
    return varied_rates

@app.get("/rates/all")
async def get_all_rates():
    base_rates = {
        "USD": 1.000000,
        "EUR": 0.930000,
        "GBP": 0.790000,
        "JPY": 148.500000,
        "CAD": 1.350000,
        "AUD": 1.520000,
        "CHF": 0.880000,
        "CNY": 7.250000,
        "INR": 83.000000,
        "MXN": 17.500000,
        "BRL": 5.200000,
        "RUB": 92.000000,
        "KRW": 1320.000000,
        "SGD": 1.340000,
        "NZD": 1.630000,
        "SEK": 10.500000,
        "NOK": 10.800000,
        "DKK": 6.900000,
        "ZAR": 18.800000,
        "HKD": 7.820000,
        "TRY": 32.000000,
        "AED": 3.670000,
        "SAR": 3.750000,
        "THB": 36.000000,
        "MYR": 4.720000,
        "IDR": 15600.000000,
        "PHP": 56.500000,
        "PLN": 4.200000,
        "CZK": 23.000000,
        "HUF": 360.000000,
        "ILS": 3.700000,
        "EGP": 30.900000,
        "NGN": 1600.000000,
        "ARS": 850.000000,
        "CLP": 950.000000,
        "COP": 3900.000000,
        "PEN": 3.800000,
        "VND": 24750.000000,
        "PKR": 280.000000,
        "BDT": 110.000000,
        "LKR": 320.000000,
        "MAD": 10.250000
    }
    
    # Add some random variation
    varied_rates = {}
    for currency, rate in base_rates.items():
        variation = random.uniform(-0.02, 0.02)
        varied_rates[currency] = round(rate + (rate * variation), 6)
    
    return varied_rates

# --- WALLET -------------------------------------------------

@app.get("/wallet/{username}")
async def get_wallet(username: str):
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    transactions = get_transactions(username)
    
    return {
        "balance_usd": user["wallet_usd"],
        "wallets": [
            {"currency": "USD", "amount": user["wallet_usd"], "symbol": "$"},
            {"currency": "EUR", "amount": round(user["wallet_usd"] * 0.93, 2), "symbol": "€"},
            {"currency": "GBP", "amount": round(user["wallet_usd"] * 0.79, 2), "symbol": "£"}
        ],
        "user_info": {
            "full_name": user["full_name"],
            "email": user["email"]
        },
        "transactions": transactions
    }

@app.get("/transactions/{username}")
async def get_user_transactions(username: str):
    if not get_user(username):
        raise HTTPException(status_code=404, detail="User not found")
    
    transactions = get_transactions(username)
    return {"transactions": transactions}

# --- SEND MONEY --------------------------------------------

@app.post("/wallet/send")
async def send(data: SendData):
    user = get_user(data.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user["wallet_usd"] < data.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")

    # Check if recipient exists
    recipient_user = get_user(data.recipient)
    if not recipient_user:
        raise HTTPException(status_code=404, detail="Recipient not found")

    # Update sender balance
    new_balance = user["wallet_usd"] - data.amount
    update_wallet(data.username, new_balance)
    
    # Update recipient balance
    recipient_new_balance = recipient_user["wallet_usd"] + data.amount
    update_wallet(data.recipient, recipient_new_balance)
    
    # Add transaction for sender
    transaction = {
        "type": "sent",
        "description": f"Sent to {data.recipient}",
        "amount": data.amount,
        "currency": data.currency,
        "recipient": data.recipient,
        "status": "Completed"
    }
    add_transaction(data.username, transaction)
    
    # Add transaction for recipient
    receive_transaction = {
        "type": "received",
        "description": f"Received from {data.username}",
        "amount": data.amount,
        "currency": data.currency,
        "recipient": data.username,
        "status": "Completed"
    }
    add_transaction(data.recipient, receive_transaction)

    return {
        "status": "success",
        "new_balance": new_balance,
        "transaction": transaction
    }

@app.post("/wallet/convert")
async def convert_currency(data: dict):
    username = data.get("username")
    from_currency = data.get("from_currency", "USD")
    to_currency = data.get("to_currency", "EUR")
    amount = data.get("amount", 0)
    
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    
    if user["wallet_usd"] < amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")
    
    conversion_rates = {
        "USD_EUR": 0.93,
        "USD_GBP": 0.79,
        "EUR_USD": 1.08,
        "EUR_GBP": 0.85,
        "GBP_USD": 1.27,
        "GBP_EUR": 1.18
    }
    
    rate_key = f"{from_currency}_{to_currency}"
    if rate_key not in conversion_rates:
        raise HTTPException(status_code=400, detail="Conversion not supported")
    
    converted_amount = amount * conversion_rates[rate_key]
    
    # Update wallet
    new_balance = user["wallet_usd"] - amount
    update_wallet(username, new_balance)
    
    # Add transaction
    transaction = {
        "type": "conversion",
        "description": f"Converted {amount} {from_currency} to {to_currency}",
        "amount": converted_amount,
        "currency": to_currency,
        "status": "Completed"
    }
    add_transaction(username, transaction)

    return {
        "status": "success",
        "converted_amount": converted_amount,
        "rate": conversion_rates[rate_key],
        "new_balance": new_balance,
        "transaction": transaction
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)