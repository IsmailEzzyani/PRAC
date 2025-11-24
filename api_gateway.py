from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, validator
import secrets
import hashlib
import sqlite3
import os
from typing import Optional
import uvicorn

app = FastAPI(title="PRAC API Gateway")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development - restrict in production
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

# Password hashing
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password

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
        return v

class SignupData(BaseModel):
    username: str
    password: str
    email: EmailStr
    full_name: str
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters')
        return v
    
    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        return v

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
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def update_wallet(username: str, new_balance: float):
    conn = sqlite3.connect('prac.db')
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET wallet_usd = ? WHERE username = ?',
        (new_balance, username)
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
        'SELECT type, description, amount, currency, recipient, status, created_at FROM transactions WHERE username = ? ORDER BY created_at DESC',
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

# --- AUTH -------------------------------------------------

@app.post("/auth/login")
async def login(data: LoginData):
    user = get_user(data.username)
    
    if user and verify_password(data.password, user['password_hash']):
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
    password_hash = hash_password(data.password)
    user_id = create_user(data.username, password_hash, data.email, data.full_name)
    
    if user_id is None:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    
    return {
        "message": "User created successfully",
        "user": data.username,
        "user_data": {
            "full_name": data.full_name,
            "email": data.email
        }
    }

# --- LIVE RATES --------------------------------------------

@app.get("/rates")
async def get_rates():
    import random
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

    # Update balance
    new_balance = user["wallet_usd"] - data.amount
    update_wallet(data.username, new_balance)
    
    # Add transaction
    transaction = {
        "type": "sent",
        "to": data.recipient,
        "amount": data.amount,
        "currency": data.currency,
        "status": "Completed"
    }
    add_transaction(data.username, transaction)

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
        "description": f"{from_currency} to {to_currency}",
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