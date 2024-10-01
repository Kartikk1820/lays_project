# Relative path: database.py
DATA_FILE = './data.json'


import sqlite3
from datetime import datetime
import json
import random
import string

def get_db_connection():
    conn = sqlite3.connect('database.db', timeout=10) 
    conn.execute('PRAGMA busy_timeout = 10000')
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            password TEXT NOT NULL,
            invitation_code TEXT,
            signup_time DATETIME NOT NULL,
            user_count INTEGER NOT NULL,
            logged_in INTEGER DEFAULT 0
        );
    ''')

    # Create wallets table with income_rate
    cursor.execute(''' 
        CREATE TABLE IF NOT EXISTS wallets (
            id INTEGER PRIMARY KEY,
            user_id TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0,
            income_rate REAL NOT NULL DEFAULT 0,  -- New column for income rate
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Create schemes table
    cursor.execute(''' 
        CREATE TABLE IF NOT EXISTS schemes (
            scheme_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            initial_deposit REAL NOT NULL,
            daily_rate REAL NOT NULL, -- This should be a percentage (e.g., 0.05 for 5%)
            time_duration INTEGER NOT NULL, -- Duration in days
            option TEXT CHECK(option IN ('A', 'B')) -- New column for options A or B
        );
    ''')

    # Create user_schemes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_schemes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            scheme_id INTEGER NOT NULL,
            start_time DATETIME NOT NULL,
            time_left INTEGER NOT NULL, -- Remaining days in the scheme
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (scheme_id) REFERENCES schemes (scheme_id) ON DELETE CASCADE
        );
    ''')

    # Create admin table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            logged_in INTEGER DEFAULT 0
        );
    ''')

    # Create central_pool table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS central_pool (
            id INTEGER PRIMARY KEY,
            balance REAL NOT NULL DEFAULT 0
        )
    ''')
    
    # Create pending_payments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pending_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            amount REAL NOT NULL,
            screenshot_url TEXT,
            pending INTEGER NOT NULL DEFAULT 1,  -- 1 for True, 0 for False
            type TEXT CHECK(type IN ('recharge', 'withdrawal')),  -- New column for type
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Initialize central pool if it does not exist
    cursor.execute("SELECT * FROM central_pool")
    if cursor.fetchone() is None:
        cursor.execute("INSERT INTO central_pool (balance) VALUES (?)", (0.0,))



    # Add default admin if not exists

    
    with open(DATA_FILE, 'r') as file:
        data = json.load(file)
        UPI_ID = data.get("payment_id", "")

        admin_credentials = data.get("admin_credentials", {})
        for admin in admin_credentials:
            default_admin_username = admin.get("id", "admin")
            default_admin_password = admin.get("password", "1234")

            cursor.execute("SELECT * FROM admins WHERE username = ?", (default_admin_username,))
            if cursor.fetchone() is None:
                # Hash the password for security
                hashed_password = hashlib.sha256(default_admin_password.encode()).hexdigest()
                cursor.execute("INSERT INTO admins (username, password) VALUES (?, ?)", 
                            (default_admin_username, hashed_password))


    # DEVELOPMENT ONLY
    
        
    # Add default user if not exists
    default_username = 'user'
    default_phone = '0000'
    default_password = '1'  # Ensure it's a string if the password column is TEXT
    cursor.execute("SELECT * FROM users WHERE name = ?", (default_username,))
    if cursor.fetchone() is None:
        user_id = generate_random_id()
        cursor.execute("INSERT INTO users (id, name, phone, password, invitation_code, signup_time, user_count) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                    (user_id, default_username, default_phone, default_password, None, datetime.now(), 1))
        cursor.execute("INSERT INTO wallets (user_id) VALUES (?)", (user_id,))
        
        
    # DEVELOPMENT ONLY ENDS

    # Check if the central pool already exists
    cursor.execute("SELECT * FROM central_pool WHERE id = 1")
    if str(cursor.fetchone()) == str(0):
        cursor.execute("INSERT INTO central_pool (id, balance) VALUES (1, 1000000)")  # Set initial balance


    load_schemes_from_json(cursor)

    conn.commit()
    init_payment_history_table()
    init_bank_details_table()
    conn.close()




def add_user(name, phone, password, invitation_code):
    signup_time = datetime.now()
    user_id = generate_random_id()  # Generate random ID
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Get current user count
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0] + 1  # Increment count

        cursor.execute("INSERT INTO users (id, name, phone, password, invitation_code, signup_time, user_count) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                       (user_id, name, phone, password, invitation_code, signup_time, user_count))
        conn.commit()
    
    return user_id  # Return the new user's ID


def get_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    return users

def get_user_by_identifier(identifier):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ? OR phone = ?", (identifier, identifier))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_wallet(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO wallets (user_id) VALUES (?)", (user_id,))  # Ensure user_id is passed
        conn.commit()


def get_wallet_by_user_id(user_id):
    with get_db_connection() as conn:    
        cursor = conn.cursor()
        cursor.execute("SELECT balance FROM wallets WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        return row['balance'] if row else 0

import hashlib

def add_admin(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Hash the password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    cursor.execute("INSERT INTO admins (username, password) VALUES (?, ?)", 
                   (username, hashed_password))
    conn.commit()
    conn.close()


def get_admin_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admins WHERE username = ?", (username,))
    admin = cursor.fetchone()
    conn.close()
    return admin

def get_users_with_wallets():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT users.id, users.name, users.phone, IFNULL(wallets.balance, 0) AS wallet_balance, users.signup_time
        FROM users
        LEFT JOIN wallets ON users.id = wallets.user_id
    ''')
    users = cursor.fetchall()
    conn.close()

    return users


def update_user(user_id, name, phone):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE users 
        SET name = ?, phone = ? 
        WHERE id = ?
    ''', (name, phone, user_id))

    conn.commit()
    conn.close()

def init_payment_history_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS payment_history (
            payment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            payer_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            payment_time DATETIME NOT NULL,
            amount REAL NOT NULL,
            FOREIGN KEY (payer_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

def record_payment(payer_id, receiver_id, amount, is_admin=False):
    payment_time = datetime.now()
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Insert the payment into the payment history
    cursor.execute(''' 
        INSERT INTO payment_history (payer_id, receiver_id, payment_time, amount) 
        VALUES (?, ?, ?, ?) 
    ''', (payer_id, receiver_id, payment_time, amount))

    if is_admin:
        # Update the central pool balance (when an admin is the payer)
        cursor.execute(''' 
            UPDATE central_pool 
            SET balance = balance - ? 
            WHERE id = 1  -- Assuming only one row in central_pool
        ''', (amount,))
        
        # Update receiver's wallet balance (if receiver is a user)
        cursor.execute(''' 
            UPDATE wallets 
            SET balance = balance + ? 
            WHERE user_id = ? 
        ''', (amount, receiver_id))
    else:
        # Update payer's wallet balance (deduct the amount)
        cursor.execute(''' 
            UPDATE wallets 
            SET balance = balance - ? 
            WHERE user_id = ? 
        ''', (amount, payer_id))

        # Check if receiver is an admin
        admin = get_admin_by_id(receiver_id)
        if admin:
            # If the receiver is an admin, update the central pool
            cursor.execute(''' 
                UPDATE central_pool 
                SET balance = balance + ? 
                WHERE id = 1 
            ''', (amount,))
        else:
            # Update receiver's wallet balance (add the amount)
            cursor.execute(''' 
                UPDATE wallets 
                SET balance = balance + ? 
                WHERE user_id = ? 
            ''', (amount, receiver_id))

    conn.commit()
    conn.close()


def get_payment_history(user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if user_id is None:
        cursor.execute('''
            SELECT payment_id, payer_id, receiver_id, payment_time, amount
            FROM payment_history
            ORDER BY payment_time DESC
        ''')
    else:
        cursor.execute('''
            SELECT payment_id, payer_id, receiver_id, payment_time, amount
            FROM payment_history
            WHERE payer_id = ? OR receiver_id = ?
            ORDER BY payment_time DESC
        ''', (user_id, user_id))

    payments = cursor.fetchall()
    conn.close()
    return payments



def set_user_logged_in(user_id, status):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET logged_in = ? WHERE id = ?", (status, user_id))
        conn.commit()

def set_admin_logged_in(admin_id, status):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE admins SET logged_in = ? WHERE id = ?", (status, admin_id))
        conn.commit()

def get_admin_by_id(admin_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admins WHERE id = ?", (admin_id,))
    admin = cursor.fetchone()
    conn.close()
    return admin

def get_central_pool_balance():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM central_pool WHERE id = 1")  # Assuming only one row
    balance = cursor.fetchone()
    conn.close()
    return balance['balance'] if balance else 0


def get_total_wallet_balance():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT SUM(balance) AS total_balance
        FROM wallets
    ''')
    total_balance = cursor.fetchone()['total_balance']
    conn.close()
    return total_balance if total_balance is not None else 0


def init_bank_details_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bank_details (
            user_id TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            bank_account TEXT NOT NULL,
            bank_name TEXT NOT NULL,
            ifsc TEXT NOT NULL,
            branch_name TEXT NOT NULL,
            withdrawal_password TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()



def get_bank_details(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM bank_details WHERE user_id = ?", (user_id,))
    bank_details = cursor.fetchone()
    conn.close()
    return bank_details


def update_bank_details(user_id, full_name, phone_number, bank_account, bank_name, ifsc, branch_name, withdrawal_password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO bank_details (user_id, full_name, phone_number, bank_account, bank_name, ifsc, branch_name, withdrawal_password)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            full_name = excluded.full_name,
            phone_number = excluded.phone_number,
            bank_account = excluded.bank_account,
            bank_name = excluded.bank_name,
            ifsc = excluded.ifsc,
            branch_name = excluded.branch_name,
            withdrawal_password = excluded.withdrawal_password
    ''', (str(user_id), str(full_name), str(phone_number), str(bank_account), str(bank_name), str(ifsc), str(branch_name), str(withdrawal_password)))
    conn.commit()
    conn.close()



def generate_random_id(length=16):
    characters = string.ascii_uppercase + string.digits + ''
    return ''.join(random.choice(characters) for _ in range(length))

def count_withdraws_and_recharges(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Sum payments made (withdraws)
    cursor.execute('''
        SELECT SUM(amount) AS total_withdraw
        FROM payment_history
        WHERE payer_id = ?
    ''', (user_id,))
    total_withdraw = cursor.fetchone()['total_withdraw'] or 0  # Default to 0 if None

    # Sum payments received (recharges), excluding rows where payer_id is 'scheme'
    cursor.execute('''
        SELECT SUM(amount) AS total_recharge
        FROM payment_history
        WHERE receiver_id = ? AND payer_id != 'scheme'
    ''', (user_id,))
    total_recharge = cursor.fetchone()['total_recharge'] or 0  # Default to 0 if None

    conn.close()
    return total_withdraw, total_recharge



def add_scheme(initial_deposit, daily_rate, time_duration, option):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(''' 
        INSERT INTO schemes (initial_deposit, daily_rate, time_duration, option)
        VALUES (?, ?, ?, ?)
    ''', (initial_deposit, daily_rate, time_duration, option))
    conn.commit()
    conn.close()


def subscribe_to_scheme(user_id, scheme_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get scheme details
    cursor.execute("SELECT * FROM schemes WHERE scheme_id = ?", (scheme_id,))
    scheme = cursor.fetchone()

    if not scheme:
        raise ValueError("Scheme not found.")

    initial_deposit = scheme['initial_deposit']

    # Get user's wallet balance
    cursor.execute("SELECT balance FROM wallets WHERE user_id = ?", (user_id,))
    wallet = cursor.fetchone()

    if wallet['balance'] < initial_deposit:
        raise ValueError("Insufficient funds in wallet.")

    # Deduct initial deposit from user's wallet
    cursor.execute('''
        UPDATE wallets 
        SET balance = balance - ? 
        WHERE user_id = ?
    ''', (initial_deposit, user_id))

    # Add subscription to user_schemes
    cursor.execute('''
        INSERT INTO user_schemes (user_id, scheme_id, start_time, time_left)
        VALUES (?, ?, ?, ?)
    ''', (user_id, scheme_id, datetime.now(), scheme['time_duration']))

    conn.commit()
    conn.close()

def update_wallets_for_schemes():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT user_schemes.user_id, schemes.daily_rate, user_schemes.time_left
        FROM user_schemes
        JOIN schemes ON user_schemes.scheme_id = schemes.scheme_id
        WHERE user_schemes.time_left > 0
    ''')

    for row in cursor.fetchall():
        user_id = row['user_id']
        daily_rate = row['daily_rate']
        time_left = row['time_left']

        # Update user's wallet balance based on the daily rate
        cursor.execute('''
            UPDATE wallets 
            SET balance = balance + (balance * ?) 
            WHERE user_id = ?
        ''', (daily_rate, user_id))

        # Decrease time left for the scheme
        cursor.execute('''
            UPDATE user_schemes
            SET time_left = time_left - 1
            WHERE user_id = ? AND scheme_id = ?
        ''', (user_id, row['scheme_id']))

    conn.commit()
    conn.close()

def load_schemes_from_json(cursor):
    try:
        with open('scheme.json', 'r') as file:
            schemes = json.load(file)
            for scheme in schemes:
                # Check if the scheme already exists
                cursor.execute("SELECT * FROM schemes WHERE name = ?", (scheme['name'],))
                if cursor.fetchone() is None:  # Only insert if the scheme does not exist
                    cursor.execute(''' 
                        INSERT INTO schemes (name, initial_deposit, daily_rate, time_duration, option)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (scheme['name'], scheme['initial_deposit'], scheme['daily_rate'], scheme['time_duration'], scheme['option']))
                else:
                    print(f"Scheme '{scheme['name']}' already exists. Skipping.")
    except FileNotFoundError:
        print("scheme.json file not found.")
    except json.JSONDecodeError:
        print("Error decoding JSON from scheme.json.")
    except Exception as e:
        print(f"An error occurred: {e}")



def get_all_schemes():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM schemes")
    schemes = cursor.fetchall()
    conn.close()
    return schemes


def get_user_subscribed_schemes(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT scheme_id FROM user_schemes WHERE user_id = ?", (user_id,))
        return cursor.fetchall()  # Adjust according to your database schema

def get_pending_payments():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_payments")  # Update query as needed
        return cursor.fetchall()


def add_pending_payment(user_id, amount, screenshot_path, payment_type):
    if payment_type not in ['recharge', 'withdrawal']:
        raise ValueError("Invalid payment type. Must be 'recharge' or 'withdrawal'.")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO pending_payments (user_id, amount, screenshot_url, pending, type) VALUES (?, ?, ?, 1, ?)", 
                       (user_id, amount, screenshot_path, payment_type))
        conn.commit()

def update_wallet_balance(user_id, new_balance):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE wallets SET balance = ? WHERE user_id = ?", (new_balance, user_id))
        conn.commit()

def get_users_by_invitation_code(inviter_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE invitation_code = ?", (inviter_id,))
        return cursor.fetchall()

def get_active_schemes_for_user(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT schemes.*, user_schemes.start_time, 
                   datetime(user_schemes.start_time, '+' || user_schemes.time_left || ' days') AS end_time
            FROM schemes
            JOIN user_schemes ON schemes.scheme_id = user_schemes.scheme_id
            WHERE user_schemes.user_id = ? AND user_schemes.time_left > 0
        """, (user_id,))
        return cursor.fetchall()

def get_expired_schemes_for_user(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT schemes.*, user_schemes.start_time, 
                   datetime(user_schemes.start_time, '+' || user_schemes.time_left || ' days') AS end_time
            FROM schemes
            JOIN user_schemes ON schemes.scheme_id = user_schemes.scheme_id
            WHERE user_schemes.user_id = ? AND user_schemes.time_left <= 0
        """, (user_id,))
        return cursor.fetchall()

def get_level_1_team(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE invitation_code = ?", (user_id,))
        result = [dict(user) for user in cursor.fetchall()]
        for user in result:
            withdraw_count, recharge_count = count_withdraws_and_recharges(user['id'])

            user['recharge'] = recharge_count
            user['withdrawal'] = withdraw_count
        return result

def get_level_2_team(level_1_user_ids):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE invitation_code IN ({})".format(','.join('?' * len(level_1_user_ids))), level_1_user_ids)
        
        result = [dict(user) for user in cursor.fetchall()]
        for user in result:
            withdraw_count, recharge_count = count_withdraws_and_recharges(user['id'])

            user['recharge'] = recharge_count
            user['withdrawal'] = withdraw_count
        return result

def get_level_3_team(level_2_user_ids):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE invitation_code IN ({})".format(','.join('?' * len(level_2_user_ids))), level_2_user_ids)

        result = [dict(user) for user in cursor.fetchall()]
        for user in result:
            withdraw_count, recharge_count = count_withdraws_and_recharges(user['id'])

            user['recharge'] = recharge_count
            user['withdrawal'] = withdraw_count
        return result

def get_team_structure(current_user_id):
    # Get level 1 team
    level_1_team = get_level_1_team(current_user_id)
    level_1_ids = [user['id'] for user in level_1_team]

    # Get level 2 team
    level_2_team = []
    if level_1_ids:
        level_2_team = get_level_2_team(level_1_ids)
    level_2_ids = [user['id'] for user in level_2_team]

    # Get level 3 team
    level_3_team = []
    if level_2_ids:
        level_3_team = get_level_3_team(level_2_ids)

    return {
        'level_1': level_1_team,
        'level_2': level_2_team,
        'level_3': level_3_team
    }

def extract_user_ids(team_structure):
    user_ids = []

    # Extract IDs from level 1
    for user in team_structure.get('level_1', []):
        user_ids.append(user['id'])

    # Extract IDs from level 2
    for user in team_structure.get('level_2', []):
        user_ids.append(user['id'])

    # Extract IDs from level 3
    for user in team_structure.get('level_3', []):
        user_ids.append(user['id'])

    return user_ids


def update_wallet_income_rate(user_id, income_rate):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE wallets SET income_rate = ? WHERE user_id = ?", (income_rate, user_id))
        conn.commit()

def get_wallet_income_rate(user_id) -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT income_rate FROM wallets WHERE user_id = ?", (user_id,))
        result =  cursor.fetchone()    
        return list(result)[0]
    
def get_all_user_id() -> list:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users")
    users = cursor.fetchall()
    conn.close()
    return [user['id'] for user in users]

def update_scheme_time_left(scheme_id , time_left):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE user_schemes SET time_left = ? WHERE scheme_id = ?", (time_left, scheme_id))
        conn.commit()


def get_time_left(scheme_id , user_id) -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT time_left FROM user_schemes WHERE scheme_id = ? AND user_id = ?", (scheme_id, user_id))
        result =  cursor.fetchone()    
        return list(result)[0]
    

def get_withdrawal_history(user_id):
    # Return those payments where the payer was the user
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM payment_history WHERE payer_id = ? ORDER BY payment_time DESC", (user_id,))
        return cursor.fetchall()

def get_income_history(user_id):
    # Return those payments where the payer was the scheme
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM payment_history WHERE payer_id = 'scheme' AND receiver_id = ? ORDER BY payment_time DESC", (user_id,))
        return cursor.fetchall()
    
def get_recharge_history(user_id):
    # Return those payments where the receiver was the user
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM payment_history WHERE receiver_id = ? AND payer_id != 'scheme' ORDER BY payment_time DESC", (user_id,))
        return cursor.fetchall()

