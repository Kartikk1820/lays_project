from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response , send_from_directory , abort
from database import *
import hashlib
from functools import wraps
from flask_session import Session
from werkzeug.utils import secure_filename
import os , json
import re


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management
TOKEN_EXPIRATION_TIME = 3600  # Token valid for 1 hour
# Define the path to save uploaded screenshots
UPLOAD_DIRECTORY = 'pending'

BASE_DIR = os.path.join(app.root_path, 'static')

DATA_FILE = './data.json'

UPI_ID = ""

with open(DATA_FILE, 'r') as file:
    data = json.load(file)
    UPI_ID = data.get("payment_id", "")


# Initialize Flask-Session
app.config["SESSION_TYPE"] = "filesystem"  # You can also use "redis", "mongodb", etc.
app.config["SESSION_PERMANENT"] = False  # Session will not persist across server restarts
app.config["SESSION_USE_SIGNER"] = True  # Sign cookies for extra security
Session(app)  # Initialize the session extension


# Initialize the database
init_db()




def hash_user_id(user_id):
    return hashlib.sha256(str(user_id).encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in() and not verify_token():
            flash("Please log in to access this page.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def is_logged_in():
    return 'user_id' in session  # Adjust based on your session management

def verify_token():
    token = request.cookies.get('session_token')
    if token:
        user_id = session.get('user_id')
        expected_token = hash_user_id(user_id)
        return token == expected_token
    return False

@app.route('/')
def root():
    return redirect(url_for('logout'))



@app.route('/home')
@login_required
def home():
    user_id = session['user_id']
    schemes = get_all_schemes()  # Fetch available schemes
    subscribed_schemes = get_user_subscribed_schemes(user_id)  # Fetch user's subscribed schemes

    # Create a set of subscribed scheme IDs for easy lookup
    subscribed_scheme_ids = {scheme['scheme_id'] for scheme in subscribed_schemes}

    return render_template('home.html', schemes=schemes, subscribed_scheme_ids=subscribed_scheme_ids)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']        

        user = get_user_by_identifier(identifier)

        if user and user['password'] == password:
            if user['logged_in']:
                print("This account is already logged in from another session.")
                return redirect(url_for('logout', user_id=user['id']))
            
            session['user_id'] = user['id']
            set_user_logged_in(user['id'], 1)  # Mark as logged in
            
            # Set session token
            token = hash_user_id(user['id'])
            resp = make_response(redirect(url_for('home')))
            resp.set_cookie('session_token', token, max_age=TOKEN_EXPIRATION_TIME)
            flash("Login successful!")
            return resp
        else:

            msg = "Invalid credentials! Please try again."
            render_template('login.html' , message=msg)

    return render_template('login.html')

@app.route('/logout', methods=['GET'])
def logout():
    user_id = request.args.get('user_id', None)  # Get the optional user_id from the query parameters
    admin_id = session.get('admin_id',0)

    if user_id:
        # Log out the specified user by user_id
        set_user_logged_in(user_id, 0)  # Mark as logged out
        session.pop('user_id', None)  # Optionally clear session if needed
    elif session.get('user_id'):
        # Log out the current session user
        set_user_logged_in(session['user_id'], 0)  # Mark as logged out
        session.pop('user_id', None)
    
    if admin_id:
        # Log out the current session admin
        set_admin_logged_in(admin_id, 0)  # Mark as logged out
        session.pop('admin_id', None)

    # Clear the session token cookie
    resp = make_response(redirect(url_for('home')))
    resp.set_cookie('session_token', '', expires=0)
    flash("You have been logged out.")
    return resp


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        invitation_code = request.form['invitation_code']

        # Regular expression for alphanumeric validation
        alphanumeric_regex = re.compile("^[a-zA-Z0-9]*$")

        # Check if inputs are alphanumeric
        if not alphanumeric_regex.match(name):
            msg = ("Name can only contain letters and numbers.")
            print("Name can only contain letters and numbers.")
            return render_template('signup.html', message=msg)

        if not alphanumeric_regex.match(phone):
            msg = ("Phone number can only contain numbers.")
            print("Phone number can only contain numbers.")
            return render_template('signup.html', message=msg)  

        # Check for existing user by name or phone number
        existing_user = get_user_by_identifier(name) or get_user_by_identifier(phone)

        if existing_user:
            # TODO: convert these into messages which can be shown on the signup page
            print("Credentials already exist please use different ones")
            msg = "Credentials already exist please use different ones"
            return render_template('signup.html', message=msg)

        if password != confirm_password:
            print("Passwords do not match!")
            return render_template('signup.html', message="Passwords do not match!")

        user_id = add_user(name, phone, password, invitation_code)  # Ensure this returns the new user's ID
        create_wallet(user_id)  # Pass the user_id to create a wallet
        flash("Signup successful! You can now log in.")
        return redirect(url_for('login'))

    invite_code = request.args.get('invite_code')
    return render_template('signup.html', invite_code=invite_code)

@app.route('/profile')
@login_required
def profile():
    user_id = session['user_id']
    user = get_user_by_id(user_id)
    wallet_balance = get_wallet_by_user_id(user_id)

    # Get withdraw and recharge counts
    withdraw_count, recharge_count = count_withdraws_and_recharges(user_id)

    return render_template('profile.html', 
                           user=user, 
                           wallet_balance=wallet_balance,
                           withdraw_count=withdraw_count, 
                           recharge_count=recharge_count)

@app.route('/payment_history')
@login_required
def payment_history():
    user_id = session['user_id']
    payment_history = get_payment_history(user_id)  # Fetch user's payment history
    withdrawal_history = get_withdrawal_history(user_id)  # Fetch user's withdrawal history
    income_history = get_income_history(user_id)  # Fetch user's income history
    recharge_history = get_recharge_history(user_id)  # Fetch user's recharge history

    return render_template('payment_history.html', payments=payment_history , withdrawals=withdrawal_history, income=income_history, recharge=recharge_history)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        admin = get_admin_by_username(username)
        
        if admin and admin['password'] == hashlib.sha256(password.encode()).hexdigest():
            
            
            session['admin_id'] = admin['id']
            set_admin_logged_in(admin['id'], 1)  # Mark as logged in
            flash("Admin login successful!")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid admin credentials!")

    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please log in to access the admin dashboard.")
        return redirect(url_for('admin_login'))

    users = get_users_with_wallets()  # This function will be defined below
    total_wallet_balance = get_total_wallet_balance()  # Get total wallet balance
    central_pool_balance = get_central_pool_balance()  # Create this function

    return render_template('admin_dashboard.html', users=users, 
                           total_wallet_balance=total_wallet_balance,
                           central_pool_balance=central_pool_balance)

@app.route('/admin/edit_user/<string:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'admin_id' not in session:
        flash("Please log in to access the admin dashboard.")
        return redirect(url_for('admin_login'))

    admin_id = session['admin_id']  # Get the admin ID from the session
    user = get_user_by_id(user_id)  # Fetch user by ID
    if not user:
        flash("User not found.")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        invitation_code = request.form['invitation_code']
        logged_in = request.form.get('logged_in', type=int)
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        wallet_balance_change = request.form.get('wallet_balance_change', type=float)  # New field

        # Update user info in the database
        update_user(user_id, name, phone)

        # Handle password update
        if new_password:
            if new_password != confirm_password:
                flash("Passwords do not match!")
                return redirect(url_for('edit_user', user_id=user_id))
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user_id))
                conn.commit()

        # Handle wallet balance change
        if wallet_balance_change is not None:
            current_balance = get_wallet_by_user_id(user_id)
            new_balance = current_balance + wallet_balance_change

            # Record payment history for the transaction
            record_payment(payer_id=admin_id, receiver_id=user_id, amount=abs(wallet_balance_change), is_admin=True)

            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE wallets SET balance = ? WHERE user_id = ?", (new_balance, user_id))
                conn.commit()

        set_user_logged_in(user_id, logged_in)  # Update logged_in status if needed
        flash("User info updated successfully!")
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_user.html', user=user)

@app.route('/admin/<path:filename>', methods=['GET'])
def serve_image(filename):
    # Split the filename into the folder and the actual file name
    folder = filename.split('/')[0]  # Extract the folder (e.g., "pending")
    file_name = '/'.join(filename.split('/')[1:])  # Extract the rest (e.g., "withdraw_page.png")

    # Construct the full path to the folder
    folder_path = os.path.join(BASE_DIR, folder)

    # Check if the folder exists
    if os.path.exists(folder_path):
        return send_from_directory(folder_path, file_name)
    else:
        abort(404)  # Return a 404 if the folder doesn't exist

@app.route('/admin/payment_history')
def admin_payment_history():
    if 'admin_id' not in session:
        flash("Please log in to access the admin dashboard.")
        return redirect(url_for('admin_login'))

    payment_history = get_payment_history()  # Get all payment history
    return render_template('admin_payment_history.html', payments=payment_history)

@app.route('/profile/bank_details', methods=['GET', 'POST'])
@login_required
def bank_details():
    user_id = session['user_id']
    
    if request.method == 'POST':
        full_name = request.form['fullName']
        phone_number = request.form['phoneNumber']
        bank_account = request.form['bankAccount']
        bank_name = request.form['bankName']
        ifsc = request.form['ifsc']
        branch_name = request.form['branch_name']
        withdrawal_password = request.form['withdrawalPassword']

        update_bank_details(user_id, full_name, phone_number, bank_account, bank_name, ifsc, branch_name, withdrawal_password)
        flash("Bank details updated successfully!")
        return redirect(url_for('home'))

    bank_details = get_bank_details(user_id)
    return render_template('bank_details.html', bank_details=bank_details)

@app.route('/invite', methods=['GET'])
def invite():
    if is_logged_in():
        user_id = session['user_id']
        invite_link = url_for('invite', user_id=user_id, _external=True)  # Generate invite link
        return render_template('invite.html', user_id=user_id, invite_link=invite_link)
    else:
        user_id_from_url = request.args.get('user_id')
        if not user_id_from_url:
            return redirect(url_for('signup'))  # Redirect to signup if no user_id in URL
        else:
            return redirect(url_for('signup', invite_code=user_id_from_url))  # Redirect with invite code

@app.route('/subscribe_scheme/<int:scheme_id>', methods=['POST'])
@login_required
def subscribe_scheme(scheme_id):
    user_id = session['user_id']
    
    try:
        subscribe_to_scheme(user_id, scheme_id)  # Call the function to subscribe the user
        flash("Successfully subscribed to the scheme!")
    except Exception as e:
        flash(str(e))  # Display any errors (like insufficient funds)
        return redirect(url_for('recharge'))

    return redirect(url_for('home'))  # Redirect back to the home page

@app.route('/recharge', methods=['GET', 'POST'])
@login_required
def recharge():
    global UPI_ID
    if request.method == 'POST':
        amount = request.form['amount']

        try:
            amount = float(amount)
            if amount <= 0:
                flash("Please enter a valid amount.", "error")
                return redirect(url_for('recharge'))

            # Redirect to the payment gateway with the amount
              # This should be dynamically retrieved
            return redirect(url_for('payment_gateway', amount=amount, upi_id=UPI_ID))

        except ValueError:
            flash("Invalid amount. Please enter a numeric value.", "error")
            return redirect(url_for('recharge'))

    return render_template('recharge.html')


@app.route('/payment_gateway', methods=['GET', 'POST'])
@login_required
def payment_gateway():
    user_id = session['user_id']  # Get the user ID from the session

    if request.method == 'POST':
        # Handle form submission (screenshot upload, etc.)
        screenshot = request.files['screenshot']
        if screenshot:
            screenshot_filename = secure_filename(screenshot.filename)
            screenshot_path = os.path.join(UPLOAD_DIRECTORY, screenshot_filename)
            screenshot.save(os.path.join('static',screenshot_path))

            # Record the pending payment
            amount = request.form['amount']
            # Assuming the amount is passed along with the form submission
            try:
                amount = float(amount)

                # Add an entry in the pending payments table
                add_pending_payment(user_id=user_id, amount=amount, screenshot_path=screenshot_path , payment_type='recharge')

                flash("Payment details submitted successfully!", "success")
            except ValueError:
                flash("Invalid amount. Please enter a numeric value.", "error")

            return redirect(url_for('profile'))  # Redirect to profile after submission

    amount = request.args.get('amount')
    upi_id = request.args.get('upi_id')

    return render_template('payment_gateway.html', amount=amount, upi_id=upi_id)


@app.route('/admin/pending_payments')
def admin_pending_payments():
    if 'admin_id' not in session:
        flash("Please log in to access the admin dashboard.")
        return redirect(url_for('admin_login'))

    pending_payments = get_pending_payments()  # Function to retrieve pending payments from the database
    return render_template('pending_payments.html', payments=pending_payments)

@app.route('/admin/approve_payment', methods=['POST'])
def approve_payment():
    if 'admin_id' not in session:
        flash("Please log in to access the admin dashboard.")
        return redirect(url_for('admin_login'))

    admin_id = session['admin_id']
    
    payment_id = request.form['payment_id']
    user_id = request.form['user_id']
    amount = float(request.form['amount'])
    payment_type = request.form['type']

    # Record the payment
    if payment_type == 'recharge':
        record_payment(payer_id=admin_id, receiver_id=user_id, amount=amount, is_admin=True)


    elif payment_type == 'withdrawal':
        record_payment(payer_id=user_id, receiver_id=admin_id, amount=amount, is_admin=False)


    else:
        redirect(url_for('admin_pending_payments'))

    
    # Update the pending payment entry
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE pending_payments SET pending = 0 WHERE id = ?", (payment_id,))
        conn.commit()


    flash("Payment approved successfully!")
    return redirect(url_for('admin_pending_payments'))


@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    user_id = session['user_id']
    wallet_balance = get_wallet_by_user_id(user_id)  # Get user's wallet balance
    bank_details = get_bank_details(user_id)  # Get bank details for the user

    if request.method == 'POST':
        print(1)
        amount = request.form['amount']
        withdrawPassword = request.form['withdrawPassword']

        if bank_details["withdrawal_password"] != withdrawPassword:
            print("Incorrect withdrawal password. Please try again.", "error")
            return redirect(url_for('withdraw'))

        try:
            amount = float(amount)
            if amount <= 0:
                print("Please enter a valid amount.", "error")
                return redirect(url_for('withdraw'))

            if amount > wallet_balance:
                print("Insufficient funds in your wallet.", "error")
                return redirect(url_for('withdraw'))

            # Process the withdrawal here (e.g., update the wallet balance)
            # Add an entry in the pending payments table
            add_pending_payment(user_id=user_id, amount=amount, screenshot_path=None , payment_type='withdrawal')

            
            flash("Withdrawal successful!", "success")
            return redirect(url_for('profile'))

        except ValueError:
            flash("Invalid amount. Please enter a numeric value.", "error")
            return redirect(url_for('withdraw'))

    return render_template('withdraw.html', wallet_balance=wallet_balance, bank_details=bank_details)


@app.route('/admin/user_details/<string:user_id>')
def admin_user_details(user_id):
    if 'admin_id' not in session:
        flash("Please log in to access the admin dashboard.")
        return redirect(url_for('admin_login'))

    # Fetch user details
    user = get_user_by_id(user_id)
    wallet_balance = get_wallet_by_user_id(user_id)
    bank_details = get_bank_details(user_id)
    payment_history = get_payment_history(user_id)
    users_invited = get_users_by_invitation_code(user_id)  # Assume this function exists

    if not user:
        flash("User not found.")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_user_details.html', 
                           user=user, 
                           wallet_balance=wallet_balance,
                           bank_details=bank_details,
                           payment_history=payment_history,
                           users_invited=users_invited)

@app.route('/my_collection')
@login_required
def my_collection():
    user_id = session['user_id']
    active_schemes = get_active_schemes_for_user(user_id)
    expired_schemes = get_expired_schemes_for_user(user_id)

    return render_template('my_collection.html', 
                           active_schemes=active_schemes, 
                           expired_schemes=expired_schemes,
                           current_timestamp=datetime.now())

@app.route('/team')
@login_required
def team():
    current_user_id = session.get('user_id')  # Replace with the way you get the current user's ID
    if not current_user_id:
        return "Please log in first.", 403

    team_asset = 0
    team_member = 0
    total_recharge = 0

    team_structure = get_team_structure(current_user_id)
    all_members = extract_user_ids(team_structure)


    

    for user_id in all_members:
        withdraw_count, recharge_count = count_withdraws_and_recharges(user_id)
        total_recharge += recharge_count
        team_asset += get_wallet_by_user_id(user_id)
        team_member += 1

    withdraw_count , recharge_count = count_withdraws_and_recharges(current_user_id)
    total_recharge += recharge_count
    team_asset += get_wallet_by_user_id(current_user_id)
    return render_template('team.html', team=team_structure , team_asset=team_asset , team_member=team_member, total_recharge=total_recharge)

@app.route('/company_profile')
@login_required
def company_profile():
    
    return render_template('company-profile.html')



if __name__ == '__main__':
    app.run(debug=True)
