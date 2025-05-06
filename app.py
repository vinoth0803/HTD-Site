from flask import Flask, render_template, request, redirect, send_from_directory, url_for, session, jsonify, flash, make_response, send_file
import firebase_admin
from firebase_admin import credentials, firestore
import os
import csv
import logging
import random
from twilio.rest import Client
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv  
from functools import wraps
from datetime import datetime, timedelta
from flask import jsonify
import stripe
import uuid
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from io import BytesIO

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
publishable_key = os.getenv("STRIPE_PUBLISHABLE_KEY")

load_dotenv()


# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Set a secret key for session management
otp_store = {}

account_sid = os.getenv('TWILIO_ACCOUNT_SID')  # Fetches Twilio Account SID
auth_token = os.getenv('TWILIO_AUTH_TOKEN')      # Fetches Twilio Auth Token
twilio_phone_number = os.getenv('TWILIO_PHONE_NUMBER')  # Fetches Twilio phone number

# Create a Twilio client
twilio_client = Client(account_sid, auth_token)

# FAST2SMS_API_KEY = os.getenv('FAST2SMS_API_KEY')  # Make sure to set your Fast2SMS API Key

# Initialize Firestore DB
cred = credentials.Certificate("firebase-credentials.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# Set up logging
logging.basicConfig(level=logging.DEBUG)
app.logger.info("Flask app started")

# Admin credentials (can be stored securely, e.g., in environment variables)
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')  # Change this to a strong password

#-------------------------------------------------------#-------------------------------------------------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        mobile = request.form['phone']
        password = request.form['password']  # Get the plaintext password

        # Hash the password before storing
        hashed_password = generate_password_hash(password)

        # Log the hashed password
        logging.info(f"Generated hashed password for {username}: {hashed_password}")

        # Save user data to Firestore
        users_ref = db.collection('users')
        users_ref.add({
            'username': username,
            'email': email,
            'phone': mobile,
            'password': hashed_password  # Store the hashed password
        })

        flash('Signup successful! Redirecting to home page.', 'success')
        return redirect(url_for('home'))

    return render_template('signup.html')
#-------------------------------------------------------#-------------------------------------------------------
@app.route('/add_review', methods=['GET', 'POST'])
def add_review():
    if request.method == 'POST':
        user_name = request.form['user_name']
        rating = request.form['rating']
        comment = request.form['comment']
        
        # Handle the image upload
        if 'review_image' not in request.files:
            flash("No file part")
            return redirect(request.url)
        
        file = request.files['review_image']
        if file.filename == '':
            flash("No selected file")
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_path = f'static/uploads/{filename}'

            # Add the review to Firestore, including the image path
            db.collection('reviews').add({
                'user_name': user_name,
                'rating': rating,
                'comment': comment,
                'image_path': image_path  # Store the image path in Firestore
            })
            
            flash("Review added successfully!", "success")
            return redirect(url_for('manage_reviews'))  # Redirect after POST

    return render_template('add_review.html')  # Render the form for GET requests

#-------------------------------------------------------#-------------------------------------------------------
@app.route('/manage_reviews')
def manage_reviews():
    reviews_ref = db.collection('reviews')
    reviews = reviews_ref.stream()
    
    # Collect all reviews into a list
    reviews_data = []
    for review in reviews:
        review_dict = review.to_dict()
        review_dict['id'] = review.id  # Add review ID for referencing
        reviews_data.append(review_dict)

    return render_template('manage_reviews.html', reviews=reviews_data)

#-------------------------------------------------------#-------------------------------------------------------
@app.route('/edit_review/<review_id>', methods=['GET', 'POST'])
def edit_review(review_id):
    review_ref = db.collection('reviews').document(review_id)
    
    if request.method == 'POST':
        user_name = request.form['user_name']
        rating = int(request.form['rating'])
        comment = request.form['comment']
        
        # Prepare update data
        update_data = {
            'user_name': user_name,
            'rating': rating,
            'comment': comment
        }
        
        # Check if a new image file is uploaded
        if 'reviewer_image' in request.files:
            reviewer_image = request.files['reviewer_image']
            if reviewer_image.filename != '':
                # Save the new image
                filename = secure_filename(reviewer_image.filename)
                image_path = os.path.join('static/uploads', filename)
                reviewer_image.save(image_path)
                update_data['image_path'] = image_path  # Update image path in Firestore

        # Update Firestore with new data
        review_ref.update(update_data)
        return redirect(url_for('manage_reviews'))

    # Fetch existing review data
    review = review_ref.get().to_dict()
    return render_template('edit_review.html', review=review, review_id=review_id)


#-------------------------------------------------------#-------------------------------------------------------

@app.route('/delete_review/<review_id>', methods=['POST'])
def delete_review(review_id):
    try:
        # Attempt to delete the review from Firestore
        db.collection('reviews').document(review_id).delete()
        flash("Review deleted successfully!", "success")
    except Exception as e:
        # Log the error and show a failure message
        print(f"Error deleting review: {e}")
        flash("Error deleting review. Please try again.", "danger")
        
    return redirect(url_for('manage_reviews'))

#-------------------------------------------------------#-------------------------------------------------------
# Decorator to require login for specific routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
#-------------------------------------------------------#-------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f"Username entered: {username}, Password entered: {password}")

        # Check if the provided credentials are for the admin
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['user'] = 'admin'
            flash('Admin logged in successfully!', 'success')
            print("Redirecting to admin dashboard...")
            return redirect(url_for('admin_dashboard'))

        try:
            # Check Firestore for the user
            users_ref = db.collection('users').where('username', '==', username).stream()
            user = None

            user_found = False
            for u in users_ref:
                user_found = True
                user = u.to_dict()

            if not user_found:
                print("No user found in Firestore.")

            logging.info(f"Attempting to log in user: {username}")

            if user:
                logging.info(f"User found: {user}")

                # Verify hashed password
                if check_password_hash(user['password'], password):
                    session['user'] = username
                    flash('Logged in successfully!', 'success')
                    print("Redirecting to home...")
                    return redirect(url_for('home'))
                else:
                    logging.warning(f"Password mismatch for user: {username}")
                    flash('Invalid credentials. Please try again.', 'danger')
            else:
                logging.warning(f"User not found: {username}")
                flash('Invalid credentials. Please try again.', 'danger')

        except Exception as e:
            logging.error(f"An error occurred during login: {str(e)}")
            flash(f"An error occurred: {str(e)}", 'danger')

    return render_template('login.html')
#-------------------------------------------------------#-------------------------------------------------------
#forgot password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Check if the email exists in the Firestore database
        users_ref = db.collection('users')  # Replace 'users' with your collection name
        query = users_ref.where('email', '==', email).limit(1).stream()
        
        if any(query):  # If at least one user exists
            return redirect(url_for('reset_password', email=email))
        else:  # If no user with that email exists
            flash('No account found with that email address.', 'danger')
            return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')
#-------------------------------------------------------#-------------------------------------------------------
#Reset password
@app.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password == confirm_password:
            # Update the user's password in Firestore
            users_ref = db.collection('users')  # Replace 'users' with your collection name
            user_doc = users_ref.where('email', '==', email).limit(1).get()
            
            if user_doc:
                user_ref = user_doc[0].reference  # Get a reference to the user document
                user_ref.update({'password': generate_password_hash(new_password)})  # Hash the new password before saving
                flash('Your password has been reset successfully!', 'success')
                return redirect(url_for('login'))
            else:
                flash('Error: User not found.', 'danger')
        else:
            flash('Passwords do not match. Please try again.', 'danger')
    
    return render_template('reset_password.html', email=email)


#-------------------------------------------------------#-------------------------------------------------------
# Logout Route
@app.route('/logout')
def logout():
    session.pop('logged_in', None)  # Clear the session
    return redirect('/')  # Redirect to home or login page
#-------------------------------------------------------#-------------------------------------------------------
# Home route
@app.route('/')
def home():
    app.logger.info("Home route accessed")
    
    # Fetch products
    products_ref = db.collection('products')
    products = products_ref.stream()
    
    product_list = []
    for product in products:
        product_data = product.to_dict()
        product_list.append(product_data)

    # Fetch reviews
    reviews_ref = db.collection('reviews')
    reviews = reviews_ref.stream()
    
    review_list = []
    for review in reviews:
        review_data = review.to_dict()
        # Ensure that image_path is relative to the static directory
        image_path = review_data.get('image_path', '')
        if image_path:  # Ensure we only add paths that exist
            # Change backslashes to forward slashes and trim if necessary
            image_path = image_path.replace('\\', '/')
            # Check if it already contains 'static/uploads/' and adjust accordingly
            if image_path.startswith('static/uploads/'):
                image_path = image_path[len('static/'):]

        review_list.append({
            'user_name': review_data.get('user_name'),
            'rating': review_data.get('rating'),
            'comment': review_data.get('comment'),
            'image_path': image_path  # Include image path
        })
    
    print(review_list)  # Add this line to check if reviews are fetched correctly

    return render_template('home.html', products=product_list, reviews=review_list)


#-------------------------------------------------------#-------------------------------------------------------
#gallery route
@app.route('/gallery')
def gallery():
    app.logger.info("Gallery route accessed")
    return render_template('gallery.html')
#-------------------------------------------------------#-------------------------------------------------------
# About route
@app.route('/about')
def about():
    app.logger.info("About route accessed")
    return render_template('about.html')
#-------------------------------------------------------#-------------------------------------------------------
# Contact route
@app.route('/contact')
def contact():
    app.logger.info("Contact route accessed")
    return render_template('contact.html')
#-------------------------------------------------------#-------------------------------------------------------
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')
#-------------------------------------------------------#-------------------------------------------------------
product_prices = {
    "Milk": 3500,     # 35.00
    "Paneer": 23000,  # 230.00
    "Ghee": 30000,    # 300.00
    "Curd": 4500,     # 45.00
    "Honey": 21000    # 210.00
}
# Add Customer
@app.route('/add_customer', methods=['GET', 'POST'])
def add_customer():
    if request.method == 'POST':
        # Generate a unique invoice ID
        invoice_id = str(uuid.uuid4())

        # Get customer details from the form
        customer_details = {
            'name': request.form['name'],
            'email': request.form['email'],
            'phone': request.form['phone'],
            'address': request.form['address'],
            'product': request.form['product'],
            'invoice_id': invoice_id  # Include the invoice ID
        }

        # Save customer details to Firestore
        db.collection('customers').add(customer_details)

        # Retrieve the selected product and its price
        product = customer_details['product']
        price = product_prices.get(product)

        # Log customer details for debugging
        logging.info(f"Customer Details: {customer_details}")

        # Validate the price
        if price is not None and price > 0:
            session['customer_info'] = customer_details  # Store customer info in session

            logging.info(f"Stored in session: {session['customer_info']}")  # Debugging log

            # Create Stripe Checkout Session
            stripe_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': product,
                        },
                        'unit_amount': price,
                    },
                    'quantity': 1,  # Assuming quantity is always 1 for now
                }],
                mode='payment',
                success_url=url_for('payment_success', _external=True),
                cancel_url=url_for('payment_cancel', _external=True),
            )
            return redirect(stripe_session.url, code=303)
        else:
            flash("Invalid product selected.", "error")
            return redirect(url_for('add_customer'))

    return render_template('add_customer.html')



#manage customers
@app.route('/manage_customers')

def manage_customers():
    customers_ref = db.collection('customers').stream()
    customers = []
    
    for customer in customers_ref:
        customer_data = customer.to_dict()
        customer_data['id'] = customer.id  # Add the document ID to the customer data
        customers.append(customer_data)
        
    return render_template('manage_customers.html', customers=customers)

# Route to delete a customer
@app.route('/delete_customer/<customer_id>', methods=['POST'])

def delete_customer(customer_id):
    try:
        # Delete the customer document from Firestore
        db.collection('customers').document(customer_id).delete()
        flash('Customer deleted successfully!', 'success')
    except Exception as e:
        flash(f"An error occurred while deleting the customer: {str(e)}", 'danger')

    # Redirect back to the manage customers page
    return redirect(url_for('manage_customers'))

# Payment Success
@app.route('/payment_success')
def payment_success():
    # Retrieve customer info from session
    customer_info = session.get('customer_info')

    if customer_info:
        # Log payment success
        logging.info(f"Payment successful for customer: {customer_info['email']}")
        
        # Return the payment success page without clearing the session data
        return render_template('payment_success.html', customer_info=customer_info)
    else:
        logging.warning("Payment success route accessed without customer info.")
        return "No customer information found.", 400



# Generate Invoice
@app.route('/generate_invoice', methods=['POST'])
def generate_invoice():
    # Access customer info from session
    customer_info = session.get('customer_info')

    if not customer_info:
        logging.error("Customer info is missing")
        return "Customer info is missing", 400

    invoice_id = customer_info.get('invoice_id')
    if not invoice_id:
        return "Invoice ID is missing", 400

    # Retrieve product, price, and quantity
    product = customer_info.get('product', 'N/A')
    quantity = request.form.get('quantity', 1, type=int)  # Get quantity from the form submission
    price = product_prices.get(product, 0)  # Use the product_prices dictionary for the correct price

    # Calculate subtotal
    subtotal = price * quantity

    # Update customer_info with subtotal for rendering
    customer_info['quantity'] = quantity  # Ensure quantity is included in customer_info
    customer_info['subtotal'] = subtotal

    # Render the HTML invoice template
    html_invoice = render_template('invoice.html', customer_info=customer_info)

    # Create a response object
    response = make_response(html_invoice)
    response.headers['Content-Type'] = 'text/html'
    response.headers['Content-Disposition'] = 'attachment; filename=invoice.html'

    return response


# Payment Cancel
@app.route('/payment_cancel')
def payment_cancel():
    return "Payment cancelled."


# Success Route (Redirect to Invoice Generation)
@app.route('/success')
def success():
    # Retrieve customer info from session
    customer_info = session.get('customer_info')

    if customer_info:
        # Redirect to the invoice generation endpoint with customer info
        return redirect(url_for('generate_invoice', **customer_info))
    else:
        return "No customer information found.", 400
    
#-------------------------------------------------------#-------------------------------------------------------
# Get Sample
@app.route('/get_sample', methods=['GET', 'POST'])
def get_sample():
    if request.method == 'POST':
        phone = request.form['phone']
        otp = str(random.randint(100000, 999999))  # Generate a 6-digit OTP
        otp_store[phone] = (otp, datetime.now())  # Store OTP with the current timestamp

        # Send the OTP via SMS using Twilio
        try:
            message = twilio_client.messages.create(
                body=f'Your OTP is {otp}. It will expire in 5 minutes.',
                from_=twilio_phone_number,
                to=phone
            )
            print(f'Message sent: {message.sid}')
            flash("OTP has been sent successfully! It will expire in 5 minutes.", "success")
        except Exception as e:
            print(f'Failed to send message: {e}')
            flash("Failed to send OTP. Please try again.", "error")

        return render_template('verify_otp.html', phone=phone)

    return render_template('get_sample.html')
#-------------------------------------------------------#-------------------------------------------------------
# Verify OTP
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    phone = request.form['phone']
    otp = request.form['otp']
    
    if phone in otp_store:
        stored_otp, timestamp = otp_store[phone]
        # Check if the OTP is correct and if it's within 5 minutes
        if stored_otp == otp and datetime.now() <= timestamp + timedelta(minutes=5):
            del otp_store[phone]  # Remove OTP after successful verification
            return redirect(url_for('customer_details'))
        else:
            flash("Invalid or expired OTP. Please try again.", "error")
            return redirect(url_for('get_sample'))  # Redirect to the get_sample page to enter phone number again
    else:
        flash("OTP not found. Please request a new one.", "error")
        return redirect(url_for('get_sample'))
#-------------------------------------------------------#-------------------------------------------------------
# Customer Details
@app.route('/customer_details', methods=['GET', 'POST'])
def customer_details():
    if request.method == 'POST':
        name = request.form['name']
        district = request.form['district']
        address = request.form['address']
        return "Customer details saved!"
    
    return render_template('customer_details.html')
#-------------------------------------------------------#-------------------------------------------------------
# Set up the upload folder for images
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
upload_folder = app.config['UPLOAD_FOLDER']
if not os.path.exists(upload_folder):
    os.makedirs(upload_folder)
#-------------------------------------------------------#-------------------------------------------------------
# Route to display all products
@app.route('/products')
def get_products():
    try:
        products_ref = db.collection('products').stream()
        products = [{**prod.to_dict(), 'id': prod.id} for prod in products_ref]
        app.logger.info(f'Products fetched: {products}')
        return render_template('product_page.html', products=products)
    except Exception as e:
        app.logger.error(f'Error fetching products: {str(e)}')
        return f"Error fetching products from the database: {str(e)}", 500
#-------------------------------------------------------#-------------------------------------------------------
# Route to display product detail
@app.route('/product/<id>')
def product_details(id):
    app.logger.debug(f'Received request for product ID: {id}')
    product_ref = db.collection('products').document(id).get()
    
    if not product_ref.exists:
        app.logger.error(f'Product not found: {id}')
        return "Product not found", 404
    
    product = product_ref.to_dict()
    app.logger.debug(f'Product fetched: {product}')  # Log product details
    return render_template('product_detail.html', product=product)

#-------------------------------------------------------#-------------------------------------------------------
# Admin Dashboard
@app.route('/admin')
def admin_dashboard():
    print("Admin dashboard accessed!")
    if 'user' not in session or session['user'] != 'admin':
        flash('Access denied: You must be an admin to view this page.', 'danger')
        return redirect(url_for('login'))
    # Get references to collections
    products_ref = db.collection('products')  # Replace 'products' with your actual collection name
    users_ref = db.collection('users')        # Replace 'users' with your actual collection name
    customers_ref = db.collection('customers')     # Replace 'samples' with your actual collection name
    reviews_ref = db.collection('reviews')

    # Fetch data
    total_products = len(products_ref.get())
    total_users = len(users_ref.get())
    total_samples = len(customers_ref.get())
    total_reviews = len(reviews_ref.get())

    return render_template('admin.html', 
                           total_products=total_products, 
                           total_users=total_users, 
                           total_samples=total_samples,total_reviews=total_reviews)
#-------------------------------------------------------#-------------------------------------------------------
@app.route('/registered_users')

def registered_users():
    users = []
    # Fetch users from Firebase
    users_ref = db.collection('users')  # Adjust based on your Firestore collection name
    users_data = users_ref.stream()

    for user in users_data:
        user_dict = user.to_dict()
        user_dict['id'] = user.id  # Get the document ID
        users.append(user_dict)

    return render_template('registered_users.html', users=users)
#-------------------------------------------------------#-------------------------------------------------------
#edit user
@app.route('/edit_user/<user_id>', methods=['GET', 'POST'])

def edit_user(user_id):
    user_ref = db.collection('users').document(user_id)

    if request.method == 'POST':
        updated_username = request.form['username']
        updated_email = request.form['email']
        updated_password = request.form['password']
        
        user_ref.update({
            'username': updated_username,
            'email': updated_email,
            'password': updated_password
        })

        return redirect(url_for('registered_users'))

    user_data = user_ref.get().to_dict()
    return render_template('edit_user.html', user=user_data)
#------------------------------------------------------------------------------------
@app.route('/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    print(f"Delete request received for user_id: {user_id}")  # Debugging line
    db.collection('users').document(user_id).delete()
    return redirect(url_for('registered_users'))
#-------------------------------------------------------#-------------------------------------------------------
# Add Product
@app.route('/add_product', methods=['GET', 'POST'])

def add_product():
    if request.method == 'POST':
        new_product = {
            'name': request.form['name'],
            'price': float(request.form['price']),
            'description': request.form['description'],
        }

        if 'image' in request.files and request.files['image']:
            file = request.files['image']
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                new_product['image_url'] = url_for('static', filename=f'uploads/{filename}')
                app.logger.info(f'Image saved at: {filepath}')
            else:
                app.logger.warning('File type not allowed for image upload.')

        db.collection('products').add(new_product)
        flash('Product added successfully!', 'success')
        app.logger.info(f'Added new product: {new_product}')
        return redirect('/admin')

    return render_template('add_product.html')
#-------------------------------------------------------#-------------------------------------------------------
# Manage Products
@app.route('/admin/manage_products')

def manage_products():
    products_ref = db.collection('products').stream()
    products = [{**prod.to_dict(), 'id': prod.id} for prod in products_ref]
    app.logger.debug(f'Products: {products}')  # Log the products for debugging
    return render_template('manage_products.html', products=products)
#-------------------------------------------------------#-------------------------------------------------------
# Upload Products from CSV
@app.route('/upload_products', methods=['POST'])

def upload_products():
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    if file and allowed_file(file.filename):
        csv_reader = csv.reader(file.stream.read().decode("UTF-8").splitlines())
        next(csv_reader)  # Skip header row
        for row in csv_reader:
            new_product = {
                'name': row[0],
                'price': float(row[1]),
                'description': row[2],
                'image_url': row[3]
            }
            db.collection('products').add(new_product)
            app.logger.info(f'Uploaded product from CSV: {new_product}')
        return redirect('/admin')

    return "File type not allowed", 400
#-------------------------------------------------------#-------------------------------------------------------
@app.route('/admin/update_product/<product_id>', methods=['GET', 'POST'])

def update_product(product_id):  # Use <product_id> as a string
    app.logger.debug(f'Attempting to update product with ID: {product_id}')

    # Retrieve product data for the form
    product_ref = db.collection('products').document(product_id).get()  # Use product_id as a string
    product = product_ref.to_dict()  # Convert document to dictionary

    # Check if product exists
    if product is None:
        app.logger.error(f'Product with ID {product_id} does not exist.')
        return f"Product with ID {product_id} does not exist.", 404

    # Include the Firestore document ID in the product dictionary
    product['id'] = product_ref.id  

    if request.method == 'POST':
        app.logger.debug(f'Received POST data: {request.form}')

        try:
            updated_product = {
                'name': request.form['name'],
                'price': float(request.form['price']),
                'description': request.form['description'],
            }

            # Handle image upload
            if 'image' in request.files and request.files['image']:
                file = request.files['image']
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    updated_product['image_url'] = url_for('static', filename=f'uploads/{filename}')
                    app.logger.info(f'Image uploaded for product ID {product_id}: {updated_product["image_url"]}')
                else:
                    app.logger.warning('File type not allowed for image upload.')

            # Update the product document in the database
            db.collection('products').document(product_id).update(updated_product)
            app.logger.info(f'Product updated successfully: {updated_product}')
            return redirect('/admin')

        except Exception as e:
            app.logger.error(f'Error updating product: {str(e)}')
            return f"Error updating product: {str(e)}", 500

    return render_template('update_product.html', product=product)

#-------------------------------------------------------#-------------------------------------------------------
# Delete Product
@app.route('/delete_product/<product_id>', methods=['POST'])

def delete_product(product_id):  # Change 'id' to 'product_id'
    try:
        db.collection('products').document(product_id).delete()
        flash(f'Product with ID {product_id} deleted successfully!', 'success')
        app.logger.info(f'Product with ID {product_id} deleted successfully.')
    except Exception as e:
        flash(f'Error deleting product: {str(e)}', 'danger')
        app.logger.error(f'Error deleting product: {str(e)}')
    return redirect('/admin')

# Allowed file types for image uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS




#-----------------------------------------------------------------------------------------------------------------------
# Run the Flask app
if __name__ == '__main__':
    with app.app_context():
        print(app.url_map)
    app.run(debug=True)  # Set debug=True for development purposes
