from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory,jsonify,Response
from flask_mail import Mail, Message
from pymongo import MongoClient
from bson import ObjectId
from pymongo.errors import DuplicateKeyError
import bcrypt
import os
import random 
import string 
from datetime import datetime, timedelta
from time import time
from werkzeug.utils import secure_filename  # Add this import
import cv2
import math
from ultralytics import YOLO


app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# MongoDB setup
client = MongoClient('mongodb+srv://flaskuser17:8MOK8vPPRUh1VTMb@cluster0.uxkt8vq.mongodb.net/?tls=true')
db = client['AuthDetails']
super_admins_collection = db['SuperAdmin']
admins_collection = db['Admin']
users_collection = db['Users']

# Index creation
users_collection.create_index([('mobile', 1)], unique=True)
users_collection.create_index([('aadhar', 1)], unique=True)
users_collection.create_index([('email', 1)], unique=True)

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'flaskuser17@gmail.com'  # Update with your Gmail address
app.config['MAIL_PASSWORD'] = 'vkfa qegm udzn pcbp'  # Update with your Gmail password
app.config['UPLOAD_FOLDER'] = "D:\\Pune Metro Rail Hackathon\\CodeV5SuperAdminOTP\\uploads"

mail = Mail(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif','mp4','avi'}  # Add this variable for allowed file extensions

#Index (Home Page)
@app.route('/')
def Index():
    print("Accessed Index page.")
    return render_template("Index.html")

#Contact Page
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        mobile = request.form['mobile']
        email = request.form['email']
        message = request.form['message']  # Retrieve the message from the form

        # Send email
        msg = Message('Contact Form Submission', sender='flaskuser17@gmail.com', recipients=['ahildoesstudy@gmail.com'])
        msg.body = f"Name: {name}\nMobile: {mobile}\nEmail: {email}\nMessage: {message}"  # Include the message in the email body
        mail.send(msg)
        return redirect(url_for('Index'))
    return render_template("Contact.html")



# Generate OTP function
def generate_otp():
    otp = ''.join(random.choices(string.digits, k=6))  # Generate a 6-digit OTP
    timestamp = time()  # Get the current timestamp
    return otp, timestamp

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Retrieve form data
        user_type = request.form['user-type']
        email = request.form['email']
        password = request.form['password']

        # Choose the collection based on the user type
        if user_type == 'superadmin':
            collection = db['SuperAdmin']
        elif user_type == 'admin':
            collection = db['Admin']
        elif user_type == 'user':
            collection = db['Users']
        else:
            return 'Invalid user type'

        # Query the MongoDB database to check if the user exists
        user = collection.find_one({'email': email})

        if user:
            # Check if the entered password matches the hashed password stored in the database
            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                # Generate OTP
                otp = generate_otp()
                # Store user email, type, and OTP in session
                session['user_email'] = email
                session['user_type'] = user_type
                session['otp'] = otp  # Store OTP in session temporarily
                # Send OTP via email or SMS (you need to implement this part)
                # For now, let's print the OTP to the console
                print("Generated OTP:", otp)
                # Redirect to OTP verification page
                return redirect(url_for('verify_otp_route'))
            else:
                # Incorrect password
                error = 'Incorrect password.'
        else:
            # User not found
            error = 'User not found.'

    # Render login form for GET requests
    return render_template('Login.html', error=error)

# Verify OTP function with timeout
def verify_otp(otp_entered):
    if 'otp' in session:
        otp_stored, timestamp = session['otp']
        # Check if the OTP matches
        if otp_entered == otp_stored:
            # Check if the timestamp is within the 30-second window
            if time() - timestamp <= 30:
                return True
    return False

# Verify OTP route
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp_route():  # Rename the route function to avoid naming conflict
    if 'user_email' not in session:
        # If user email is not stored in session, redirect to login page
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Retrieve entered OTP
        otp_entered = request.form['otp']
        # Verify OTP
        if verify_otp(otp_entered):
            # Successful OTP verification, set session variables and redirect to profile page based on user type
            session['logged_in'] = True  # Set logged_in session variable to indicate user is logged in
            return redirect_profile(session['user_type'])
        else:
            # Incorrect OTP or expired
            error = 'Incorrect OTP or expired. Please try again.'
            return render_template('VerifyOTP.html', error=error)

    # If the request method is GET, it means the user is accessing the OTP verification form page
    # Generate a new OTP and send it via email
    otp, timestamp = generate_otp()  # Generate OTP and timestamp
    session['otp'] = (otp, timestamp)  # Store OTP and timestamp in session
    send_otp_email(session['user_email'], otp)  # Send OTP via email
    return render_template('VerifyOTP.html')


# Function to redirect to profile page based on user type
def redirect_profile(user_type):
    if user_type == 'superadmin':
        return redirect(url_for('SProfile'))
    elif user_type == 'admin':
        return redirect(url_for('AProfile'))
    elif user_type == 'user':
        return redirect(url_for('UProfile'))
    else:
        return 'Invalid user type'


# Define the function to send OTP email
def send_otp_email(recipient, otp):
    try:
        # Create a message object
        msg = Message('OTP Verification', sender='flaskuser17@gmail.com', recipients=[recipient])
        
        # Compose the email body
        msg.body = f'Your OTP for verification is: {otp}'
        
        # Print the email content for debugging
        print("Sending OTP email to:", recipient)
        print("Email content:", msg.body)
        
        # Send the email
        mail.send(msg)
        print("OTP email sent successfully.")
    except Exception as e:
        # Print error message if email sending fails
        print("Error sending OTP email:", e)

last_otp_time = datetime.now()
@app.route('/resend_otp', methods=['GET'])
def resend_otp():
    global last_otp_time  # Access the global variable within the function
    current_time = datetime.now()  # Get the current time using datetime.now()

    # Check if enough time has passed since the last OTP was sent (10 seconds)
    if current_time - last_otp_time >= timedelta(seconds=10):
        # If enough time has passed, generate and send a new OTP
        otp, timestamp = generate_otp()  # Generate OTP and timestamp
        
        # Retrieve the user's email from the session
        recipient_email = session.get('user_email')
        
        # Check if the recipient's email is available
        if recipient_email:
            # Send the OTP email to the recipient
            send_otp_email(recipient_email, otp)
            last_otp_time = current_time  # Update the last OTP time
            return "OTP resent successfully"
        else:
            return "Recipient's email not found in session."
    else:
        # If not enough time has passed, return a message indicating that
        return "Please wait before resending OTP"

#Logout route 
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        session.pop('logged_in', None)
        return redirect(url_for('login'))

# User Profile Page
@app.route('/UProfile')
def UProfile():
    if 'logged_in' in session:
        email = session['user_email']
        print(email)  # Retrieve user's email from session
        user_type = session.get('user_type')  # Retrieve user's type from session
        print(user_type)
        # Choose the collection based on the user type
        if user_type == 'user':
            collection = db['Users']
        else:
            return 'Invalid user type'
        
        # Query MongoDB to retrieve user details based on email
        user = collection.find_one({'email': email})

        if user:
            # Construct user_details dictionary
            user_details = {
                'name': user.get('name', ''),
                'mobile': user.get('mobile', ''),
                'age': user.get('age', ''),
                'email': user.get('email', ''),
                'aadhar': user.get('aadhar', ''),
                'dob': user.get('dob', ''),
                'profile_photo': user.get('profile_photo', '')  # Ensure 'profile_photo' key is present
            }
            return render_template("UserProfile.html", user_details=user_details)
        else:
            return 'User not found'  # Handle case where user is not found in the database
    else:
        return redirect(url_for('login'))  # Redirect to login page if user is not logged in

#Admin Profile Page
@app.route('/AProfile')
def AProfile():
    if 'logged_in' in session:
        email = session['user_email']
        print(email)  # Retrieve user's email from session
        user_type = session.get('user_type')  # Retrieve user's type from session
        print(user_type)
        # Choose the collection based on the user type
        if user_type == 'admin':
            collection = db['Admin']
        else:
            return 'Invalid user type'
        
        # Query MongoDB to retrieve user details based on email
        admin = collection.find_one({'email': email})

        if admin:
            # Construct user_details dictionary
            admin_details = {
                'name': admin.get('name', ''),
                'mobile': admin.get('mobile', ''),
                'age': admin.get('age', ''),
                'email': admin.get('email', ''),
                'aadhar': admin.get('aadhar', ''),
                'dob': admin.get('dob', ''),
                'profile_photo': admin.get('profile_photo', '')  # Ensure 'profile_photo' key is present
            }
            return render_template("AdminProfile.html", admin_details=admin_details)
        else:
            return 'Admin not found'  # Handle case where user is not found in the database
    else:
        return redirect(url_for('login'))  # Redirect to login page if user is not logged in

#Super Admin Profile Page
@app.route('/SProfile')
def SProfile():
    if 'logged_in' in session:
        email = session['user_email']
        print(email)  # Retrieve user's email from session
        user_type = session.get('user_type')  # Retrieve user's type from session
        print(user_type)
        # Choose the collection based on the user type
        if user_type == 'superadmin':
            collection = db['SuperAdmin']
        else:
            return 'Invalid user type'
        
        # Query MongoDB to retrieve user details based on email
        superadmin = collection.find_one({'email': email})

        if superadmin:
            # Construct user_details dictionary
            superadmin_details = {
                'name': superadmin.get('name', ''),
                'mobile': superadmin.get('mobile', ''),
                'age': superadmin.get('age', ''),
                'email': superadmin.get('email', ''),
                'aadhar': superadmin.get('aadhar', ''),
                'dob': superadmin.get('dob', ''),
                'profile_photo': superadmin.get('profile_photo', '')  # Ensure 'profile_photo' key is present
            }
            return render_template("SuperAdminProfile.html", superadmin_details=superadmin_details)
        else:
            return 'Super Admin not found'  # Handle case where user is not found in the database
    else:
        return redirect(url_for('login'))  # Redirect to login page if user is not logged in


@app.route('/ASignup', methods=['GET', 'POST'])
def ASignup():
    error = None
    success = None
    server_error = None
    
    if request.method == 'POST':
        name = request.form.get('name')
        mobile = request.form.get('mobile')
        age = int(request.form.get('age'))
        email = request.form.get('email')
        password = request.form.get('password')
        aadhar = request.form.get('aadhar')
        dob = request.form.get('dob')

        # Check if the post request has the file part
        if 'profile-photo' not in request.files:
            error = 'No file selected'
        else:
            file = request.files['profile-photo']
            
            # If user does not select file, browser also submit an empty part without filename
            if file.filename == '':
                error = 'No file selected'
            elif not allowed_file(file.filename):
                error = 'Invalid file type'
            else:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                collection = db['Users']  # Always store users in the Users collection

                # Hash the password before storing it in the database
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

                user_data = {
                    'name': name,
                    'mobile': mobile,
                    'age': age,
                    'email': email,
                    'password': hashed_password,
                    'aadhar': aadhar,
                    'dob': dob,
                    'profile_photo': filename,  # Store the filename in the database
                }

                try:
                    collection.insert_one(user_data)
                    print("User signed up successfully:", user_data)
                    success = 'Account created successfully.'
                except DuplicateKeyError:
                    error = 'User already exists!'
                except Exception as e:
                    print("Server error:", e)
                    server_error = 'Server error. Please try again later.'

    # Render signup form for GET requests
    return render_template('ASignup.html', error=error, success=success, server_error=server_error)


@app.route('/SAsignup', methods=['GET', 'POST'])
def SAsignup():
    error = None
    success = None
    server_error = None
    
    if request.method == 'POST':
        name = request.form.get('name')
        mobile = request.form.get('mobile')
        age = int(request.form.get('age'))
        email = request.form.get('email')
        password = request.form.get('password')
        aadhar = request.form.get('aadhar')
        dob = request.form.get('dob')
        user_type = request.form.get('user-type')

        # Check if the post request has the file part
        if 'profile-photo' not in request.files:
            error = 'No file selected'
        else:
            file = request.files['profile-photo']
            
            # If user does not select file, browser also submit an empty part without filename
            if file.filename == '':
                error = 'No file selected'
            elif not allowed_file(file.filename):
                error = 'Invalid file type'
            else:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                # Choose the collection based on the user type
                if user_type == 'user':
                    collection = db['Users']
                elif user_type == 'admin':
                    collection = db['Admin']
                else:
                    error = 'Invalid user type'

                if error is None:
                    # Hash the password before storing it in the database
                    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

                    user_data = {
                        'name': name,
                        'mobile': mobile,
                        'age': age,
                        'email': email,
                        'password': hashed_password,
                        'aadhar': aadhar,
                        'dob': dob,
                        'profile_photo': filename,  # Store the filename in the database
                    }

                    try:
                        collection.insert_one(user_data)
                        print("User signed up successfully:", user_data)
                        success = 'Account created successfully.'
                    except DuplicateKeyError:
                        error = 'User already exists!'
                    except Exception as e:
                        print("Server error:", e)
                        server_error = 'Server error. Please try again later.'

    # Render signup form for GET requests
    return render_template('SuperAdminSignup.html', error=error, success=success, server_error=server_error)


@app.route('/Amoddisplay', methods=['GET', 'POST'])
def Amod_display():
    # Retrieve user data from the database
    selected_collection = db['Users']
    documents = list(selected_collection.find({}, {'_id': 0, 'profile_photo': 0}))  # Exclude _id and profile_photo
    print("User table flask accessed")

    # Add serial numbers to the documents list
    for index, document in enumerate(documents):
        document['serial_no'] = index + 1

    # Render the AModifyData.html template with user details
    return render_template('AModifyData.html', documents=documents, table_only=True, user_details=None)

@app.route('/Smoddisplay', methods=['GET', 'POST'])
def Smod_display():
    if request.method == 'POST':
        # Handle form submission and retrieve data based on selected role
        selected_role = request.form.get('role')
        if selected_role == 'admin':
            # Retrieve admin data from the database
            selected_collection = db['Admin']
            documents = list(selected_collection.find({}, {'_id': 0, 'profile_photo': 0}))  # Exclude _id and profile_photo
            print("Admin table flask accessed")
        elif selected_role == 'user':
            # Retrieve user data from the database
            selected_collection = db['Users']
            documents = list(selected_collection.find({}, {'_id': 0, 'profile_photo': 0}))  # Exclude _id and profile_photo
        else:
            # Invalid role selected, handle the error (e.g., render an error page)
            return render_template('error.html', message='Invalid role selected')

        # Add serial numbers to the documents list
        for index, document in enumerate(documents):
            document['serial_no'] = index + 1

        # Render only the table content as a response
        return render_template('SModifyData.html', documents=documents, table_only=True, user_details=None)
        
    # Render the initial form
    return render_template('SModifyData.html', user_details=None)

@app.route('/Aedit_data_page/<email>')
def Aedit_data_page(email):
    # Connect to MongoDB
    client = MongoClient('mongodb+srv://flaskuser17:8MOK8vPPRUh1VTMb@cluster0.uxkt8vq.mongodb.net/?tls=true')
    db = client['AuthDetails']
    
    # Query the Users collection
    user_collection = db['Users']
    user_user = user_collection.find_one({'email': email})
    
    # Close the connection to MongoDB
    client.close()
    
    # Check if user_user is not None
    if user_user:
        return render_template('AEditDataPage.html', user_details=user_user)
    else:
        # Print a message indicating that user details were not found
        print("User details not found for email:", email)
        return 'User details not found'
    

@app.route('/Sedit_data_page/<email>')
def Sedit_data_page(email):
    # Query the database to retrieve user details based on the email address
    
    # Connect to MongoDB
    client = MongoClient('mongodb+srv://flaskuser17:8MOK8vPPRUh1VTMb@cluster0.uxkt8vq.mongodb.net/?tls=true')
    db = client['AuthDetails']
    
    # Query the Admin collection
    admin_collection = db['Admin']
    admin_user = admin_collection.find_one({'email': email})
    
    # Query the Users collection
    user_collection = db['Users']
    user_user = user_collection.find_one({'email': email})
    
    # Close the connection to MongoDB
    client.close()
    
    # Check if either admin_user or user_user is not None
    if admin_user:
        return render_template('SEditDataPage.html', user_details=admin_user)
    elif user_user:
        return render_template('SEditDataPage.html', user_details=user_user)
    else:
        # Print a message indicating that user details were not found
        print("User details not found for email:", email)
        return 'User details not found'


# Function to update user details in the Users collection
def update_user_in_user_collection(user_id, updated_data):
    # Assuming users_collection is already defined in your Flask application
    users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': updated_data})

def update_user_in_admin_collection(user_id, updated_data):
    # Connect to MongoDB
    client = MongoClient('mongodb+srv://flaskuser17:8MOK8vPPRUh1VTMb@cluster0.uxkt8vq.mongodb.net/?tls=true')
    db = client['AuthDetails']
    collection = db['Admin']
    
    # Print information for debugging
    print("Updating user details in Admin collection:")
    print("User ID:", user_id)
    print("Updated data:", updated_data)
    
    # Update the user details in the database
    collection.update_one({'_id': ObjectId(user_id)}, {'$set': updated_data})
    
    # Close the connection to MongoDB
    client.close()


@app.route('/Aupdate_user', methods=['POST'])
def Aupdate_user():
    try:
        # Get form data
        user_id = request.form['user_id']
        name = request.form['name']
        mobile = request.form['mobile']
        aadhar = request.form['aadhar']
        dob = request.form['dob']
        email = request.form['email']
        age = request.form['age']

        # Update user details in the Users collection
        updated_data = {
            'name': name,
            'mobile': mobile,
            'aadhar': aadhar,
            'dob': dob,
            'email': email,
            'age': age
        }
        update_user_in_user_collection(user_id, updated_data)

        # Redirect back to the ModifyData.html page
        return redirect(url_for('Amod_display'))
    except Exception as e:
        # Return error response if an exception occurs
        return jsonify({'error': str(e)})
    
@app.route('/Supdate_user', methods=['POST'])
def Supdate_user():
    try:
        # Get form data
        user_id = request.form['user_id']
        name = request.form['name']
        mobile = request.form['mobile']
        aadhar = request.form['aadhar']
        dob = request.form['dob']
        email = request.form['email']
        age = request.form['age']

        # Update user details in the Users collection
        updated_data = {
            'name': name,
            'mobile': mobile,
            'aadhar': aadhar,
            'dob': dob,
            'email': email,
            'age': age
        }
        update_user_in_admin_collection(user_id, updated_data)

        # Redirect back to the ModifyData.html page
        return redirect(url_for('Smod_display'))
    except Exception as e:
        # Return error response if an exception occurs
        return jsonify({'error': str(e)})


@app.route('/Adelete_user_by_email', methods=['POST'])
def Adelete_user_by_email():
    try:
        # Retrieve the email from the request data
        email = request.json.get('email')
        print(email)
        
        # Delete the user from the database based on the email
        result = db['Users'].delete_one({'email': email})
        if result.deleted_count == 1:
            print("User deleted successfully.")
            return "User deleted successfully"
        else:
            print("User not found.")
            return "User not found"
    except Exception as e:
        print("Error deleting user:", e)
        # Handle the error and return an error message
        return "Error deleting user"

@app.route('/Sdelete_user_by_email', methods=['POST'])
def Sdelete_user_by_email():
    try:
        # Retrieve the email from the request data
        email = request.json.get('email')
        
        # Check if the email exists in the Admin collection
        print("Searching Admin collection for email:", email)
        admin_result = db['Admin'].delete_one({'email': email})
        
        # Check if the email exists in the Users collection if it's not found in the Admin collection
        if admin_result.deleted_count == 0:
            # If email not found in Admin collection, search in Users collection
            print("Searching Users collection for email:", email)
            user_result = db['Users'].delete_one({'email': email})
            if user_result.deleted_count == 1:
                print("User deleted successfully.")
                return "User deleted successfully"
            else:
                print("User not found.")
                return "User not found"
        else:
            print("Admin deleted successfully.")
            return "Admin deleted successfully"
    except Exception as e:
        print("Error deleting user or admin:", e)
        # Handle the error and return an error message
        return "Error deleting user or admin"




@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/real-time-analysis', methods=['GET', 'POST'])
def Analysis():
    return render_template("User_Dashboard.html")

@app.route('/Areal-time-analysis', methods=['GET', 'POST'])
def AdminAnalysis():
    return render_template("AdminAnalysis.html")

@app.route('/Sreal-time-analysis', methods=['GET', 'POST'])
def SuperAdminAnalysis():
    return render_template("SuperAdminAnalysis.html")



# Function to check if the filename has an allowed extension
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

UPLOAD_FOLDER = "D:\\Pune Metro Rail Hackathon\\CodeV5SuperAdminOTP\\uploads"

def process_video(video_file):
    # Global variables to store ROI coordinates
    roi_start = None
    roi_end = None

    # Function to handle mouse events for selecting ROI
    def mouse_callback(event, x, y, flags, param):
        nonlocal roi_start, roi_end

        if event == cv2.EVENT_LBUTTONDOWN:
            # Start selecting ROI
            roi_start = (x, y)
        elif event == cv2.EVENT_LBUTTONUP:
            # End selecting ROI
            roi_end = (x, y)
            cv2.rectangle(param, roi_start, roi_end, (0, 255, 0), 2)
            cv2.imshow("Image", param)

    # Function to check if a point is inside a rectangle
    def point_inside_rect(x, y, rect):
        x1, y1, x2, y2 = rect
        return x1 <= x <= x2 and y1 <= y <= y2

    cap = cv2.VideoCapture(video_file)

    frame_width = int(cap.get(3))
    frame_height = int(cap.get(4))

    model = YOLO("../YOLO-Weights/yolov8l.pt")
    classNames = ["person"]

    # Define the limit for number of persons in ROI
    LIMIT_PERSONS = 7

    # Create a window to display the video
    cv2.namedWindow("Image")

    # Set mouse callback function
    cv2.setMouseCallback("Image", mouse_callback)

    while True:
        success, img = cap.read()

        if roi_start and roi_end:
            # Draw the ROI rectangle
            cv2.rectangle(img, roi_start, roi_end, (0, 255, 0), 2)

            # Get ROI coordinates
            x1 = min(roi_start[0], roi_end[0])
            y1 = min(roi_start[1], roi_end[1])
            x2 = max(roi_start[0], roi_end[0])
            y2 = max(roi_start[1], roi_end[1])

            # Define the ROI rectangle
            roi_rect = (x1, y1, x2, y2)

            # Doing detections using YOLOv8 frame by frame
            results = model(img)

            # Count the number of people within the ROI
            people_in_roi = 0

            for r in results:
                boxes = r.boxes
                for box in boxes:
                    x1, y1, x2, y2 = box.xyxy[0]
                    x1, y1, x2, y2 = int(x1), int(y1), int(x2), int(y2)

                    # Check if the center of the bounding box is inside the ROI
                    center_x = (x1 + x2) // 2
                    center_y = (y1 + y2) // 2
                    if point_inside_rect(center_x, center_y, roi_rect):
                        people_in_roi += 1

                    cv2.rectangle(img, (x1, y1), (x2, y2), (255, 0, 255), 3)

                    conf = math.ceil((box.conf[0] * 100) / 100)
                    cls = int(box.cls[0])
                    if cls < len(classNames):  # Ensure class index is within range
                        class_name = classNames[cls]
                        label = f'{class_name}{conf}'
                        t_size = cv2.getTextSize(label, 0, fontScale=1, thickness=2)[0]
                        c2 = x1 + t_size[0], y1 - t_size[1] - 3
                        cv2.rectangle(img, (x1, y1), c2, [255, 0, 255], -1, cv2.LINE_AA)  # filled
                        cv2.putText(img, label, (x1, y1 - 2), 0, 1, [255, 255, 255], thickness=1, lineType=cv2.LINE_AA)

            # Display the number of people within the ROI
            cv2.putText(img, f'People in ROI: {people_in_roi}', (10, 50), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)

            # Check if the number of people exceeds the limit
            if people_in_roi > LIMIT_PERSONS:
                # Display message
                cv2.putText(img, 'Please move to other counters', (10, 100), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)

            # Yield the processed frame as a byte array
            yield cv2.imencode('.jpg', img)[1].tobytes()

        # Display the frame
        cv2.imshow("Image", img)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    # Release the video capture object and close windows
    cap.release()
    cv2.destroyAllWindows()

@app.route('/analyze/<video_file>')
def analyze(video_file):
    for frame in process_video(video_file):
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n'
               + frame
               + b'\r\n')

@app.route('/save-file', methods=['POST'])
def save_file():
    if 'file' not in request.files:
        return redirect(request.url)

    file = request.files['file']

    if file.filename == '':
        return redirect(request.url)

    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        result = process_video(os.path.join(UPLOAD_FOLDER, filename))
        return result

if __name__ == "__main__":
    app.run(debug=True)  # Set debug=True for development mode
