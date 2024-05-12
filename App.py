from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, jsonify, Response
from flask_mail import Mail, Message
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
from pymongo.errors import DuplicateKeyError
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'flaskuser17s@gmail.com'  # Update with your Gmail address
app.config['MAIL_PASSWORD'] = 'vkfa qegm udzn pcbp'  # Update with your Gmail password
mail = Mail(app)

# MongoDB connection
client = MongoClient('mongodb+srv://flaskuser17:8MOK8vPPRUh1VTMb@cluster0.uxkt8vq.mongodb.net/')
db = client['WebInvest']
admin_collection = db['Admin']
investor_collection = db['Investors']
project_builder_collection = db['ProjectBuilders']
invested_collection = db['Invested']
wishlist_collection = db['Wishlist']


# Define the upload folder
UPLOAD_FOLDER = "D:\\Bangalore Hackathon\\useruploads"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}  # Allowed file extensions

# Configure Flask app
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to check if a filename has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Index Page
@app.route('/')
def Index():
    print("Accessed Index page.")
    return render_template("Index.html")

@app.route('/projects/<idea>')
def project_details(idea):
    return render_template("projects_details.html")

from flask import request, jsonify

@app.route('/fetch_data_with_filters', methods=['GET'])
def fetch_data_with_filters():
    # Get filter parameters from request
    min_funding = request.args.get('minFundingInput')
    max_funding = request.args.get('maxFundingInput')
    domain_filter = request.args.get('domain-filter')

      # Define the filter criteria
    filter_criteria = {}

    # Add funding range filter if provided
    if min_funding is not None and max_funding is not None:
        filter_criteria["funding_needed"] = {"$gte": min_funding, "$lte": max_funding}

    # Add domain filter if provided
    if domain_filter:
        filter_criteria["domain"] = domain_filter

    try:
        # Define projection to fetch only domain and idea fields
        projection = {"domain": 1, "idea": 1, "_id": 0}

        # Filter projects based on the criteria and projection
        filtered_projects = project_builder_collection.find(filter_criteria, projection)

        # Convert MongoDB cursor to list of dictionaries
        filtered_projects_list = list(filtered_projects)

        # Print filtered projects
        print("Filtered Projects:")
        for project in filtered_projects_list:
            print(project)

        # Return filtered projects as JSON response
        return jsonify(data=filtered_projects_list)

    except Exception as e:
        # Handle exceptions and return an error response
        return jsonify(error=str(e)), 500







@app.route('/handle_action', methods=['POST'])
def handle_action():
    # Get data from the request
    data = request.json

    # Extract idea, domain, and action from the request data
    idea = data.get('idea')
    domain = data.get('domain')
    action = data.get('action')

    # Fetch the user's email from the session
    user_email = session.get('email')

    # Print relevant information for debugging
    print('User Email:', user_email)
    print('Action:', action)
    print('Idea:', idea)
    print('Domain:', domain)

    # Check if the user is authenticated
    if not user_email:
        return jsonify({'error': 'User not authenticated'}), 401

    # Check if the action is valid
    if action not in ['invest', 'wishlist']:
        return jsonify({'error': 'Invalid action'}), 400

    # Check if the project already exists in the corresponding collection
    if action == 'invest':
        existing_project = db.Invested.find_one({'idea': idea, 'domain': domain})
    elif action == 'wishlist':
        existing_project = db.Wishlist.find_one({'idea': idea, 'domain': domain})

    # If the project exists and the action is to invest or add to wishlist
    if existing_project:
        # Check if the existing project belongs to the current user
        if existing_project['user_email'] == user_email:
            # If it belongs to the current user, remove it from the database
            if action == 'invest':
                db.Invested.delete_one({'idea': idea, 'domain': domain})
            elif action == 'wishlist':
                db.Wishlist.delete_one({'idea': idea, 'domain': domain})
            return jsonify({'message': 'Project removed successfully'})
        else:
            # If it belongs to a different user, add it with the current user's email
            if action == 'invest':
                db.Invested.insert_one({'idea': idea, 'domain': domain, 'user_email': user_email})
                return jsonify({'message': 'Project invested successfully'})
            elif action == 'wishlist':
                db.Wishlist.insert_one({'idea': idea, 'domain': domain, 'user_email': user_email})
                return jsonify({'message': 'Project added to wishlist'})
    
    # If the project does not exist, add it with the current user's email
    else:
        if action == 'invest':
            db.Invested.insert_one({'idea': idea, 'domain': domain, 'user_email': user_email})
            return jsonify({'message': 'Project invested successfully'})
        elif action == 'wishlist':
            db.Wishlist.insert_one({'idea': idea, 'domain': domain, 'user_email': user_email})
            return jsonify({'message': 'Project added to wishlist'})



@app.route('/fetch_project_data/<idea>')
def fetch_project_data(idea):
    # Access the ProjectBuilders collection
    collection = db['ProjectBuilders']
    
    # Fetch project data based on the provided idea, excluding the _id field
    project_data = list(collection.find({"idea": idea}, {'_id': 0}))
    
    # Print the project data to the server console for debugging
    print(project_data)
    
    # Return the project data as JSON
    return jsonify(project_data)

# Contact Page
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        mobile = request.form['mobile']
        email = request.form['email']
        message = request.form['message']

        # Send email
        msg = Message('Contact Form Submission', sender='flaskuser17@gmail.com', recipients=['ahildoesstudy@gmail.com'])
        msg.body = f"Name: {name}\nMobile: {mobile}\nEmail: {email}\nMessage: {message}"
        mail.send(msg)
        return redirect(url_for('Index'))
    return render_template("Index.html")

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    success = None
    server_error = None
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')

        # Validate password format
        password_error = validate_password(password)
        if password_error:
            error = password_error
        elif password != confirm_password:
            error = 'Password and Confirm Password do not match.'
        else:
            try:
                # Hash the password using bcrypt and encode it to bytes
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

                collection = db['Investors']
                existing_user = collection.find_one({'email': email})

                if existing_user:
                    error = 'User already exists.'
                else:
                    user_data = {
                        'name': name,
                        'email': email,
                        'password': hashed_password,  # Store the hashed password as bytes
                    }
                    collection.insert_one(user_data)
                    success = 'Account created successfully.'
            except Exception as e:
                print("Server error:", e)
                server_error = 'Server error. Please try again later.'

    return render_template('Signup.html', error=error, success=success, server_error=server_error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = db['Investors'].find_one({'email': email})

        if user:
            # Retrieve the hashed password from the database
            stored_password_bytes = user['password']

            # Check if the entered password matches the hashed password stored in the database
            if bcrypt.checkpw(password.encode('utf-8'), stored_password_bytes):
                session['email'] = email  # Store email in session
                session['user_type'] = 'investor'
                return redirect('/investor_dashboard')
            else:
                error = 'Incorrect password.'
        else:
            error = 'User not found.'

    return render_template('Login.html', error=error)

@app.route('/get_current_user_email')
def getCurrentUserEmail():
    # Retrieve the user's email from the session
    email = session.get('email')
    print(email)  # Debugging print
    return jsonify({'email': email})  # Return the email as JSON response


def validate_password(password):
    if len(password) < 8:
        return 'Password must be at least 8 characters long.'
    if not any(char.isupper() for char in password):
        return 'Password must contain at least one uppercase letter.'
    if not any(char.islower() for char in password):
        return 'Password must contain at least one lowercase letter.'
    if not any(char.isdigit() for char in password):
        return 'Password must contain at least one digit.'
    if not any(char in '!@#$%^&*()_+}{:;\'?/\|.,' for char in password):
        return 'Password must contain at least one special character.'
    return None



from pymongo.errors import OperationFailure

# Define a global variable to keep track of the current page
current_page = 1
# Define a global variable to store the total number of documents per page
documents_per_page = 6

# Modify the fetch_data route
@app.route('/fetch_data')
def fetch_data():
    global current_page
    # Get the search term from the request
    search_term = request.args.get('search_term')
    # Get the action from the request (next or previous)
    action = request.args.get('action')

    # Define the query based on the search term
    query = {}  # Empty query to fetch all documents
    sort = None  # Default to no sorting
    if search_term:
        # Use the $text operator for text search
        query = {'$text': {'$search': search_term}}
        # Add text score metadata for relevance scoring
        sort = [('score', {'$meta': 'textScore'})]

    try:
        if action == 'next':
            current_page += 1
        elif action == 'previous' and current_page > 1:
            current_page -= 1

        # Calculate the skip value based on the current page
        skip = (current_page - 1) * documents_per_page

        # Fetch data from the MongoDB collection based on the query, sort, and pagination
        cursor = project_builder_collection.find(query, {'_id': 0, 'idea': 1, 'domain': 1}).skip(skip).limit(documents_per_page).sort(sort) if sort else project_builder_collection.find(query, {'_id': 0, 'idea': 1, 'domain': 1}).skip(skip).limit(documents_per_page)

        # Convert cursor to list of documents
        data = list(cursor)

        # If no data is found, return a specific message
        if not data:
            return jsonify({'message': 'Sorry, no projects found for your query.'})

        # Print the fetched data to the console
        print('Fetched Data:', data)

        # Return the fetched data as JSON response along with pagination information
        return jsonify({'data': data, 'current_page': current_page})
    except OperationFailure as e:
        return jsonify({'error': 'An error occurred while fetching data'}), 500
    

# Route to check if the idea exists in the database
@app.route('/check_idea')
def check_idea():
    idea = request.args.get('idea')

    # Query MongoDB to check if the idea exists in the collection
    result = project_builder_collection.find_one({'idea': idea})

    # If the idea exists, return True, else return False
    if result:
        return jsonify({'exists': True})
    else:
        return jsonify({'exists': False})


import requests

@app.route('/investor_dashboard')
def investor_dashboard():
    try:
        # Make a request to the fetch_data route to get the data
        response = requests.get('http://localhost:5000/fetch_data')
        if response.status_code == 200:
            # Extract data from the response
            data = response.json()

            # Print the fetched data to the console
            print('Fetched Data:', data)

            # Return the fetched data along with rendering the template
            return render_template('InvestorDashBoard.html', data=data)
        else:
            return Response('Failed to fetch data from the server.', status=response.status_code, mimetype='text/plain')
    except Exception as e:
        print('An error occurred:', e)
        return Response('An error occurred while processing the request.', status=500, mimetype='text/plain')







@app.route('/projectbuilder', methods=['GET', 'POST'])
def project_builder():
    if request.method == 'POST':
        # Get form data from request
        domain = request.form.get('domain')
        idea = request.form.get('projectDescription')
        description = request.form.get('comprehensiveDescription')
        target_market = request.form.get('targetMarket')
        funding_needed = request.form.get('fundingNeeded')
        name = request.form.get('name')
        email = request.form.get('email')
        
        print('Received form data:')
        print('Domain:', domain)
        print('Idea:', idea)
        print('Description:', description)
        print('Target Market:', target_market)
        print('Funding Needed:', funding_needed)
        print('Name:', name)
        print('Email:', email)
        
        # Check if project already exists
        existing_project = project_builder_collection.find_one({
            'domain': domain,
            'idea': idea,
            'name': name,
            'email': email
        })
        
        if existing_project:
            error_message = 'Project already exists for this user.'
            print('Error:', error_message)
            return render_template("ProjectBuilderDashBoard.html", error=error_message)
        
        # Handle file uploads
        uploaded_files = request.files.getlist('mediaFiles')
        uploaded_filenames = []
        for file in uploaded_files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                uploaded_filenames.append(filename)
        
        # Print uploaded filenames for debugging
        print('Uploaded Files:', uploaded_filenames)
        
        # Store the data in MongoDB
        project_data = {
            'domain': domain,
            'idea': idea,
            'description': description,
            'target_market': target_market,
            'funding_needed': funding_needed,
            'name': name,
            'email': email,
            'uploaded_files': uploaded_filenames  # Add uploaded filenames to the data
        }
        project_builder_collection.insert_one(project_data)
        print('Data stored in MongoDB:', project_data)
        
        # Display success message
        success_message = 'Project submitted successfully.'
        # Render the template with success message and JavaScript for redirection
        return render_template("ProjectBuilderDashBoard.html", success=success_message, redirect=True)
    else:
        # Render the template without redirection
        return render_template("ProjectBuilderDashBoard.html", redirect=False)

@app.route('/investor-profile')
def investor_profile():
    return render_template('InvestorProfile.html')


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        session.pop('logged_in', None)
        return redirect(url_for('login'))
    # In case the request method is not POST, we should redirect to some page or show an error message
    return redirect(url_for('login'))  # Redirect to login page if the request method is not POST






UPLOAD_INVEST = "D:\\Bangalore Hackathon\\investoruploads"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi'}
app.config['UPLOAD_INVEST'] = UPLOAD_INVEST



# Assuming UPLOAD_INVEST is defined somewhere earlier in your code
UPLOAD_INVEST = "D:\\Bangalore Hackathon\\investoruploads"



@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'GET':
        # Check if user is logged in
        if 'email' in session:
            user_email = session['email']
            # Query MongoDB to fetch user details
            user = investor_collection.find_one({"email": user_email})
            if user:
                # Initialize an empty dictionary to store user details
                user_details = {}
                # Add fields with values to the dictionary
                for key, value in user.items():
                    # Exclude sensitive fields and fields that shouldn't be displayed
                    if key not in ["_id", "password", "file"]:
                        user_details[key] = value
                # Construct the profile image URL
                profile_image_filename = user.get('profileimage', 'defaultprofile.png')
                profile_image_url = url_for('profile_image', filename=profile_image_filename)
                user_details['profile_image_url'] = profile_image_url
                return jsonify(user_details)  # Return user details as JSON
            else:
                return jsonify({"error": "User details not found."}), 404
        else:
            return jsonify({"error": "User not logged in."}), 401

    elif request.method == 'POST':
        # Check if user is logged in
        if 'email' in session:
            user_email = session['email']
            # Check if the request contains a file
            if 'file' in request.files:
                file = request.files['file']
                # If user selects a file, save it as the profile image
                if file.filename != '':
                    if allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        file.save(os.path.join(app.config['UPLOAD_INVEST'], filename))
                        # Update user profile in MongoDB to include the filename
                        investor_collection.update_one({"email": user_email}, {"$set": {"profileimage": filename}})
                        # Redirect to the same page after updating the profile image
                        return redirect(url_for('profile'))
                    else:
                        return jsonify({"error": "File type not allowed"}), 400

            # Update other user fields
            fields_to_update = {key: request.form.get(key) for key in request.form if key != 'email'}
            investor_collection.update_one({"email": user_email}, {"$set": fields_to_update})
            # Redirect to the same page after updating the profile details
            return redirect(url_for('profile'))
        else:
            return jsonify({"error": "User not logged in."}), 401


@app.route('/profile_image/<filename>')
def profile_image(filename):
    if filename == 'defaultprofile.png':
        return send_from_directory(app.config['UPLOAD_INVEST'], filename)
    else:
        return send_from_directory(app.config['UPLOAD_INVEST'], filename)




@app.route('/add_more_details', methods=['GET', 'POST'])
def add_more_details():
    if request.method == 'POST':
        print("Received POST request to add_more_details route.")
        # Get the user's email from the session
        user_email = session.get('email')

        # Retrieve user details from MongoDB using the email
        user = investor_collection.find_one({'email': user_email})

        if user:
            print("User email:", user_email)
            print("Retrieved user details:", user)

            # Get form data including email
            email = request.form.get('email')
            name = request.form.get('name')
            age = request.form.get('age')
            dob = request.form.get('dob')
            phone = request.form.get('phone')
            interests = request.form.get('interests')

            print("Form data:")
            print("Email:", email)
            print("Name:", name)
            print("Age:", age)
            print("Date of Birth:", dob)
            print("Phone:", phone)
            print("Interests:", interests)

            # Update fields in the user document
            update_data = {
                'email': email,  # Update email
                'name': name,
                'age': age,
                'dob': dob,
                'phone': phone,
                'interests': interests
            }

            # Update the user document in MongoDB
            investor_collection.update_one({'email': user_email}, {'$set': update_data})

            # Update email in session
            session['email'] = email

            # Redirect to the profile page or any other page
            return redirect(url_for('investor_profile'))
        else:
            # Handle the case where the user is not found
            return render_template('error.html', message='User not found')

    else:
        print("Received GET request to add_more_details route.")
        # Render the HTML template for add more details page
        return render_template('AddMoreDetails.html')
    



@app.route('/projects-invested-data')
def fetch_projects_invested_data():
    # Get the user's email from the session
    user_email = session.get('email')

    # Fetch data from MongoDB and exclude '_id' field
    invested_projects = list(invested_collection.find({'user_email': user_email}, {'_id': 0}))

    print(invested_projects)
    return jsonify(invested_projects)


@app.route('/projects-invested')
def projects_invested_page():
    return render_template('ProjectsInvested.html')



@app.route('/projects-wish-data')
def fetch_projects_wish_data():
    # Get the user's email from the session
    user_email = session.get('email')

    # Fetch data from MongoDB and exclude '_id' field
    wished_projects = list(wishlist_collection.find({'user_email': user_email}, {'_id': 0}))

    print(wished_projects)
    return jsonify(wished_projects)

@app.route('/projects-wish')
def projects_wish_page():
    return render_template('Wishlist.html')


if __name__ == '__main__':
    app.run(debug=True)
