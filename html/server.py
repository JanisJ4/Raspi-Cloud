from flask import Flask, request, jsonify, redirect, url_for, send_from_directory, send_file, make_response
from flask_cors import CORS
import socket
import sqlite3
import os
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
import jwt  # Ensure jwt library is installed, e.g., with "pip install PyJWT"
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import json
import mimetypes 
from pathlib import Path
import re
from datetime import datetime
import shutil

# Initialize the Flask app and other extensions
app = Flask(__name__)
jwt_manager = JWTManager(app)
bcrypt = Bcrypt(app)
# Generate a random secret key for JWT
app.config['SECRET_KEY'] = os.urandom(24).hex()  

# Enable Cross-Origin Resource Sharing (CORS)
CORS(app, resources={r"/*": {"origins": "*"}})

# Determine the path to the user's "Documents" directory
home_directory = '/srv/Raspi-Cloud/'  # Replace with `Path(os.environ['HOME'])` for dynamic home directory

# Paths for the user database, files database, and uploaded files directory
db_path = home_directory + 'Database/user_database.db'
db_files_path = home_directory + 'Database/files.db'
upload_folder = home_directory + 'Database/uploaded_files'

# Create the necessary directories if they don't exist
os.makedirs(home_directory + 'Database', exist_ok=True)
os.makedirs(upload_folder, exist_ok=True)
os.makedirs(home_directory + 'Database/uploaded_files/1', exist_ok=True)

# Create the user database if it doesn't exist
if not os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create a table for users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            hashed_password TEXT
        )
    ''')

    # Create a table for groups
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            group_id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT UNIQUE
        )
    ''')

    # Create a table for group memberships
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            user_id INTEGER,
            group_id INTEGER,
            right_id INTEGER,
            PRIMARY KEY (user_id, group_id, right_id),
            FOREIGN KEY (user_id) REFERENCES users(user_id),
            FOREIGN KEY (group_id) REFERENCES groups(group_id),
            FOREIGN KEY (right_id) REFERENCES rights(right_id)
        )
    ''') 

    # Create a table for rights
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rights (
            right_id INTEGER PRIMARY KEY AUTOINCREMENT,
            right_name TEXT UNIQUE
        )
    ''')

    # Create a table for group rights
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS group_rights (
            right_id INTEGER PRIMARY KEY AUTOINCREMENT,
            right_name TEXT UNIQUE
        )
    ''')

    # Insert global rights (owner, admin, user)
    global_rights = ['owner', 'admin', 'user']
    for right in global_rights:
        cursor.execute('INSERT OR IGNORE INTO rights (right_name) VALUES (?)', (right,))

    # Insert group-specific rights (read, write, local_admin)
    group_rights = ['read', 'write', 'local_admin']
    for right in group_rights:
        cursor.execute('INSERT OR IGNORE INTO group_rights (right_name) VALUES (?)', (right,))

    # Create a table for user rights
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_rights (
            user_id INTEGER,
            right_id INTEGER,
            PRIMARY KEY (user_id, right_id),
            FOREIGN KEY (user_id) REFERENCES users(user_id),
            FOREIGN KEY (right_id) REFERENCES rights(right_id)
        )
    ''')

    conn.commit()
    conn.close()

# Create the files database if it doesn't exist
if not os.path.exists(db_files_path):
    conn = sqlite3.connect(db_files_path)
    cursor = conn.cursor()

    # Create a table `files` with additional columns including 'folder'
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER,
            filename TEXT,
            created_at DATETIME,
            last_modified_by INTEGER,
            size INTEGER,
            folder TEXT,  -- Path to the folder where the file/folder is stored
            is_folder BOOLEAN DEFAULT FALSE,  -- Indicates whether the entry is a folder
            FOREIGN KEY (group_id) REFERENCES groups(group_id)
        )
    ''')
    conn.commit()
    conn.close()

def log_login_attempt(timestamp, username, ip_address, status, message):
    # Log login attempts to a file
    with open(home_directory + "Database/uploaded_files/1/login_attempts.log", "a") as log_file:
        # Write the log entry with timestamp, username, IP address, status, and message
        log_file.write(f"{timestamp} - Username: {username}, IP: {ip_address}, Status: {status}, Message: {message}\n")

# Utility function to establish a database connection
def get_db_connection():
    # Connect to the SQLite database using the path defined earlier
    conn = sqlite3.connect(db_path)
    # Set row factory to sqlite3.Row to access data by names
    conn.row_factory = sqlite3.Row
    return conn

def get_user_id(username):
    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # SQL query to retrieve the user_id based on the username
    cursor.execute('SELECT user_id FROM users WHERE username = ?', (username,))

    # Fetch the result
    result = cursor.fetchone()

    # Close the connection
    conn.close()

    # Check if a result is present and return the user_id
    if result:
        return result[0]
    else:
        return None

def get_username(user_id):
    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # SQL query to retrieve the username based on the user_id
    cursor.execute('SELECT username FROM users WHERE user_id = ?', (user_id,))

    # Fetch the result
    result = cursor.fetchone()

    # Close the connection
    conn.close()

    # Check if a result is present and return the username
    if result:
        return result[0]
    else:
        return None

def check_user_is_admin(user_id):
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the user has admin rights
    cursor.execute('''
        SELECT r.right_name
        FROM user_rights ur
        JOIN rights r ON ur.right_id = r.right_id
        WHERE ur.user_id = ? AND r.right_name IN ('admin', 'owner')
    ''', (user_id,))

    admin_rights = cursor.fetchall()
    conn.close()

    # Return True if any admin rights are found
    return any(admin_rights)

def check_user_role(user_id, required_right, group_id=None):
    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor()

    if group_id:
        # Check if the user has the required group right
        query = '''
        SELECT COUNT(*) as count
        FROM group_members gm
        JOIN users u ON gm.user_id = u.user_id
        JOIN groups g ON gm.group_id = g.group_id
        JOIN group_rights gr ON gm.right_id = gr.right_id
        WHERE gm.group_id = ? AND u.username = ? AND gr.right_name = ?
        '''
        result = conn.execute(query, (group_id, get_username(user_id), required_right)).fetchone()
        conn.close()
        
        # Return True if the user has the group right (count > 0)
        return result['count'] > 0

    # Check global rights if no specific group is specified or no group-specific rights were found
    query = '''
    SELECT COUNT(*) as count
    FROM users u
    JOIN user_rights ur ON u.user_id = ur.user_id
    JOIN rights r ON ur.right_id = r.right_id
    WHERE u.username = ? AND r.right_name = ?
    '''
    result = conn.execute(query, (get_username(user_id), required_right)).fetchone()
    conn.close()
    
    # Return True if the user has the right (count > 0)
    return result['count'] > 0

@app.route('/login', methods=['POST'])
def login():
    try:
        # Retrieve JSON data from the request
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        # Retrieve the user's IP address and the current timestamp
        ip_address = request.remote_addr
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Log the login attempt
        log_login_attempt(timestamp, username, ip_address, "Success", "")

        # Validate the username input
        if not re.match(r"^[A-Za-z0-9]+$", username):
            return jsonify({'success': False, 'message': 'Invalid username'})

        # Connect to the SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if the user already exists in the database
        cursor.execute('SELECT hashed_password, user_id FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()

        if result is None:
            # Check if there are any existing users
            cursor.execute('SELECT COUNT(*) FROM users')
            user_count = cursor.fetchone()[0]

            if user_count == 0:
                # Add the first user to the database
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                cursor.execute('INSERT INTO users (username, hashed_password) VALUES (?, ?)', (username, hashed_password))
                user_id = cursor.lastrowid

                # Assign 'owner' rights to the first user
                cursor.execute('SELECT right_id FROM rights WHERE right_name = "owner"')
                owner_right_id = cursor.fetchone()[0]
                cursor.execute('INSERT INTO user_rights (user_id, right_id) VALUES (?, ?)', (user_id, owner_right_id))

                # Check and create the "First Group" if it doesn't exist
                cursor.execute('SELECT group_id FROM groups WHERE group_name = "Your group"')
                group = cursor.fetchone()
                if group is None:
                    cursor.execute('INSERT INTO groups (group_name) VALUES ("Your group")')
                    group_id = cursor.lastrowid
                else:
                    group_id = group[0]

                # Add the user to the "First Group"
                cursor.execute('INSERT INTO group_members (user_id, group_id) VALUES (?, ?)', (user_id, group_id))

                conn.commit()
                # Create a JWT for the user
                token = create_access_token(identity=user_id)
                conn.close()
                return jsonify({'success': True, 'message': 'New user created.', 'token': token})
            conn.close()
            return jsonify({'success': False, 'message': 'Have an admin create an account.'})
        else:
            # Check if the provided password matches the hashed password in the database
            if bcrypt.check_password_hash(result[0], password):
                user_id = result[1]
                # Create a JWT for the user
                token = create_access_token(identity=user_id)
                conn.close()
                return jsonify({'success': True, 'token': token})
            else:
                conn.close()
                return jsonify({'success': False, 'message': 'Wrong password.'})
    except Exception as e:
        # Handle any exceptions during the login process
        print('Error during login:', str(e))
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/create_user', methods=['POST'])
@jwt_required()  # Require a valid JWT to access this route
def create_user():
    # Retrieve the user ID from the JWT
    user_id = get_jwt_identity()
    data = request.get_json()
    username = str(data.get('username'))
    password = str(data.get('password'))

    # Connect to the SQLite database
    conn = sqlite3.connect(db_path)

    # Check if the requesting user has admin rights
    if not check_user_is_admin(user_id):
        return jsonify({'success': False, 'message': 'Permission denied.'})

    # Validate the username input
    if not re.match(r"^[A-Za-z0-9]+$", username):
        return jsonify({'success': False, 'message': 'Invalid username'})

    cursor = conn.cursor()

    # Check if the username already exists
    cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
    if cursor.fetchone() is not None:
        return jsonify({'success': False, 'message': 'Username already taken.'})

    # Add the new user to the database
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    cursor.execute('INSERT INTO users (username, hashed_password) VALUES (?, ?)', (username, hashed_password))
    
    # Commit the transaction and close the connection
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'New user created.'})

@app.route('/create_group', methods=['POST'])
@jwt_required()  # Require a valid JWT to access this route
def create_group():
    # Retrieve the user ID from the JWT
    user_id = get_jwt_identity()
    try:
        data = request.get_json()
        group_name = data.get('group_name')

        # Validate group name input
        if not group_name:
            return jsonify({'success': False, 'message': 'Group name required.'})

        # Validate the username input
        if not re.match(r"^[A-Za-z0-9]+$", group_name):
            return jsonify({'success': False, 'message': 'Invalid group name'})
        
        conn = sqlite3.connect(db_path)

        # Check if the requesting user has admin rights
        if not check_user_is_admin(user_id):
            return jsonify({'success': False, 'message': 'Permission denied.'})

        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            # Check if the group name already exists
            cursor.execute('SELECT 1 FROM groups WHERE group_name = ?', (group_name,))
            if cursor.fetchone() is not None:
                return jsonify({'success': False, 'message': 'Group name already assigned.'})

            # Add the new group to the database
            cursor.execute('INSERT INTO groups (group_name) VALUES (?)', (group_name,))
            conn.commit()

        return jsonify({'success': True, 'message': 'New group created.'})

    # Handle SQLite and general exceptions
    except sqlite3.Error as e:
        print('Database error:', str(e))
        return jsonify({'success': False, 'message': 'Database error: ' + str(e)}), 500
    except Exception as e:
        print('General error:', str(e))
        return jsonify({'success': False, 'message': 'Error: ' + str(e)}), 500

def get_group_upload_folder(group_id, folder):
    # Create a user directory if it doesn't exist
    group_folder = os.path.join(upload_folder, str(group_id))
    if folder != "" and folder is not None:
        group_folder = os.path.join(folder, folder)
    os.makedirs(group_folder, exist_ok=True)
    return group_folder

@app.route('/upload_file', methods=['POST'])
@jwt_required()  # Ensure the user is authenticated via JWT
def upload_file():
    user_id = get_jwt_identity()  # Get the user's identity from the JWT
    file = request.files.get('file')  # Extract the uploaded file from the request
    json_data = request.form.get('json')  # Extract the additional JSON data (like folder and group ID)

    # Debugging prints to check the received file and JSON data
    print("Received file:", file)
    print("Received JSON data:", json_data)

    # Validate the presence of both file and JSON data
    if file and json_data:
        try:
            # Parse the JSON data
            data = json.loads(json_data)
            folder = data.get('folder')  # Folder to upload the file to
            group_id = data.get("group")  # Group ID for the upload
            # Ensure group ID is present
            if group_id is None:
                return jsonify({'success': False, 'message': 'Group ID missing in data.'})
        except (json.JSONDecodeError, TypeError):
            # Handle errors in JSON parsing
            return jsonify({'success': False, 'message': 'Could not parse JSON data.'})
    else:
        # Handle case where either file or JSON data is missing
        return jsonify({'success': False, 'message': 'Invalid or missing data.'})

    try:
        # Check if the user has appropriate permissions to upload the file
        if (check_user_role(user_id, 'write', group_id) or 
            check_user_role(user_id, 'local_admin', group_id) or 
            check_user_is_admin(user_id)):

            # Securely generate a filename and save the file in the designated folder
            filename = secure_filename(file.filename)
            file_path = os.path.join(get_group_upload_folder(group_id, folder), filename)
            file.save(file_path)

            # Add a record of the file in the database
            conn = sqlite3.connect(db_files_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO files (group_id, filename, created_at, last_modified_by, size, folder) 
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (group_id, filename, datetime.now(), user_id, os.path.getsize(file_path), folder))
            conn.commit()
            conn.close() 

            return jsonify({'success': True, 'message': 'File successfully uploaded.'})
        else:
            # Return a permission denied error if the user lacks appropriate rights
            return jsonify({'success': False, 'message': 'Permission denied.'})
    except Exception as e:
        # Handle any exceptions during file upload
        print(f"Error uploading file: {e}")
        return jsonify({'success': False, 'message': 'Error uploading file.' + str({e})})

@app.route('/create_folder', methods=['POST'])
@jwt_required()  # Ensure the user is authenticated via JWT
def create_folder():
    user_id = get_jwt_identity()  # Get the user's identity from the JWT

    try:
        # Parse the JSON data from the request
        data = request.get_json()
        folder_name = data.get('folder_name')  # Name of the new folder
        directory = data.get('directory')  # Directory in which to create the folder
        group_id = data.get('group_id')  # Group ID under which the folder is being created

        # Check if the user has permissions to create a folder
        if not (check_user_role(user_id, 'write', group_id) or 
                check_user_role(user_id, 'local_admin', group_id) or 
                check_user_is_admin(user_id)):
            return jsonify({'success': False, 'message': 'Permission denied.'})

        if not folder_name:
            # Validate the folder name input
            return jsonify({'success': False, 'message': 'Folder name required.'})

        conn = sqlite3.connect(db_files_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM files WHERE filename = ? AND folder = ? AND group_id = ?
        ''', (folder_name, directory, group_id))
        file_exists_in_db = cursor.fetchone()
        

        if file_exists_in_db:
            conn.close()
            return jsonify({'success': False, 'message': 'The folder already exists in the database.'})

        # Set the path for the new folder
        new_folder_path = os.path.join(get_group_upload_folder(group_id, directory), folder_name)

        # Register the new folder in the database
        cursor.execute('''
            INSERT INTO files (group_id, filename, created_at, last_modified_by, size, folder, is_folder)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (group_id, folder_name, datetime.now(), user_id, 0, directory, True))
        conn.commit()
        conn.close()

        # Create the folder on the file system if it does not exist
        if not os.path.exists(new_folder_path):
            os.makedirs(new_folder_path)

        return jsonify({'success': True, 'message': 'New folder created.'})
    except Exception as e:
        # Handle any exceptions during folder creation
        print('Error creating folder:', str(e))
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/delete_file', methods=['POST'])
@jwt_required()  # Ensure the user is authenticated via JWT
def delete_file():
    user_id = get_jwt_identity()  # Get the user's identity from the JWT

    # Check if the JWT token is valid
    if user_id is None:
        return jsonify({'success': False, 'message': 'Invalid token.'})

    # Parse the JSON data from the request
    if request.is_json:
        data = request.json
        folder_data = data.get('folder')
        filename = data.get('filename', '')
        group_id = data.get('group')
        folder = json.loads(folder_data) if folder_data else ''
    else:
        return jsonify({'success': False, 'message': 'Invalid data format.'})

    # Check if the filename is provided in the request
    if not filename:
        return jsonify({'success': False, 'message': 'Filename missing in the request.'})

    # Check user permissions to delete the file or folder
    if (check_user_role(user_id, 'write', group_id) or
            check_user_role(user_id, 'local_admin', group_id) or
            check_user_is_admin(user_id)):

        # Create the path to the file or folder
        path = os.path.join(get_group_upload_folder(group_id, folder), filename)

        try:
            error_message = ""
            if os.path.isfile(path):
                # Delete the file from the file system
                os.remove(path)
                # Update the database to remove the file entry
                error_message = delete_db_entries(group_id, folder, filename, False)
            elif os.path.isdir(path):
                # Delete the folder and its contents from the file system
                shutil.rmtree(path)
                # Update the database to remove the folder entry and its contents
                error_message = delete_db_entries(group_id, folder, filename, True)
            else:
                return jsonify({'success': False, 'message': 'Path does not exist.'})

            return jsonify({'success': True, 'message': f'Successfully deleted. {str(error_message)}'})
        except Exception as e:
            # Handle any errors that occur during file/folder deletion
            return jsonify({'success': False, 'message': f'Error while deleting: {str(e)}'})

    else:
        return jsonify({'success': False, 'message': 'Permission denied.'})

def delete_db_entries(group_id, directory, filename, is_folder):
    try:
        conn = sqlite3.connect(db_files_path)
        cursor = conn.cursor()

        # Construct the path for the database entry
        path_for_database = os.path.join(directory, filename) if filename else directory

        if is_folder:
            # Delete the folder and its contents from the database
            directory_pattern = path_for_database.rstrip('/')  # Remove a trailing slash if present
            cursor.execute('DELETE FROM files WHERE group_id = ? AND ((folder = ? AND filename = ?) OR folder LIKE ?)', (group_id, directory, filename, f'{directory_pattern}/%'))
        else:
            # Delete a single file entry from the database
            cursor.execute('DELETE FROM files WHERE group_id = ? AND filename = ? AND folder = ?', (group_id, filename, directory))

        conn.commit()
        conn.close()

        # Return the directory path that was deleted
        return directory
    except Exception as e:
        # Handle any errors that occur during database deletion
        return str(e)

@app.route('/files', methods=['POST'])
@jwt_required()
def get_user_files():
    user_id = get_jwt_identity()
    json_data = request.form.get('json')

    print("Received JSON data:", json_data)  # Debugging

    data = json.loads(json_data)
    group_id = data.get("group")
    folder = data.get('folder')
    if group_id is None or folder is None:
        return jsonify({'success': False, 'message': 'Group ID is missing.'})

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check user permissions
        if not (check_user_role(user_id, 'read', group_id) or check_user_role(user_id, 'local_admin', group_id) or check_user_is_admin(user_id)):
            conn.close()
            return jsonify({'success': False, 'message': 'Permission denied.'})
        
        # Get usernames from the user database
        cursor.execute('SELECT user_id, username FROM users')
        users = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()

        # Get file information from the file database
        conn = sqlite3.connect(db_files_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT filename, created_at, last_modified_by, size, is_folder
            FROM files
            WHERE group_id = ? AND folder = ?
        ''', (group_id, folder))
        files_info = cursor.fetchall()
        conn.close()

        # Check if files were found
        if not files_info:
            return jsonify({'success': False, 'message': 'No files found.'})

        # Merge information and format for response
        files_and_folders = [
            {
                'name': row[0],
                'created_at': row[1].split(' ')[0],  # Extract date part from DateTime
                'last_modified_by': users.get(row[2], 'Unknown User'),
                'size': row[3],
                'is_folder': row[4]
            }
            for row in files_info
        ]

        return jsonify({'success': True, 'files_and_folders': files_and_folders})
    except sqlite3.Error as e:
        print(f'Database error: {e}')
        return jsonify({'success': False, 'message': 'Database error occurred.'})



@app.route('/download_file', methods=['POST'])  # This route handles file downloads using POST method
@jwt_required()  # Requires a valid JWT (JSON Web Token) for authentication
def download_file():
    user_id = get_jwt_identity()  # Get the user's identity from the JWT

    # Extract file name, folder, and group ID from the JSON data in the request body
    if request.is_json:
        data = request.json
        folder = data.get('folder')  # The folder where the file is located
        filename = data.get('filename')  # The name of the file to be downloaded
        group_id = data.get('group')  # The ID of the group that owns the file

    if user_id is None:
        return jsonify({'success': False, 'message': 'Invalid token.'})

    # Check if the user has permission to download the file
    if not (check_user_role(user_id, 'read', group_id) or check_user_role(user_id, 'local_admin', group_id) or check_user_is_admin(user_id)):
        return jsonify({'success': False, 'message': 'Permission denied.'})
        
    # Build the full file path by combining the group's upload folder, folder, and filename
    file_path = os.path.join(get_group_upload_folder(group_id, folder), filename)

    # Determine the MIME type of the file (e.g., 'application/pdf', 'image/jpeg')
    mimetype, _ = mimetypes.guess_type(filename)

    # Prepare the file for download as an attachment in the response
    response = make_response(send_file(file_path, as_attachment=True))

    # Set the Content-Disposition header to suggest a filename when downloading
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'

    # Set the Content-Type header to specify the file's MIME type
    response.headers['Content-Type'] = mimetype

    return response  # Return the response for file download
    
@app.route('/users', methods=['GET'])
def get_users():
    conn = get_db_connection()
    
    # Retrieve all user records from the database
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    
    # Convert the user records to a JSON response
    return jsonify([dict(user) for user in users])

@app.route('/groups', methods=['GET'])
def get_groups():
    conn = get_db_connection()
    
    # Retrieve all group records from the database
    groups = conn.execute('SELECT * FROM groups').fetchall()
    conn.close()
    
    # Convert the group records to a JSON response
    return jsonify([dict(group) for group in groups])

@app.route('/my_groups', methods=['GET'])
@jwt_required()
def get_my_groups():
    user_id = get_jwt_identity()
    try:
        # Establish a database connection
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # SQL query to obtain group IDs and names for all groups the user belongs to
        query = '''
        SELECT DISTINCT g.group_id, g.group_name
        FROM groups g
        JOIN group_members gm ON g.group_id = gm.group_id
        WHERE gm.user_id = ?
        '''
        cursor.execute(query, (user_id,))
        groups = cursor.fetchall()

        # Convert the query result into a user-friendly JSON format
        groups_list = [{'group_id': group[0], 'group_name': group[1]} for group in groups]
        conn.close()

        # Return a JSON response with the user's groups
        return jsonify({'success': True, 'groups': groups_list})
    except Exception as e:
        print('Error retrieving user groups:', str(e))
        return jsonify({'success': False, 'message': 'Internal Server Error'}), 500

@app.route('/user_groups/<username>', methods=['GET'])
def get_user_groups(username):
    try:
        # Establish a database connection
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Retrieve the user's ID based on the provided username
        user_id_result = get_user_id(username)

        # Check if the user exists
        if not user_id_result:
            conn.close()
            return jsonify({'success': False, 'message': 'User not found.'})

        user_id = user_id_result

        # SQL query to obtain group IDs and names for all groups the user belongs to
        query = '''
        SELECT DISTINCT g.group_id, g.group_name
        FROM groups g
        JOIN group_members gm ON g.group_id = gm.group_id
        WHERE gm.user_id = ?
        '''
        cursor.execute(query, (user_id,))
        groups = cursor.fetchall()

        # Convert the query result into a user-friendly JSON format
        groups_list = [{'group_id': group[0], 'group_name': group[1]} for group in groups]
        conn.close()

        # Return a JSON response with the user's groups
        return jsonify({'success': True, 'groups': groups_list})
    except Exception as e:
        print('Error retrieving user groups:', str(e))
        return jsonify({'success': False, 'message': 'Internal Server Error'}), 500



@app.route('/group_members', methods=['POST'])
def get_group_members():
    data = request.json
    group_name = data.get('group_name')
    conn = get_db_connection()

    # Update the SQL query to join the 'groups' table
    members = conn.execute('''
        SELECT DISTINCT users.*
        FROM users
        JOIN group_members ON users.user_id = group_members.user_id
        JOIN groups ON group_members.group_id = groups.group_id
        WHERE groups.group_name = ?
    ''', (group_name,)).fetchall()
    
    conn.close()
    
    # Convert the member records to a JSON response
    return jsonify([dict(member) for member in members])


@app.route('/user_rights/<username>', methods=['GET'])
def get_user_rights(username):
    conn = get_db_connection()
    
    # Join users, user_rights, and rights to retrieve usernames and rights
    query = '''
    SELECT u.username, r.right_name
    FROM users u
    JOIN user_rights ur ON u.user_id = ur.user_id
    JOIN rights r ON ur.right_id = r.right_id
    WHERE u.username = ?
    '''
    user_rights = conn.execute(query, (username,)).fetchall()
    
    conn.close()
    
    # Convert the user rights records to a JSON response
    return jsonify([{'username': row['username'], 'right': row['right_name']} for row in user_rights])

@app.route('/user_group_rights', methods=['POST'])
def get_user_group_rights():
    # Extract user name and group ID from the JSON data in the request body
    data = request.json
    username = data.get('username')
    group_id = data.get('group_id')

    if not username or not group_id:
        return jsonify({'error': 'Please provide both a username and a group name.'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Execute the query to retrieve user rights in the group
    cursor.execute('''
        SELECT u.username, g.group_name, gr.right_name
        FROM group_members gm
        JOIN users u ON gm.user_id = u.user_id
        JOIN groups g ON gm.group_id = g.group_id
        JOIN group_rights gr ON gm.right_id = gr.right_id
        WHERE gm.group_id = ? AND u.username = ?
    ''', (group_id, username))

    user_group_rights = cursor.fetchall()

    # Create the JSON response
    return jsonify([{'username': row[0], 'group': row[1], 'right': row[2]} for row in user_group_rights])


@app.route('/change_password', methods=['POST'])
@jwt_required()
def change_password():
    changing_user_id = get_jwt_identity()  # Ensure that the user is logged in
    conn = get_db_connection()
    
    # Extract user name and new password from the JSON data in the request body
    data = request.get_json()
    username = data.get('username')
    new_password = data.get('new_password')
    user_id = get_user_id(username)  # Get the user_id associated with the provided username
    
    if user_id:
        # Check if the user requesting the password change is an admin or the same user
        if(check_user_is_admin(user_id) or changing_user_id == user_id):
            if not new_password:
                return jsonify({'success': False, 'message': 'New password is missing.'})

            # Generate a hashed password and update it in the database
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            conn.execute('UPDATE users SET hashed_password = ? WHERE user_id = ?', (hashed_password, user_id))
            conn.commit()
            conn.close()

            return jsonify({'success': True, 'message': 'Password successfully changed.'})
        else:
            conn.close()
            return jsonify({'success': True, 'message': 'Permission denied.'})
    return({'success': False, 'message': 'No User'})  # Return a failure message if the user doesn't exist


@app.route('/change_username', methods=['POST'])
@jwt_required()
def change_username():
    changing_user_id = get_jwt_identity()  # Ensure that the user is logged in
    conn = get_db_connection()
    data = request.get_json()
    username = data.get('username')  # The current username
    new_username = data.get('new_username')  # The new desired username

    user_id = get_user_id(username)  # Get the user_id associated with the current username
    
    if user_id:
        # Check if the user requesting the username change is an admin or the same user
        if(check_user_is_admin(changing_user_id) or changing_user_id == user_id):
            if not new_username:
                conn.close()
                return jsonify({'success': False, 'message': 'New username is missing.'})

            # Update the username in the database
            conn.execute('UPDATE users SET username = ? WHERE user_id = ?', (new_username, user_id))
            conn.commit()
            conn.close()

            return jsonify({'success': True, 'message': 'Username successfully changed.'})
        else:
            conn.close()
            return jsonify({'success': False, 'message': 'Permission denied.'})
    else:
        conn.close()
        return jsonify({'success': False, 'message': 'Username not found.'})



@app.route('/change_user_rights', methods=['POST'])
@jwt_required()
def change_user_rights():
    admin_id = get_jwt_identity()  # The administrator making the changes
    conn = get_db_connection()
    data = request.get_json()
    username = data.get('username')  # The username of the user whose rights are being changed
    new_rights = data.get('new_rights')  # A list of right_ids to assign to the user

    user_id = get_user_id(username)  # Get the user_id associated with the given username
    
    if user_id:
        # Check if the user making the request is an admin
        if(check_user_is_admin(admin_id)):
            # Remove all old rights first
            conn.execute('DELETE FROM user_rights WHERE user_id = ?', (user_id,))
            
            # Load the right_ids from the database
            rights_name_to_id = {row['right_name']: row['right_id'] for row in conn.execute('SELECT right_id, right_name FROM rights')}
            
            # Prepare the new rights (remove duplicates and ensure they exist in the database)
            unique_new_right_ids = {rights_name_to_id[right] for right in new_rights if right in rights_name_to_id}

            # Assign the new rights to the user
            for right_id in unique_new_right_ids:
                conn.execute('INSERT INTO user_rights (user_id, right_id) VALUES (?, ?)', (user_id, right_id))
            conn.commit()
            conn.close()

            return jsonify({'success': True, 'message': 'User rights successfully changed.'})
        else:
            conn.close()
            return jsonify({'success': True, 'message': 'Permission denied.'})
    else:
        return jsonify({'success': False, 'message': 'No User'})


@app.route('/change_group_rights', methods=['POST'])
@jwt_required()
def change_group_rights():
    admin_id = get_jwt_identity()  # The administrator making the changes
    conn = get_db_connection()
    
    data = request.get_json()
    username = data.get('username')  # The username of the user whose group rights are being changed
    group_id = data.get('group_id')  # The ID of the group whose rights are being changed
    new_rights = data.get('new_rights')  # A list of right names to assign to the user in the group

    if group_id == "null":
        return jsonify({'success': False})

    # Check if the user making the request is an admin
    if not (check_user_is_admin(admin_id)):
        return jsonify({'success': True, 'message': 'Permission denied.'})

    user_id = get_user_id(username)  # Get the user_id associated with the given username
    cursor = conn.cursor()

    try:
        # Remove all old group rights of the user in this group
        cursor.execute('DELETE FROM group_members WHERE user_id = ? AND group_id = ?', (user_id, group_id))

        # Add the new group rights
        for right_name in new_rights:
            cursor.execute('SELECT right_id FROM group_rights WHERE right_name = ?', (right_name,))
            right_id_row = cursor.fetchone()
            if right_id_row:
                right_id = right_id_row[0]
                cursor.execute('INSERT INTO group_members (user_id, group_id, right_id) VALUES (?, ?, ?)', (user_id, group_id, right_id))

        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Group rights successfully changed.'})
    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': 'Error'})

@app.route('/change_user_groups', methods=['POST'])
@jwt_required()
def change_user_groups():
    admin_id = get_jwt_identity()  # The administrator making the changes
    conn = get_db_connection()
    
    data = request.get_json()
    username = data.get('username')  # The username of the user whose groups are being changed
    new_groups = data.get('new_groups')  # A list of group_ids to assign to the user

    user_id = get_user_id(username)  # Get the user_id associated with the given username
    if user_id:
        if(check_user_is_admin(admin_id)):
            # Remove all old groups first
            conn.execute('DELETE FROM group_members WHERE user_id = ?', (user_id,))
            # then add the new groups

            # Prepare the new groups (remove duplicates)
            unique_new_groups = set(new_groups)

            for group_id in unique_new_groups:
                conn.execute('INSERT INTO group_members (user_id, group_id) VALUES (?, ?)', (user_id, group_id))
            conn.commit()
            conn.close()

            return jsonify({'success': True, 'message': 'User groups successfully changed.'})
        else:
            conn.close()
            return jsonify({'success': True, 'message': 'Permission denied.'})
    else:
        return jsonify({'success': False, 'message': 'No User'})

if __name__ == '__main__':
    # Check if SSL certificates exist, and run the app accordingly
    if not (os.path.exists('/etc/letsencrypt/live/raspi.cloud/fullchain.pem') or os.path.exists('/etc/letsencrypt/live/raspi.cloud/privkey.pem')):
        app.run(host='0.0.0.0', port=8080, debug=False)
    else:
        app.run(host='0.0.0.0', port=8080, debug=False, ssl_context=('/etc/letsencrypt/live/raspi.cloud/fullchain.pem', '/etc/letsencrypt/live/raspi.cloud/privkey.pem'))
