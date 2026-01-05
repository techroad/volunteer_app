from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from datetime import date
from datetime import datetime

app = Flask(__name__)

# --- MySQL Configuration ---
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root' # Your MySQL username
app.config['MYSQL_PASSWORD'] = 'root' # Your MySQL password
app.config['MYSQL_DB'] = 'isewa'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' # Returns rows as dictionaries
app.secret_key = 'abcdefgh' # Change this for security

mysql = MySQL(app)

# --- Routes ---

## Home / Landing Page
@app.route('/', methods=['GET'])
def index():
    tasks = []
    signed_up_task_ids = set()
    past_tasks = []
    tasks_duration = []
    try:
        cur = mysql.connection.cursor()
        # Get all tasks
        cur.execute("SELECT * FROM isewa_vln_tasks where ivt_event_date >= current_date AND ivt_no_of_volunteers_required > ivt_no_of_volunteers_already_signedup ORDER BY ivt_event_date ASC")
        tasks = cur.fetchall()
        cur.close()
        #signed_up_task_ids = set()
        #past_tasks = []
        #tasks_duration = []
        if 'user_id' in session:
            user_id = session['user_id']
            cur = mysql.connection.cursor()
            print(user_id)
            cur.execute("SELECT ivs_task_id FROM isewa_vln_signups WHERE ivs_user_id = %s", [user_id])
            signed_up_tasks = cur.fetchall()
            cur.close()
            signed_up_task_ids = {item['ivs_task_id'] for item in signed_up_tasks}
            print(signed_up_task_ids)
            cur = mysql.connection.cursor()
            cur.execute("SELECT a.ivt_id,a.ivt_title,a.ivt_event_date,a.ivt_description,a.ivt_location,b.ivs_notes,b.ivs_is_approved,b.ivs_is_coordinator_approved from isewa_vln_tasks a, isewa_vln_signups b WHERE a.ivt_id = b.ivs_task_id and b.ivs_user_id = %s order by a.ivt_event_date", [user_id])
            past_tasks = cur.fetchall()
            cur.close
            
            cur = mysql.connection.cursor()
            cur.execute("select sum(a.ivt_event_duration) as total_duration from isewa_vln_tasks a, isewa_vln_signups b where a.ivt_id = b.ivs_task_id and b.ivs_user_id = %s", [user_id])
            tasks_duration = cur.fetchall()
            
            cur.close
            print(signed_up_task_ids)
    except Exception as e:
        return f"An unexpected error occurred: {e}"   
    return render_template('index.html', tasks=tasks, signed_up_task_ids=signed_up_task_ids, current_date=date.today(), past_tasks=past_tasks,tasks_duration=tasks_duration)

@app.route('/add_note/<int:task_id>', methods=['POST'])
def add_note(task_id):
    # 1. Ensure user is logged in
    if 'user_id' not in session:
        flash('You must be logged in to add notes.', 'danger')
        return redirect(url_for('login'))

    try:
    # 2. Get data from the form and session
        note_content = request.form['note']
        user_id = session['user_id']
    # 3. Create a cursor and update the database
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE isewa_vln_signups
            SET notes = %s
            WHERE ivs_user_id = %s AND ivs_task_id = %s
        """, (note_content, user_id, task_id))
    # 4. Commit the change and close the cursor
        mysql.connection.commit()
        cur.close()
        flash('Note saved successfully!', 'success')

    except Exception as e:
        flash(f'An error occurred: {e}', 'danger')

    # 5. Redirect back to the home page
    return redirect(url_for('index'))

## User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    print("Register")
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user') 
        hashed_password = sha256_crypt.encrypt(str(password))
    #Determine if the new user should be a coordinator
        is_coordinator = 1 if role == 'coordinator' else 0
        print(is_coordinator)
        cur = mysql.connection.cursor()
        # Check if user already exists
        cur.execute("SELECT * FROM isewa_vln_users WHERE ivu_username = %s", [username])
        if cur.fetchone():
            flash('Username already exists. Please choose another.', 'danger')
            return render_template('register.html')

        cur.execute("INSERT INTO isewa_vln_users(ivu_username, ivu_password, ivu_is_coordinator) VALUES(%s, %s, %s)", (username, hashed_password, is_coordinator))
        mysql.connection.commit()
        cur.close()
        
        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

## User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    print("login page")

    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']
        role = request.form['role']

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM isewa_vln_users WHERE ivu_username = %s AND ivu_is_active = 'Y'", [username])

        if result > 0:
            data = cur.fetchone()
            password = data['ivu_password']

            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['username'] = username
                session['is_admin'] = data['ivu_is_admin']
                session['user_id'] = data['ivu_id'] # Store user ID in session
                session['is_coordinator'] = data['ivu_is_coordinator'] # Store coordinator status in session
                
                flash('You are now logged in', 'success')
                
                cur.execute("UPDATE isewa_vln_users SET ivu_user_last_login = current_timestamp WHERE ivu_username = %s",[username])
                mysql.connection.commit()

                if session['is_coordinator']:
                    return redirect(url_for('coordinator_approve'))
                if session['is_admin']:
                    return redirect(url_for('admin'))
                return redirect(url_for('index'))

            else:
                flash('Invalid password', 'danger')
                return render_template('login.html')
        else:
            flash('User not found', 'danger')
            return render_template('login.html')
        
    return render_template('login.html')

#Admin dashboard
categories = []
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # 1. Authorization Check (Keep this part)
    if not session.get('logged_in') or not session.get('is_admin'):
        flash('Unauthorized. Please login as an admin.', 'danger')
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    session_user = session.get('user_id')
    
    cur.execute("UPDATE isewa_vln_users SET ivu_user_last_login = current_timestamp where ivu_id = %s", [session_user])
    try:
        cur.execute("SELECT ivc_category FROM isewa_vln_category")
        categories = [row["ivc_category"] for row in cur.fetchall()]
    except Exception as e:
        flash(f'Error fetching categories: {str(e)}', 'danger')
        categories = []

    try:
        cur.execute("SELECT ivu_username FROM isewa_vln_users where ivu_is_coordinator = 1 AND ivu_is_active = 'Y'")
        coordinators = [row["ivu_username"] for row in cur.fetchall()]
    except Exception as e:
        flash(f'Error fetching coordinators: {str(e)}', 'danger')
        coordinators = []
    
    cur.close()     
    
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        print(form_type)

        # --- User Creation Logic ---
        if form_type == 'register_user':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            referredby = request.form.get('referredby')
            role = request.form.get('role', 'user') 
            is_coordinator = 1 if role == 'coordinator' else 0
            print(is_coordinator)
            # Basic input validation
            if not username or not password or not referredby:
                flash('Please fill out all user registration fields.', 'danger')
                return redirect(url_for('admin'))

            # 4. Hash the Password
            hashed_password = sha256_crypt.encrypt(str(password))
            
            # ser_last_login = datetime.now()5. Insert the New User
            try:
                cur = mysql.connection.cursor()
            
                cur.execute("SELECT * FROM isewa_vln_users WHERE ivu_username = %s AND ivu_is_active = 'Y'", [username])
                if cur.fetchone():
                    flash('Username already exists. Please choose another.', 'danger')
                    return render_template('admin.html')

                cur.execute("SELECT * FROM isewa_vln_users WHERE ivu_username = %s AND ivu_is_active = 'Y'", [referredby])
                if not cur.fetchone():
                    flash('referred user does not exists')
                    return render_template('admin.html')
                user_is_active = 'Y'
                ivu_is_admin = 0
                ivu_created_by = 'admin'
                current_datetime = datetime.now()
                cur.execute("INSERT INTO isewa_vln_users(ivu_username, ivu_password, ivu_is_admin, ivu_is_coordinator, ivu_user_email, ivu_referred_by, ivu_created_by, ivu_created_at_ts, ivu_is_active, ivu_user_last_login) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                            (username, hashed_password, ivu_is_admin, is_coordinator, email, referredby, ivu_created_by, current_datetime, user_is_active, current_datetime))
                
                mysql.connection.commit()

                cur.close()
                flash(f'User "{username}" created successfully.', 'success')
            except Exception as e:
                # Handle potential errors like duplicate username/email
                flash(f'Error creating user: {str(e)}', 'danger')
            
            return redirect(url_for('admin'))
        elif form_type == 'manage_user':
                manage_username = request.form.get('username')
                comment = request.form.get('comment')
                
                try:
                    print(manage_username)    
                    
                    cur = mysql.connection.cursor()
                    cur.execute("UPDATE isewa_vln_users SET ivu_is_active = 'N' WHERE ivu_username = %s", [manage_username])
                    mysql.connection.commit()
                   # cur.close()
                    
                   # cur = mysql.connection.cursor()
                    cur.execute("SELECT ivu_user_last_login from isewa_vln_users WHERE ivu_username = %s", [manage_username])
                    user_last_login = [row["ivu_user_last_login"] for row in cur.fetchall()]
                    print(user_last_login)
                    current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                     
                    cur.execute("INSERT INTO isewa_vln_archived_users (ivau_username, ivau_comment, ivau_last_login, ivau_deleted_by, ivau_archived_date) VALUES(%s,%s,%s,%s,%s)",
                                (manage_username, comment, user_last_login, session_user, current_datetime))
                    mysql.connection.commit()
                    cur.close()
                    flash(f'User "{manage_username}" deleted successfully.', 'success')
                except Exception as e:
                # Handle potential errors like duplicate username/email
                    flash(f'Error deleting user: {str(e)}', 'danger')
                return redirect(url_for('admin'))
            # --- Task Creation Logic (Your existing logic) ---
        elif form_type == 'create_task':
            print("DEBUG2")
            cur = mysql.connection.cursor()
            title = request.form.get('title')
            description = request.form.get('description')
            event_date = request.form.get('event_date')
            location = request.form.get('location')
            task_category = request.form.get('category')
            event_start_time = request.form.get('event_start_time')
            event_duration = request.form.get('event_duration')
            no_of_volunteers_required = request.form.get('no_of_volunteers_required')
            coordinator_poc = request.form.get('coordinator_poc')
            assigned_coordinator = request.form.get('assigned_coordinator')
            coordinator_id = cur.execute("SELECT ivu_id FROM isewa_vln_users WHERE ivu_username = %s AND ivu_is_active = 'Y'", [assigned_coordinator])
            print(assigned_coordinator)
            print(coordinator_id)

            # Your existing task creation database code...
            print(title,task_category)
            cur.execute("INSERT INTO isewa_vln_tasks(ivt_title, ivt_description, ivt_event_date, ivt_location, ivt_event_start_time, ivt_event_duration, ivt_no_of_volunteers_required, ivt_category, ivt_coordinator_poc, ivt_task_approval_coordinator) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (title, description, event_date, location, event_start_time, event_duration, no_of_volunteers_required, task_category, coordinator_poc, coordinator_id))
            mysql.connection.commit()
            cur.close()
            
            flash('Task Created', 'success')
            return redirect(url_for('admin'))
        
        # Handle cases where form_type might be missing or unexpected
        else:
             flash('Invalid form submission.', 'danger')
             return redirect(url_for('admin'))
# Ensure the cursor is closed after all GET data is fetched
    if cur:
        cur.close()
    # GET request: Render the dashboard page
    return render_template('admin.html',categories=categories, coordinators=coordinators)


## COORDINATOR APPROVAL PORTAL ##

@app.route('/coordinator/approve')
def coordinator_approve():
# Security: Ensure user is a logged-in coordinator
    if not session.get('logged_in') or not session.get('is_coordinator'):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    
    cur = mysql.connection.cursor()
    # Fetch tasks that are:
    # 1. Approved by an Admin (is_approved = 1)
    # 2. Have notes submitted by the user (notes are not empty)
    # 3. Not yet approved by a Coordinator (is_coordinator_approved = 0)
    
    session_user = session.get('user_id')
    
    #cur.execute("UPDATE isewa_vln_users SET ivu_user_last_login = current_timestamp where ivu_id = %s", [session_user])
    try:
        cur.execute("SELECT ivc_category FROM isewa_vln_category")
        categories = [row["ivc_category"] for row in cur.fetchall()]
    except Exception as e:
        flash(f'Error fetching categories: {str(e)}', 'danger')
        categories = []

    try:
        cur.execute("SELECT ivu_username FROM isewa_vln_users where ivu_is_coordinator = 1 AND ivu_is_active = 'Y'")
        coordinators = [row["ivu_username"] for row in cur.fetchall()]
    except Exception as e:
        flash(f'Error fetching coordinators: {str(e)}', 'danger')
        coordinators = []

    cur.execute("""
    SELECT
    s.ivs_user_id, s.ivs_task_id, s.ivs_is_approved, s.ivs_notes, s.ivs_is_coordinator_approved,
    u.ivu_username,
    t.ivt_title, t.ivt_event_date
    FROM isewa_vln_signups s
    JOIN isewa_vln_users u ON s.ivs_user_id = u.ivu_id
    JOIN isewa_vln_tasks t ON s.ivs_task_id = t.ivt_id
    WHERE t.ivt_event_date < CURDATE()
    ORDER BY t.ivt_event_date DESC, u.ivu_username ASC
    """)
    pending_tasks = cur.fetchall()
    cur.close()

    return render_template('coordinator_approve_new.html', categories=categories, coordinators=coordinators,tasks=pending_tasks)

## HANDLER FOR COORDINATOR APPROVAL ##
@app.route('/coordinator/tasks/manage', methods=['GET','POST'])

def coordinator_manage_tasks():

    if not session.get('logged_in') or not session.get('is_coordinator'):
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        print(form_type)
        if form_type == 'create_tasks':
            print("DEBUG2")
            cur = mysql.connection.cursor()
            title = request.form.get('title')
            description = request.form.get('description')
            event_date = request.form.get('event_date')
            location = request.form.get('location')
            task_category = request.form.get('category')
            event_start_time = request.form.get('event_start_time')
            event_duration = request.form.get('event_duration')
            no_of_volunteers_required = request.form.get('no_of_volunteers_required')
            coordinator_poc = request.form.get('coordinator_poc')
            assigned_coordinator = request.form.get('assigned_coordinator')
            coordinator_id = cur.execute("SELECT ivu_id FROM isewa_vln_users WHERE ivu_username = %s AND ivu_is_active = 'Y'", [assigned_coordinator])
            print(assigned_coordinator)
            print(coordinator_id)

            # Your existing task creation database code...
            print(title,task_category)
            cur.execute("INSERT INTO isewa_vln_tasks(ivt_title, ivt_description, ivt_event_date, ivt_location, ivt_event_start_time, ivt_event_duration, ivt_no_of_volunteers_required, ivt_category, ivt_coordinator_poc, ivt_task_approval_coordinator) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (title, description, event_date, location, event_start_time, event_duration, no_of_volunteers_required, task_category, coordinator_poc, coordinator_id))
            mysql.connection.commit()
            cur.close()
            
            flash('Task Created', 'success')
            return redirect(url_for('coordinator_manage_tasks'))
        
    return redirect(url_for('coordinator_approve_new'))
        

@app.route('/coordinator/approve<int:user_id>/<int:task_id>', methods=['GET','POST'])

def handle_coordinator_approval(user_id, task_id):
# Security: Ensure user is a logged-in coordinator
    
    if not session.get('logged_in') or not session.get('is_coordinator'):
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        print(form_type)

    if form_type == 'approve_tasks':

        cur = mysql.connection.cursor()

        cur.execute("""
            UPDATE isewa_vln_signups
            SET is_coordinator_approved = 1
            WHERE ivs_user_id = %s AND ivs_task_id = %s
        """, (user_id, task_id))

        mysql.connection.commit()
        cur.close()

        flash('Task has been successfully approved!', 'success')
        return redirect(url_for('coordinator_approve_new'))

    return redirect(url_for('coordinator_approve_new'))

## Sign Up for a Task
@app.route('/signup/<int:task_id>', methods=['POST'])
def signup(task_id):
    if not session.get('logged_in'):
        flash('Please log in to sign up for tasks.', 'danger')
        return redirect(url_for('login'))
    
    user_id = session['user_id']

    cur = mysql.connection.cursor()
    # Check if already signed up
    cur.execute("SELECT * FROM isewa_vln_signups WHERE ivs_user_id = %s AND ivs_task_id = %s", (user_id, task_id))
    if cur.fetchone():
        flash('You have already signed up for this task!', 'info')
        return redirect(url_for('index'))

    cur.execute("INSERT INTO isewa_vln_signups(ivs_user_id, ivs_task_id) VALUES (%s, %s)", (user_id, task_id))
    mysql.connection.commit()

    cur.execute("SELECT ivt_no_of_volunteers_already_signedup FROM isewa_vln_tasks WHERE ivt_id = %s",[task_id])
    row = cur.fetchone()
    if row:
        signedup_count = row["ivt_no_of_volunteers_already_signedup"]
        print(signedup_count)
        signedup_count += 1
        cur.execute("UPDATE isewa_vln_tasks SET ivt_no_of_volunteers_already_signedup = %s WHERE ivt_id = %s",[signedup_count,task_id])
        mysql.connection.commit()

    cur.close()
    
    flash('You have successfully signed up for the task!', 'success')
    return redirect(url_for('index'))

@app.route('/approve_signup/<int:user_id>/<int:task_id>', methods=['POST'])
def approve_signup(user_id, task_id):
    if not session.get('logged_in') or not session.get('is_admin'):
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE isewa_vln_signups
        SET is_approved = 1
        WHERE ivs_user_id = %s AND ivs_task_id = %s
    """, (user_id, task_id))
    mysql.connection.commit()
    cur.close()
    flash('Volunteer participation approved!', 'success')
    # Update this line to redirect back to the main admin page
    return redirect(url_for('admin'))

## Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# --- Main execution ---
if __name__ == '__main__':
    app.run(debug=True)