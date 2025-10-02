from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt

app = Flask(__name__)

# --- MySQL Configuration ---
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root' # Your MySQL username
app.config['MYSQL_PASSWORD'] = 'password' # Your MySQL password
app.config['MYSQL_DB'] = 'volunteer_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' # Returns rows as dictionaries
app.secret_key = 'abcdefgh' # Change this for security

mysql = MySQL(app)

# --- Routes ---

## Home / Landing Page
@app.route('/')
def index():
    try:
        cur = mysql.connection.cursor()
        # Get all tasks
        result = cur.execute("SELECT * FROM tasks ORDER BY event_date ASC")
        tasks = cur.fetchall()
        cur.close()
        signed_up_task_ids = set()
        if 'user_id' in session:
            user_id = session['user_id']
            cur = mysql.connection.cursor()
            cur.execute("SELECT task_id FROM signups WHERE user_id = %s", [user_id])
            signed_up_tasks = cur.fetchall()
            cur.close()
            signed_up_task_ids = {item['task_id'] for item in signed_up_tasks}
    except Exception as e:
        return f"An unexpected error occurred: {e}"   

    return render_template('index.html', tasks=tasks, signed_up_task_ids=signed_up_task_ids)

## User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    print("Register")
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = sha256_crypt.encrypt(str(password))

        cur = mysql.connection.cursor()
        # Check if user already exists
        cur.execute("SELECT * FROM users WHERE username = %s", [username])
        if cur.fetchone():
            flash('Username already exists. Please choose another.', 'danger')
            return render_template('register.html')

        cur.execute("INSERT INTO users(username, password) VALUES(%s, %s)", (username, hashed_password))
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

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            data = cur.fetchone()
            password = data['password']

            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['username'] = username
                session['is_admin'] = data['is_admin']
                session['user_id'] = data['id'] # Store user ID in session
                
                flash('You are now logged in', 'success')
                if session['is_admin']:
                    return redirect(url_for('admin'))
                return redirect(url_for('index'))
            else:
                flash('Invalid password', 'danger')
                return render_template('login.html')
        else:
            flash('Username not found', 'danger')
            return render_template('login.html')
        
    return render_template('login.html')

## Admin Dashboard
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('logged_in') or not session.get('is_admin'):
        flash('Unauthorized. Please login as an admin.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        event_date = request.form['event_date']
        location = request.form['location']
        event_start_time = request.form['event_start_time']
        event_duration = request.form['event_duration']
        no_of_volunteers_required = request.form['no_of_volunteers_required']

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO tasks(title, description, event_date, location, event_start_time, event_duration, no_of_volunteers_required) VALUES(%s, %s, %s, %s, %s, %s, %s)",
                    (title, description, event_date, location, event_start_time,event_duration,no_of_volunteers_required))
        mysql.connection.commit()
        cur.close()
        
        flash('Task Created', 'success')
        return redirect(url_for('admin'))

    return render_template('admin.html')

## Sign Up for a Task
@app.route('/signup/<string:task_id>', methods=['POST'])
def signup(task_id):
    if not session.get('logged_in'):
        flash('Please log in to sign up for tasks.', 'danger')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    cur = mysql.connection.cursor()
    # Check if already signed up
    cur.execute("SELECT * FROM signups WHERE user_id = %s AND task_id = %s", (user_id, task_id))
    if cur.fetchone():
        flash('You have already signed up for this task!', 'info')
        return redirect(url_for('index'))

    cur.execute("INSERT INTO signups(user_id, task_id) VALUES (%s, %s)", (user_id, task_id))
    mysql.connection.commit()
    cur.close()
    
    flash('You have successfully signed up for the task!', 'success')
    return redirect(url_for('index'))

## Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# --- Main execution ---
if __name__ == '__main__':
#    print("0====")
    #app.run(host='127.0.0.1', port=5000)
    #app.run(debug=True)
 #   print("1====")
    # Hashing the initial admin password on first run (optional but good practice)
  #  with app.app_context():
   #     print("1i====")
    #    cur = mysql.connection.cursor()
     #   print("2=====")
      #  cur.execute("SELECT password FROM users WHERE username = 'admin'")
      #  print("3=====")
      #  admin_user = cur.fetchone()
      #  print("admin_user",admin_user)
      #  if admin_user and admin_user['password'] == 'adminpass':
      #      print("4i=====")
      #      hashed_pass = sha256_crypt.encrypt('adminpass')
      #      cur.execute("UPDATE users SET password = %s WHERE username = 'admin'", [hashed_pass])
      #      mysql.connection.commit()
      #  cur.close()
      #  print("4====")
    app.run(debug=True)