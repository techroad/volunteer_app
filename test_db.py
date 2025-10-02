import MySQLdb

# --- IMPORTANT: Use the EXACT same details as in your app.py ---
DB_HOST = "localhost"
DB_USER = "root"
DB_PASS = "password"  # Use your actual password here
DB_NAME = "volunteer_db"

try:
    print("Attempting to connect...")
    db = MySQLdb.connect(host=DB_HOST, user=DB_USER, passwd=DB_PASS, db=DB_NAME)
    print("✅ Success! Database connection is working.")
    db.close()
except Exception as e:
    print("❌ Failure! Could not connect to the database.")
    print("Error:", e)