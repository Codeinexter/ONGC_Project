import sqlite3

# Connect to SQLite database
conn = sqlite3.connect("database.db")

# Create a cursor object
cursor = conn.cursor()

# Create users table
cursor.execute("""
CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    mobile_number TEXT NOT NULL,
    password BLOB NOT NULL,
    privilege TEXT DEFAULT 'user',
    email_verified INTEGER DEFAULT 0,
    mobile_verified INTEGER DEFAULT 0,
    image_path TEXT
);
""")

# Create data table
cursor.execute("""
CREATE TABLE IF NOT EXISTS data_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_type TEXT,
    uploaded_by INTEGER,
    visibility TEXT NOT NULL,
    approval_status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uploaded_by) REFERENCES user(id)
);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS approval_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data_id INTEGER NOT NULL,
    requested_by INTEGER NOT NULL,
    current_approver_role TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    remarks TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    FOREIGN KEY (data_id) REFERENCES data_items(id),
    FOREIGN KEY (requested_by) REFERENCES user(id)
);
""")

# Commit changes and close the connection
conn.commit()
conn.close()

print("Database and table created successfully.")
