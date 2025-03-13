from dotenv import load_dotenv
import os
import mysql.connector

# 1) Load environment variables from .env
load_dotenv()

# 2) Retrieve each variable from the environment
MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_PORT = os.getenv("MYSQL_PORT")
MYSQL_DB = os.getenv("MYSQL_DB")

# 3) Connect to MySQL
connection = mysql.connector.connect(
    user=MYSQL_USER,
    password=MYSQL_PASSWORD,
    host=MYSQL_HOST,
    port=MYSQL_PORT,
    database=MYSQL_DB
)

# 4) Create a cursor to execute queries
cursor = connection.cursor()

# 5) Sample query (optional)
cursor.execute("SELECT VERSION()")
version = cursor.fetchone()
print("MySQL Server version:", version[0])

# 6) Close the cursor and connection when done
cursor.close()
connection.close()
