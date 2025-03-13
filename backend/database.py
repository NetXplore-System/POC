# database.py (revised)

from dotenv import load_dotenv
import os
import mysql.connector

load_dotenv()

MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_PORT = os.getenv("MYSQL_PORT")
MYSQL_DB = os.getenv("MYSQL_DB")

db = mysql.connector.connect(
    user=MYSQL_USER,
    password=MYSQL_PASSWORD,
    host=MYSQL_HOST,
    port=MYSQL_PORT,
    database=MYSQL_DB
)

# OPTIONAL: You can do a quick check if you want:
# cursor = db.cursor()
# cursor.execute("SELECT VERSION()")
# version = cursor.fetchone()
# print("MySQL Server version:", version[0])
# cursor.close()

# DO NOT close db here. Let main.py handle that.
