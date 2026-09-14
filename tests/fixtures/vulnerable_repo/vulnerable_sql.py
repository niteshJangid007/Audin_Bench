# Vulnerable SQL Query concatenation
import sqlite3

def get_user_profile(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Flaw: RULE_A03_SQL_CONCAT
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
