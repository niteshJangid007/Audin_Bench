from flask import Flask, request, jsonify

app = Flask(__name__)

users = {
    1: {"name": "Nitesh", "email": "nitesh@example.com"},
    2: {"name": "Rahul", "email": "rahul@example.com"}
}

@app.route("/profile/<int:user_id>")
def profile(user_id):
    user = users.get(user_id)
    if user:
        return jsonify(user)
    return jsonify({"error": "User not found"}), 404

app.run(debug=True)
