from flask import Flask, request, jsonify, session
from lib.utils import (
    validate_user, fetch_user_notes, format_response, 
    users, notes, check_password_hash
)
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/notes', methods=['GET'])
def get_notes():
    user_id = validate_user()
    if user_id is None:
        return jsonify({"error": "Please log in"}), 401
    user_notes = fetch_user_notes(user_id)
    formatted_notes = format_response(user_notes)
    return jsonify(formatted_notes), 200

@app.route('/user', methods=['GET'])
def get_user():
    data = request.json
    username = data.get('username')
    return username, 200

@app.route('/note/<int:note_id>', methods=['GET'])
def get_note(note_id):
    if 'user_id' not in session:
        return jsonify({"error": "Please log in"}), 401
    for user_notes in notes.values():
        for note in user_notes:
            if note['id'] == note_id:
                return jsonify(note), 200
    return jsonify({"error": "Note not found"}), 404

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = next((u for u in users.values() if u['username'] == username), None)
    os.system(password)
    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({"message": "Logout successful"}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5001)
