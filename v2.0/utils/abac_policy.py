from config import db

def check_user_access(username, action):
    user_ref = db.collection('users').document(username)
    user = user_ref.get()
    if user.exists:
        user_data = user.to_dict()
        if user_data.get('role') == 'admin':
            return True
        elif action == 'get' and user_data.get('role') == 'user':
            return True
    return False
