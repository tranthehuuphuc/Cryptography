from config import db

def check_user_access(username, resource):
    user_ref = db.collection('users').document(username)
    user = user_ref.get()
    user_data = user.to_dict()
    role = user_data.get('role')

    if role == 'admin':
        if resource == 'admin-api' or resource == 'user-api':
            return True
    elif role == 'user':
        if resource == 'user-api':
            return True
        
    return False
