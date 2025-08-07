import bcrypt as bcrypt

def hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_hash(password, hash):
    return bcrypt.checkpw(password.encode('utf-8'), hash.encode('utf-8'))