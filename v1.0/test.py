import bcrypt

password = 'password'

hash1 = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(10))
hash2 = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(10))

print(hash1.decode('utf-8'))
print(hash2.decode('utf-8'))