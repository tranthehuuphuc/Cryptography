import os

secret_key = os.urandom(32)
data = f"SECRET_KEY='{secret_key.hex()}'\n"

with open('.env', 'w') as file:
    file.write(data)

print("Successflly!")