from db_utils import *
from crypto_utils import *

def get_user_pass():
    username = input("\n Enter a username \n")
    password = input("\n Enter a password \n ")
    password2 = input("\n Confirm your password \n")
    if password == password2:
        return username, password
    else:
        print("Passwords did not match")
        return get_user_pass()

def login_user(db_name: str, username: str, password: str):
    username_sha256 = gen_hash(username)
    user = retrieve_user(db_name, username_sha256)
    print("Retrieved user:", user)  # Debug statement to print user tuple
    if user:
        stored_password_salt = user[2]
        stored_password_bcrypt = user[3]
        if bcrypt.checkpw(password.encode('utf-8'), stored_password_bcrypt):
            print(f"User {username} logged in successfully.")
            return user
        else:
            print("Incorrect password.")
            return None
    else:
        print("Username not found.")
        return None

def add_website_password(db_name: str, user: tuple, password: str):
    website = input("\n Enter the website name \n")
    website_password = input("\n Enter the website password \n")
    value_iv = generate_iv()
    
    # Decrypt the intermediate key
    user_key_iv = user[6]
    encrypted_aes_key = user[7]
    password_based_key = pbkdf2(user[4], password)
    intermediate_key = aes256_decrypt(user_key_iv, password_based_key, encrypted_aes_key)
    
    # Encrypt the website password with the intermediate key
    encrypted_password = aes256_encrypt(value_iv, intermediate_key, website_password.encode('utf-8'))
    
    add_data_entity(db_name, user[0], website, value_iv, encrypted_password)
    print(f"Password for {website} added successfully.")

def retrieve_website_password(db_name: str, user: tuple, password: str):
    data_entities = retrieve_data_entities(db_name, user[0])
    if not data_entities:
        print("No passwords stored for this user.")
        return

    print("Stored websites:")
    for entity in data_entities:
        print(f"ID: {entity[0]}, Website: {entity[2]}")
    
    entity_id = int(input("\n Enter the ID of the website password you want to retrieve \n"))
    
    # Find the selected entity
    selected_entity = None
    for entity in data_entities:
        if entity[0] == entity_id:
            selected_entity = entity
            break
    
    if not selected_entity:
        print("Invalid ID selected.")
        return
    
    value_iv = selected_entity[3]
    encrypted_password = selected_entity[4]
    
    # Decrypt the intermediate key
    user_key_iv = user[6]
    encrypted_aes_key = user[7]
    password_based_key = pbkdf2(user[4], password)
    intermediate_key = aes256_decrypt(user_key_iv, password_based_key, encrypted_aes_key)
    
    # Decrypt the website password with the intermediate key
    decrypted_password = aes256_decrypt(value_iv, intermediate_key, encrypted_password)
    print(f"Password for {selected_entity[2]}: {decrypted_password.decode('utf-8')}")

def main():
    db_name = "password_manager.db"
    initialize_database(db_name)

    res = int(input("\n 1. Create user \n 2. Log in \n"))

    if res == 1:
        username, password = get_user_pass()
        username_sha256 = gen_hash(username)
        password_bcrypt, password_salt = generate_bcrypt(password)
        pbkdf2_key_salt = generate_salt()
        user_key_iv = generate_iv()

        intermediate_key = generate_aes_key()
        password_based_key = pbkdf2(pbkdf2_key_salt, password)

        user_key_aes256cbc = aes256_encrypt(user_key_iv, password_based_key, intermediate_key)

        add_user(db_name, username, username_sha256, password_salt, password_bcrypt, pbkdf2_key_salt, user_key_iv, user_key_aes256cbc)

        print(f"User {username} added successfully.")

    elif res == 2:
        username = input("\n Enter your username \n")
        password = input("\n Enter your password \n")
        user = login_user(db_name, username, password)
        if user:
            while True:
                action = int(input("\n 1. Add website password \n 2. Retrieve website password \n 3. Logout \n"))
                if action == 1:
                    add_website_password(db_name, user, password)
                elif action == 2:
                    retrieve_website_password(db_name, user, password)
                elif action == 3:
                    print("Logged out.")
                    break
                else:
                    print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
