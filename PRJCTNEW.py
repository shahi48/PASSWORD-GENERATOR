import random
import string
import getpass


PRIVILEGED_USER = "SHAHINA"
PRIVILEGED_PASS = "shahi@123"

def verify_user():
    """
    Verifies if the user is a privileged user.
    Returns True if the credentials are correct, otherwise False.
    """
    print("=== Privileged User Authentication ===")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")  

    if username == PRIVILEGED_USER and password == PRIVILEGED_PASS:
        print("Access granted.")
        return True
    else:
        print("Access denied. Unauthorized user.")
        return False

def generate_password(length, include_upper=True, include_lower=True, include_digits=True, include_special=True):
    """
    Generates a strong password of the specified length.
    Allows user to customize inclusion of uppercase, lowercase, digits, and special characters.
    """
    if length < 8:
        print("Password length should be at least 8 characters for security.")
        return None

    
    character_set = ""
    if include_upper:
        character_set += string.ascii_uppercase
    if include_lower:
        character_set += string.ascii_lowercase
    if include_digits:
        character_set += string.digits
    if include_special:
        character_set += string.punctuation

    if not character_set:
        print("At least one character type must be selected.")
        return None

    
    password = []
    if include_upper:
        password.append(random.choice(string.ascii_uppercase))
    if include_lower:
        password.append(random.choice(string.ascii_lowercase))
    if include_digits:
        password.append(random.choice(string.digits))
    if include_special:
        password.append(random.choice(string.punctuation))

    
    password += random.choices(character_set, k=length - len(password))

    
    random.shuffle(password)

    return ''.join(password)  

def main():
    """
    Main function to run the password generator.
    It first authenticates the user and then generates the password.
    """
    if not verify_user():
        return  

    try:
        length = int(input("Enter desired password length (min 8): "))
        
        
        print("Select password options:")
        include_upper = input("Include uppercase letters? (y/n): ").strip().lower() == 'y'
        include_lower = input("Include lowercase letters? (y/n): ").strip().lower() == 'y'
        include_digits = input("Include digits? (y/n): ").strip().lower() == 'y'
        include_special = input("Include special characters? (y/n): ").strip().lower() == 'y'

        password = generate_password(length, include_upper, include_lower, include_digits, include_special)
        if password:
            print(f"Generated Password: {password}")
            
    except ValueError:
        print("Invalid input. Please enter a valid number.")

if __name__ == "__main__":
    main()
