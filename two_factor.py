import pyfiglet  # Import pyfiglet for creating ASCII art
import pyotp  # Import the pyotp library for generating and verifying OTPs
import getpass  # Import getpass for securely reading passwords

# Define the text for your banner
app_name = "2FA_App"
version = "v1.0.0"
coder = "Coded by Brayan"

# Create ASCII art using pyfiglet
banner = pyfiglet.figlet_format(app_name, font="bubble")
version_info = f"Version: {version}"
coder_info = f"{coder}"

# Print the banner
print(banner)
print(version_info)
print(coder_info)

# In-memory user database (for demonstration purposes)
users = {}

def register_user(username):
    """Register a new user with 2FA."""
    # Check if the username already exists
    if username in users:
        print("Username already exists!")
        return

    # Prompt for the user's password
    password = getpass.getpass("Enter password: ")
    # Generate a random base32 secret key for the user
    secret = pyotp.random_base32()
    # Store the user info in the users dictionary
    users[username] = {"password": password, "secret": secret}
    print(f"User {username} registered successfully.")
    print("Secret key (store this securely):", secret)  # Print the secret key for reference

def login_user(username):
    """Login user and generate OTP."""
    # Retrieve user data from the dictionary
    user = users.get(username)
    if not user:
        print("User not found!")
        return

    # Prompt for the user's password
    password = getpass.getpass("Enter password: ")
    # Check if the entered password matches the stored password
    if user["password"] == password:
        # Create a TOTP object with the user's secret
        totp = pyotp.TOTP(user["secret"])
        # Generate the current OTP
        otp = totp.now()
        print(f"Current OTP (for demo purposes): {otp}")  # In practice, send this via email/SMS
        return otp
    else:
        print("Invalid password.")  # Notify if the password is incorrect

def verify_otp(username, expected_otp):
    """Verify the OTP entered by the user."""
    # Retrieve user data
    user = users.get(username)
    if not user:
        print("User not found!")
        return

    # Create a TOTP object to verify the OTP
    totp = pyotp.TOTP(user["secret"])
    # Verify the user's OTP
    if totp.verify(expected_otp):
        print("OTP is valid! Login successful.")
    else:
        print("Invalid OTP.")  # Notify if the OTP is incorrect

def main():
    """Main function to handle user interactions."""
    while True:
        # Prompt for action (register, login, or exit)
        action = input("Choose an action (register/login/exit): ").strip().lower()
        if action == 'register':
            # If the action is to register, get a username and register the user
            username = input("Enter username: ")
            register_user(username)
        elif action == 'login':
            # If the action is to login, get the username and attempt to login
            username = input("Enter username: ")
            otp = login_user(username)
            if otp is not None:  # Proceed only if login was successful
                user_otp = input("Enter the OTP: ")
                # Verify the entered OTP
                verify_otp(username, user_otp)
        elif action == 'exit':
            print("Exiting.")  # Exit the program
            break
        else:
            print("Invalid action. Please choose 'register', 'login', or 'exit'.")

if __name__ == "__main__":
    main()  # Run the main function when the script is executed
