# Password Strength Checker and Generator

## Overview
This C program implements a password strength checker and generator that helps users create secure passwords by enforcing specific strength requirements. The system supports two password strength standards and offers a secure default password generation feature.

## Features
- Strong password validation with comprehensive requirements
- Default password validation with simplified requirements
- Secure random password generator
- Username detection to prevent insecure password creation
- Interactive command-line interface

## Requirements
- C compiler (GCC recommended)
- Standard C libraries

## Installation
1. Clone or download the source code
2. Compile the program:
```
gcc password_strength.c -o password_strength
```

## Usage
Run the compiled program:
```
./password_strength
```

Follow the interactive prompts to:
1. Enter a username
2. Receive a generated default password
3. Optionally create a custom password that meets security requirements

## Password Requirements

### Strong Password Requirements
A password is considered strong when it meets ALL of the following criteria:
- At least 8 characters long
- Contains at least one uppercase letter
- Contains at least one lowercase letter
- Contains at least one digit
- Contains only alphanumeric characters (no special characters)
- Contains at least 4 consecutive alphabetic characters
- Does not contain the username

### Default Password Requirements
A default password must meet these simplified criteria:
- 15 characters or fewer
- Contains at least one uppercase letter
- Contains at least one lowercase letter
- Contains at least one digit
- Contains only alphanumeric characters

## Program Structure

### Key Functions
- `isStrongPassword()` - Validates passwords against the strong password criteria
- `isStrongDefaultPassword()` - Validates passwords against the default password criteria
- `generateDefaultPassword()` - Creates a secure random password
- `promptForNewPassword()` - Handles user input for custom password creation

### Helper Functions
- `containsString()` - Checks for 4+ consecutive alphabetic characters
- `hasUpper()` - Verifies presence of uppercase letters
- `hasLower()` - Verifies presence of lowercase letters
- `hasDigit()` - Verifies presence of numeric digits
- `hasMinimumLength()` - Checks minimum length requirement
- `isAlphanumericOnly()` - Ensures no special characters are present
- `containsUsername()` - Detects if username is embedded in password

## Security Notes
- The default password generator uses `srand(time(NULL))` which may not be suitable for high-security applications
- The program uses `scanf()` for input which could lead to buffer overflows with very long inputs
- For production use, consider implementing additional security measures such as password hashing

## Example Usage
```
Enter username: johnsmith
Generating a default password...
Generated default password: xT5aRbJ
Manually change password? (y/n): y
Enter new password: pass123
Your password is weak. Try again!
Enter new password: StrongPass2023
Strong password!
Successfully created password: StrongPass2023
```
