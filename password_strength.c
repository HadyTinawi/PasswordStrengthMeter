/**
 * @file password_strength.c
 * @brief Password strength meter and default password generator
 * 
 * This program allows users to create strong passwords by enforcing
 * strength requirements and offering a secure password generator.
 * It implements two password strength standards:
 * 1. Strong passwords (with string requirements)
 * 2. Default passwords (simplified requirements)
 * 
 * @author Original: Hady Tinawi
 * @date February 27, 2025
 */

 #include <stdio.h>
 #include <ctype.h>
 #include <string.h>
 #include <stdbool.h>
 #include <time.h>
 #include <stdlib.h>
 
 /* Function Prototypes */
 bool isStrongPassword(const char* username, const char* password);
 bool isStrongDefaultPassword(const char* username, const char* password);
 void generateDefaultPassword(char* default_password, const char* username);
 bool promptForNewPassword(char* customPassword, const char* username);
 
 /**
  * @brief Checks if password contains at least 4 consecutive alphabetic characters
  *
  * @param pwd Password string to check
  * @return true if contains 4+ consecutive letters, false otherwise
  */
 bool containsString(const char* pwd) {
     int consecutiveLetters = 0;
     
     while (*pwd != '\0') {
         if (isalpha(*pwd)) {
             consecutiveLetters++;
             if (consecutiveLetters >= 4) {
                 return true;
             }
         } else {
             consecutiveLetters = 0;
         }
         pwd++;
     }
     
     return false;
 }
 
 /**
  * @brief Checks if password contains at least one uppercase letter
  *
  * @param pwd Password string to check
  * @return true if contains uppercase, false otherwise
  */
 bool hasUpper(const char* pwd) {
     for (int i = 0; pwd[i] != '\0'; i++) {
         if (isupper(pwd[i])) {
             return true;
         }
     }
     
     return false;
 }
 
 /**
  * @brief Checks if password contains at least one digit
  *
  * @param pwd Password string to check
  * @return true if contains digit, false otherwise
  */
 bool hasDigit(const char* pwd) {
     for (int i = 0; pwd[i] != '\0'; i++) {
         if (isdigit(pwd[i])) {
             return true;
         }
     }
     
     return false;
 }
 
 /**
  * @brief Checks if password contains at least one lowercase letter
  *
  * @param pwd Password string to check
  * @return true if contains lowercase, false otherwise
  */
 bool hasLower(const char* pwd) {
     for (int i = 0; pwd[i] != '\0'; i++) {
         if (islower(pwd[i])) {
             return true;
         }
     }
     
     return false;
 }
 
 /**
  * @brief Checks if password meets minimum length requirement (8 characters)
  *
  * @param pwd Password string to check
  * @return true if length is sufficient, false otherwise
  */
 bool hasMinimumLength(const char* pwd) {
     return strlen(pwd) >= 8;
 }
 
 /**
  * @brief Checks if password contains only alphanumeric characters
  *
  * @param pwd Password string to check
  * @return true if alphanumeric only, false if contains special characters
  */
 bool isAlphanumericOnly(const char* pwd) {
     for (int i = 0; pwd[i] != '\0'; i++) {
         if (!isalnum(pwd[i])) {
             return false;
         }
     }
     
     return true;
 }
 
 /**
  * @brief Checks if password contains username (case-insensitive)
  *
  * @param username Username to check against
  * @param password Password to analyze
  * @return true if password contains username, false otherwise
  */
 bool containsUsername(const char* username, const char* password) {
     if (strlen(username) == 0) {
         return false;  // Empty username can't be contained
     }
     
     for (int i = 0; i <= strlen(password) - strlen(username); i++) {
         int j;
         for (j = 0; j < strlen(username); j++) {
             if (tolower(password[i + j]) != tolower(username[j])) {
                 break;
             }
         }
         if (j == strlen(username)) {
             return true;  // Username found in password
         }
     }
     
     return false;
 }
 
 /**
  * @brief Validates if a password meets strong password criteria
  * 
  * A strong password must:
  * - Be at least 8 characters long
  * - Contain at least one uppercase letter
  * - Contain at least one lowercase letter
  * - Contain at least one digit
  * - Contain only alphanumeric characters
  * - Contain at least 4 consecutive letters
  * - Not contain the username
  *
  * @param username User's username (to ensure it's not in the password)
  * @param password Password to validate
  * @return true if password meets all criteria, false otherwise
  */
 bool isStrongPassword(const char* username, const char* password) {
     if (!hasMinimumLength(password)) {
         return false;
     }
     
     if (!hasUpper(password) || !hasLower(password) || !hasDigit(password)) {
         return false;
     }
     
     if (!isAlphanumericOnly(password)) {
         return false;
     }
     
     if (!containsString(password)) {
         return false;
     }
     
     if (containsUsername(username, password)) {
         return false;
     }
     
     return true;
 }
 
 /**
  * @brief Validates if a password meets default password criteria
  * 
  * A default password must:
  * - Be 15 characters or fewer
  * - Contain at least one uppercase letter
  * - Contain at least one lowercase letter
  * - Contain at least one digit
  * - Contain only alphanumeric characters
  *
  * @param username User's username (unused but kept for API consistency)
  * @param password Password to validate
  * @return true if password meets all criteria, false otherwise
  */
 bool isStrongDefaultPassword(const char* username, const char* password) {
     if (strlen(password) > 15) {
         return false;
     }
     
     if (!hasUpper(password) || !hasLower(password) || !hasDigit(password)) {
         return false;
     }
     
     if (!isAlphanumericOnly(password)) {
         return false;
     }
     
     return true;
 }
 
 /**
  * @brief Generates a secure default password meeting default password criteria
  * 
  * Creates a random alphanumeric password that passes isStrongDefaultPassword()
  *
  * @param default_password Buffer to store the generated password (must be at least 16 bytes)
  * @param username User's username (used for validation)
  */
 void generateDefaultPassword(char* default_password, const char* username) {
     const char validCharacters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
     const int numValidChars = strlen(validCharacters);
     
     // Seed random number generator
     srand(time(NULL));
     
     do {
         // Generate random password length (1-15 characters)
         int passwordLength = rand() % 15 + 1;
         
         // Fill with random valid characters
         for (int i = 0; i < passwordLength; i++) {
             default_password[i] = validCharacters[rand() % numValidChars];
         }
         default_password[passwordLength] = '\0';
         
     } while (!isStrongDefaultPassword(username, default_password));
 }
 
 /**
  * @brief Prompts user to enter a new password and validates it
  *
  * @param customPassword Buffer to store the entered password
  * @param username User's username (for validation)
  * @return true if entered password meets requirements, false otherwise
  */
 bool promptForNewPassword(char* customPassword, const char* username) {
     printf("Enter new password: ");
     scanf("%s", customPassword);
     
     if (isStrongPassword(username, customPassword)) {
         printf("Strong password!\n");
         return true;
     } else {
         printf("Your password is weak. Try again!\n");
         return false;
     }
 }
 
 /**
  * @brief Main program function
  * 
  * Controls program flow:
  * 1. Prompts for username
  * 2. Generates a default password
  * 3. Allows user to create a custom password if desired
  *
  * @return 0 on successful execution
  */
 int main(void) {
     char username[100];
     char default_password[16];  // Max 15 chars + null terminator
     char customPassword[100];
     
     // Get username
     printf("Enter username: ");
     scanf("%s", username);
     
     // Generate and display default password
     generateDefaultPassword(default_password, username);
     printf("Generating a default password...\n");
     printf("Generated default password: %s\n", default_password);
     
     // Ask if user wants to manually set password
     printf("Manually change password? (y/n): ");
     char choice[3];
     scanf(" %s", choice);
     
     if (strcmp(choice, "y") == 0 || strcmp(choice, "Y") == 0) {
         // Keep prompting until a strong password is provided
         while (!promptForNewPassword(customPassword, username)) {
             // Loop body is empty because promptForNewPassword handles everything
         }
         printf("Successfully created password: %s\n", customPassword);
     } else {
         printf("You chose not to change your password.\n");
     }
     
     return 0;
 }