"""
Lab 4: Python Matrix Application and Password Hashing Experiment

This program allows users to:
1. Perform matrix operations (addition, subtraction, multiplication).
2. Validate phone numbers and ZIP codes.
3. Generate password hashes and analyze password security.

Users can select between these features through a main menu.
"""

import hashlib
import numpy as np
import pandas as pd

class UserInputValidator:
    """Handles validation of user inputs like phone numbers, zip codes, and matrices."""

    def validate_phone_number(self, phone):
        """Validates phone number format XXX-XXX-XXXX using Pandas."""
        if not isinstance(phone, str):
            return False
        df = pd.DataFrame({'Phone': [phone]})
        return df['Phone'].str.match(r'^\d{3}-\d{3}-\d{4}$').iat[0]

    def validate_zipcode(self, zipcode):
        """
        Validates zip code format XXXXX-XXXX or XXXXX using Pandas.
        ^\\d{5} → Ensures the first 5 digits are required.
        (-\\d{4})? → Optional hyphen followed by 4 digits.
        $ → Ensures nothing extra is added after the ZIP code.
        """
        if not isinstance(zipcode, str):
            return False
        df = pd.DataFrame({'Zipcode': [zipcode]})
        return df['Zipcode'].str.match(r'^\d{5}(-\d{4})?$').iat[0]

    def get_valid_matrix(self):
        """Prompts user to enter a 3x3 matrix and validates input."""
        while True:
            try:
                print("\nEnter 3 rows of 3 numbers each (separate numbers with spaces):")
                matrix = []
                for i in range(3):
                    row = input(f"Row {i+1}: ").strip().split()
                    if len(row) != 3:
                        raise ValueError("Each row must have exactly 3 numbers.")
                    matrix.append([float(num) for num in row])
                return np.array(matrix)
            except ValueError as e:
                print(f"Invalid input: {e}. Please try again.")

class MatrixCalculator:
    """
    Performs matrix operations including addition, subtraction, 
    multiplication, and element-wise multiplication.
    """

    def __init__(self, matrix1, matrix2):
        self.matrix1 = matrix1
        self.matrix2 = matrix2

    def add_matrices(self):
        """Returns the sum of two matrices."""
        return self.matrix1 + self.matrix2

    def subtract_matrices(self):
        """Returns the difference between two matrices."""
        return self.matrix1 - self.matrix2

    def multiply_matrices(self):
        """Returns the matrix product."""
        return np.matmul(self.matrix1, self.matrix2)

    def elementwise_multiplication(self):
        """Returns the element-wise multiplication of two matrices."""
        return self.matrix1 * self.matrix2

    def compute_results(self, operation):
        """Executes the selected matrix operation and calculates statistics."""
        operations = {
            "a": self.add_matrices,
            "b": self.subtract_matrices,
            "c": self.multiply_matrices,
            "d": self.elementwise_multiplication
        }
        if operation not in operations:
            print("Invalid operation. Try again.")
            return

        result = operations[operation]()
        print("\nResulting Matrix:\n", result)
        print("\nTranspose:\n", result.T)
        print("\nRow Means:", np.mean(result, axis=1))
        print("Column Means:", np.mean(result, axis=0))

class PasswordHasher:
    """Handles password hashing using MD5, SHA-256, and SHA-512."""

    def hash_password(self, password):
        """Hashes a password using MD5, SHA-256, and SHA-512."""
        password_bytes = password.encode()
        return {
            "MD5": hashlib.md5(password_bytes).hexdigest(),
            "SHA-256": hashlib.sha256(password_bytes).hexdigest(),
            "SHA-512": hashlib.sha512(password_bytes).hexdigest()
        }

    def test_passwords(self):
        """Prompts user to enter passwords for hashing and displays their hash values."""
        print("\n***** Password Hashing Experiment *****")
        print("Enter 10-20 passwords to hash and analyze (Type 'done' when finished).")

        passwords = []
        while len(passwords) < 20:
            pwd = input(f"Enter password {len(passwords)+1} (or 'done' to finish): ").strip()
            if pwd.lower() == 'done':
                if len(passwords) < 10:
                    print("You must enter at least 10 passwords.")
                else:
                    break
            else:
                passwords.append(pwd)

        print("\nPassword Hashing Results:")
        for pwd in passwords:
            hashes = self.hash_password(pwd)
            print(f"\nPassword: {pwd}")
            print(f"MD5: {hashes['MD5']}")
            print(f"SHA-256: {hashes['SHA-256']}")
            print(f"SHA-512: {hashes['SHA-512']}")

        print("\nNow go to Crackstation.net and try to crack these hashes. "
              "Record your findings in your report.")

class LabApplication:
    """Main application handling user interaction and execution flow."""

    def run(self):
        """
        Main menu loop to allow user to choose between the matrix game 
        and password hashing experiment.
        """
        validator = UserInputValidator()
        hasher = PasswordHasher()

        while True:
            print("\n******** Welcome to the Python Lab Application ********")
            print("1. Play the Matrix Game")
            print("2. Run Password Hashing Experiment")
            print("3. Exit")

            choice = input("Enter your choice (1/2/3): ").strip()

            if choice == '1':
                self.run_matrix_game(validator)
            elif choice == '2':
                hasher.test_passwords()
            elif choice == '3':
                print("\nExiting program. Thank you!")
                break
            else:
                print("\nInvalid choice. Please enter 1, 2, or 3.")

    def run_matrix_game(self, validator):
        """Handles the Matrix Game operations."""
        print("\n***** Welcome to the Matrix Game *****")

        while True:
            play = input("\nDo you want to play the Matrix Game? (Y/N): ").strip().lower()
            if play == 'n':
                break

            while True:
                phone = input("Enter your phone number (XXX-XXX-XXXX): ").strip()
                if validator.validate_phone_number(phone):
                    break
                print("Invalid phone number format. Please try again.")

            while True:
                zipcode = input("Enter your zip code+4 (XXXXX-XXXX): ").strip()
                if validator.validate_zipcode(zipcode):
                    break
                print("Invalid ZIP+4 format. Please try again.")

            print("\nEnter two 3x3 matrices:")
            matrix1 = validator.get_valid_matrix()
            matrix2 = validator.get_valid_matrix()

            print("\nSelect a Matrix Operation:")
            print("a. Addition\nb. Subtraction\nc. Matrix Multiplication\n"
                  "d. Element by Element Multiplication")
            operation = input("Enter your choice (a/b/c/d): ").strip().lower()

            calculator = MatrixCalculator(matrix1, matrix2)
            calculator.compute_results(operation)

        print("\n***** Exiting Matrix Game *****")

if __name__ == "__main__":
    app = LabApplication()
    app.run()
