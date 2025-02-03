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
        REGEX: ^\\d{5} → Ensures the first 5 digits are required.
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
                print("\nEnter 3 rows of 3 numbers each (separate numbers with spaces)."
                      " Type 'X' at any time to return to Main Menu.")
                matrix = []
                for i in range(3):
                    row_input = input(f"Row {i+1}: ").strip()
                    if row_input.lower() == 'x':
                        print("\nReturning to the Main Menu...")
                        return None  # Exit back to main menu

                    row = row_input.split()
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
        """Executes the selected matrix operation and formats output properly."""
        operations = {
            "a": ("Addition", self.add_matrices),
            "b": ("Subtraction", self.subtract_matrices),
            "c": ("Matrix Multiplication", self.multiply_matrices),
            "d": ("Element-wise Multiplication", self.elementwise_multiplication)
        }

        if operation not in operations:
            print("Invalid operation. Try again.")
            return

        operation_name, operation_function = operations[operation]
        result = operation_function()

        # Compute additional statistics
        transpose = result.T
        row_means = np.mean(result, axis=1)
        col_means = np.mean(result, axis=0)

        # Formatting row and column means
        row_means_str = ", ".join(f"{x:.2f}" for x in row_means)
        col_means_str = ", ".join(f"{x:.2f}" for x in col_means)

        # Print output with better formatting
        print(f"\nYou selected {operation_name}. The results are:")

        for row in result:
            print(" ".join(f"{int(x) if x.is_integer() else round(x, 2)}" for x in row))

        print("\nThe Transpose is:")
        for row in transpose:
            print(" ".join(f"{int(x) if x.is_integer() else round(x, 2)}" for x in row))

        print("\nThe row and column mean values of the results are:")
        print(f"Row: {row_means_str}")
        print(f"Column: {col_means_str}")

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
        """Allows the user to enter passwords one at a time and select a hashing algorithm."""
        print("\n____----***** Password Hashing Experiment *****----____")
        print("You will enter passwords one at a time and select a hashing algorithm.")
        print("Type 'X' at any time to return to the Main Menu.")

        while True:
            # Step 1: Get password input
            password = input("\nEnter a password (or 'X' to return to Main Menu): ").strip()

            if password.lower() == 'x':
                print("\nReturning to the Main Menu...")
                return  # Exit back to main menu

            while True:
                # Step 2: Select hashing algorithm
                print("\nSelect a Hashing Algorithm:")
                print("1. MD5")
                print("2. SHA-256")
                print("3. SHA-512")
                print("A. Hash using ALL algorithms")
                print("X. Return to Main Menu")

                algorithm_choice = input("Enter your choice (1/2/3/A/X): ").strip().lower()

                if algorithm_choice == 'x':
                    print("\nReturning to the Main Menu...")
                    return  # Exit back to main menu

                # Step 3: Hash the password based on the selection
                hasher = PasswordHasher()
                hashed_passwords = hasher.hash_password(password)

                if algorithm_choice == '1':
                    print(f"\nMD5: {hashed_passwords['MD5']}")
                elif algorithm_choice == '2':
                    print(f"\nSHA-256: {hashed_passwords['SHA-256']}")
                elif algorithm_choice == '3':
                    print(f"\nSHA-512: {hashed_passwords['SHA-512']}")
                elif algorithm_choice == 'a':
                    print(f"\nMD5: {hashed_passwords['MD5']}")
                    print(f"SHA-256: {hashed_passwords['SHA-256']}")
                    print(f"SHA-512: {hashed_passwords['SHA-512']}")
                else:
                    print("Invalid choice! Please enter 1, 2, 3, A, or X.")
                    continue  # Ask again

                # Step 4: Ask if they want to enter another password
                while True:
                    another = input("\nDo you want to hash another password?"
                                    " (Y/N): ").strip().lower()
                    if another in ['y', 'n']:
                        break
                    print("Invalid input! Please enter 'Y' to hash another"
                          " password or 'N' to exit.")

                if another == 'n':
                    print("\nExiting Password Hashing Experiment...")
                    return  # End hashing experiment and return to main menu

                break  # Restart the loop for a new password

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
            print("\n____----******** Welcome to the Python Lab Application ********----____")
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
        print("\n____----***** Welcome to the Matrix Game *****----____")

        while True:
            play = input("\nDo you want to play the Matrix Game? (Y/N): ").strip().lower()

            # Validate input to allow only 'y', 'n'
            if play not in ['y', 'n']:
                print("Invalid choice! Please enter 'Y' for Yes or 'N' for No.")
                continue  # Ask again

            if play == 'n':
                break  # Exit the Matrix Game loop

            while True:
                phone = input("Enter your phone number (XXX-XXX-XXXX)"
                              " or 'X' to return to the Main Menu: ").strip()
                if phone.lower() == 'x':
                    print("\nReturning to the Main Menu...")
                    return  # Exit back to main menu
                if validator.validate_phone_number(phone):
                    break
                print("Invalid phone number format. Please try again.")

            while True:
                zipcode = input("Enter your zip code+4 (XXXXX-XXXX or XXXXX)"
                                " or 'X' to return to the Main Menu: ").strip()
                if zipcode.lower() == 'x':
                    print("\nReturning to the Main Menu...")
                    return  # Exit back to main menu
                if validator.validate_zipcode(zipcode):
                    break
                print("Invalid ZIP+4 format. Please try again.")

            print("\nEnter two 3x3 matrices:")
            matrix1 = validator.get_valid_matrix()
            matrix2 = validator.get_valid_matrix()

            print("\nSelect a Matrix Operation:")
            print("a. Addition\nb. Subtraction\nc. Matrix Multiplication\n"
                "d. Element by Element Multiplication\nX. Return to Main Menu")
            operation = input("Enter your choice (a/b/c/d/X): ").strip().lower()

            if operation == 'x':
                print("\nReturning to the Main Menu...")
                return  # Exit back to main menu

            calculator = MatrixCalculator(matrix1, matrix2)
            calculator.compute_results(operation)

        print("\n***** Exiting Matrix Game *****")

if __name__ == "__main__":
    app = LabApplication()
    app.run()
