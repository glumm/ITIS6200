#!/usr/bin/env python3
"""
File Hash Validator
A program to generate hash tables for files in a directory and verify file integrity.
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Dict, Tuple


def hash_file(filepath: str, algorithm: str = 'sha256') -> str:
    """
    Calculates the cryptographic hash of a file's contents.
    
    Args:
        filepath: Path to the file to hash
        algorithm: Hash algorithm to use (default: sha256)
    
    Returns:
        Hexadecimal string representation of the file's hash
    """
    hash_obj = hashlib.new(algorithm)
    
    try:
        with open(filepath, 'rb') as f:
            # Read file in chunks to handle large files efficiently
            while chunk := f.read(8192):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        print(f"Error hashing file {filepath}: {e}")
        return None


def traverse_directory(directory_path: str) -> Dict[str, str]:
    """
    Navigates to the directory and calculates hash values for all files.
    
    Args:
        directory_path: Path to the directory to traverse
    
    Returns:
        Dictionary mapping file paths to their hash values
    """
    hash_table = {}
    
    try:
        # Convert to absolute path
        abs_directory = os.path.abspath(directory_path)
        
        if not os.path.exists(abs_directory):
            print(f"Error: Directory '{directory_path}' does not exist.")
            return hash_table
        
        if not os.path.isdir(abs_directory):
            print(f"Error: '{directory_path}' is not a directory.")
            return hash_table
        
        # Walk through directory and all subdirectories
        for root, dirs, files in os.walk(abs_directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                
                # Calculate hash for each file
                file_hash = hash_file(filepath)
                
                if file_hash:
                    # Store relative path for portability
                    relative_path = os.path.relpath(filepath, abs_directory)
                    hash_table[filepath] = file_hash
                    print(f"Hashed: {relative_path}")
        
        return hash_table
    
    except Exception as e:
        print(f"Error traversing directory: {e}")
        return hash_table


def generate_table(directory_path: str, output_file: str = "hash_table.json") -> bool:
    """
    Generates a hash table for all files in the directory and saves to JSON.
    
    Args:
        directory_path: Path to directory containing files to hash
        output_file: Name of the output JSON file
    
    Returns:
        True if successful, False otherwise
    """
    print(f"\nGenerating hash table for directory: {directory_path}")
    print("-" * 60)
    
    # Traverse directory and generate hashes
    hash_table = traverse_directory(directory_path)
    
    if not hash_table:
        print("\nNo files found or error occurred during hashing.")
        return False
    
    # Save hash table to JSON file
    try:
        with open(output_file, 'w') as f:
            json.dump(hash_table, f, indent=4)
        
        print("-" * 60)
        print(f"\nHash table generated successfully!")
        print(f"Total files hashed: {len(hash_table)}")
        print(f"Hash table saved to: {output_file}")
        return True
    
    except Exception as e:
        print(f"Error saving hash table: {e}")
        return False


def validate_hash(hash_table_file: str = "hash_table.json") -> None:
    """
    Reads the hash table, recomputes hashes, and validates file integrity.
    
    Args:
        hash_table_file: Path to the JSON hash table file
    """
    print("\nValidating file hashes...")
    print("-" * 60)
    
    # Load the hash table
    try:
        with open(hash_table_file, 'r') as f:
            stored_hashes = json.load(f)
    except FileNotFoundError:
        print(f"Error: Hash table file '{hash_table_file}' not found.")
        print("Please generate a hash table first (Option 1).")
        return
    except json.JSONDecodeError:
        print(f"Error: '{hash_table_file}' is not a valid JSON file.")
        return
    except Exception as e:
        print(f"Error loading hash table: {e}")
        return
    
    if not stored_hashes:
        print("Hash table is empty.")
        return
    
    # Track statistics
    valid_count = 0
    invalid_count = 0
    deleted_count = 0
    current_files = set()
    
    # Validate each file in the hash table
    for filepath, stored_hash in stored_hashes.items():
        if os.path.exists(filepath):
            current_files.add(filepath)
            current_hash = hash_file(filepath)
            
            if current_hash == stored_hash:
                print(f"✓ VALID: {filepath}")
                valid_count += 1
            else:
                print(f"✗ INVALID: {filepath} (hash mismatch - file modified)")
                invalid_count += 1
        else:
            print(f"✗ DELETED: {filepath} (file no longer exists)")
            deleted_count += 1
    
    # Check for new files in the directory
    # Extract the base directory from the stored paths
    if stored_hashes:
        # Get the common directory from stored paths
        sample_path = next(iter(stored_hashes.keys()))
        base_dir = os.path.dirname(sample_path)
        
        # Find common root directory
        all_dirs = [os.path.dirname(p) for p in stored_hashes.keys()]
        if all_dirs:
            common_path = os.path.commonpath([p for p in stored_hashes.keys()])
            if os.path.isfile(common_path):
                base_dir = os.path.dirname(common_path)
            else:
                base_dir = common_path
            
            # Check for new files
            new_files = []
            if os.path.exists(base_dir):
                for root, dirs, files in os.walk(base_dir):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        if filepath not in stored_hashes:
                            new_files.append(filepath)
                            print(f"⊕ NEW: {filepath} (not in hash table)")
            
            new_count = len(new_files)
        else:
            new_count = 0
    else:
        new_count = 0
    
    # Print summary
    print("-" * 60)
    print("\nValidation Summary:")
    print(f"  Valid files:   {valid_count}")
    print(f"  Invalid files: {invalid_count}")
    print(f"  Deleted files: {deleted_count}")
    print(f"  New files:     {new_count}")
    print(f"  Total checked: {len(stored_hashes)}")


def main():
    """
    Main function to handle user input and program flow.
    """
    print("=" * 60)
    print("File Hash Validator")
    print("=" * 60)
    
    while True:
        print("\nOptions:")
        print("1. Generate new hash table")
        print("2. Verify hashes")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1, 2, or 3): ").strip()
        
        if choice == '1':
            directory_path = input("\nEnter directory path: ").strip()
            
            # Remove quotes if user included them
            directory_path = directory_path.strip('"\'')
            
            if not directory_path:
                print("Error: No directory path provided.")
                continue
            
            output_file = input("Enter output filename (default: hash_table.json): ").strip()
            if not output_file:
                output_file = "hash_table.json"
            
            generate_table(directory_path, output_file)
        
        elif choice == '2':
            hash_table_file = input("Enter hash table filename (default: hash_table.json): ").strip()
            if not hash_table_file:
                hash_table_file = "hash_table.json"
            
            validate_hash(hash_table_file)
        
        elif choice == '3':
            print("\nExiting program. Goodbye!")
            break
        
        else:
            print("\nInvalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
