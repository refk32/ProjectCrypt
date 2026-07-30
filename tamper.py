import argparse
import sys
import os

def corrupt_file(filepath: str) -> None:
    """
    Intentionally corrupts the last byte of a binary file to invalidate its cryptographic authentication tag.

    Args:
        filepath: The exact path to the encrypted binary file that will be tampered with.

    Outputs:
        Prints a success message to standard output if the file is successfully modified.
        Prints an error message to standard error and exits with status 1 if the file is missing, empty, or unreadable.
    """
    if not os.path.exists(filepath):
        print(f"Error: The file '{filepath}' was not found.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(filepath, "rb") as f: # rb -> read binary
            data = bytearray(f.read()) # bytearray() return mutable list of bytes allowing us to edit it 
        
        if len(data) == 0:
            print("Error: The file is empty.", file=sys.stderr)
            sys.exit(1)

        # data[-1] -> target the last byte.
        # ^ 1 -> bitwise XOR operation
        data[-1] = data[-1] ^ 1 
        
        with open(filepath, "wb") as f: # wb -> write binary
            f.write(data) 
            
        print(f"Success: '{filepath}' has been maliciously modified!")
        
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}", file=sys.stderr)
        sys.exit(1)

def main() -> None:
    """
    Command-line interface for the file tampering tool.
    
    Parses the '-f' or '--file' argument from the terminal and passes it to the corruption function.
    """
    parser = argparse.ArgumentParser(description="Intentionally corrupt an encrypted file's authentication tag.")
    parser.add_argument("-f", "--file", required=True, help="Path to the encrypted file to tamper with")
    
    args = parser.parse_args()
    corrupt_file(args.file)

if __name__ == "__main__":
    main()