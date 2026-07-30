import sys
import argparse

def solve_gf2(matrix: list[list[int]]) -> list[int]:
    """
    Solves a system of linear equations over GF(2) using Gaussian Elimination.

    Args:
        matrix: An augmented matrix represented as a list of lists of integers (0 or 1).
                For a 128x128 system, the matrix should have 128 rows and 129 columns,
                where the last column represents the constant vector (b).

    Returns:
        A list of integers (0 or 1) representing the solution vector (x).

    Raises:
        ValueError: If the matrix is empty, structurally malformed, or mathematically singular.
    """
    rows = len(matrix)
    if rows == 0:
        raise ValueError("The provided matrix is empty.")
    
    cols = len(matrix[0])
    if cols != rows + 1:
        raise ValueError(f"Invalid matrix dimensions. Expected {rows}x{rows+1}, got {rows}x{cols}.")

    for i in range(rows):
        pivot_row = -1
        for j in range(i, rows):
            if matrix[j][i] == 1:
                pivot_row = j
                break
        
        if pivot_row == -1:
            raise ValueError(f"Singular matrix detected. No pivot found for column {i}. The system has no unique solution.")
        
        matrix[i], matrix[pivot_row] = matrix[pivot_row], matrix[i]
        
        for j in range(i + 1, rows):
            if matrix[j][i] == 1:
                for k in range(i, cols):
                    matrix[j][k] ^= matrix[i][k]
                    
    solution = [0] * rows
    for i in range(rows - 1, -1, -1):
        solution[i] = matrix[i][cols - 1]
        for j in range(i - 1, -1, -1):
            if matrix[j][i] == 1:
                matrix[j][cols - 1] ^= solution[i]
                matrix[j][i] = 0
                
    return solution

def main() -> None:
    """
    Command-line interface for testing the GF(2) solver with a hardcoded matrix.
    """
    parser = argparse.ArgumentParser(description="GF(2) Gaussian Elimination Solver Test")
    parser.parse_args()

    # test_matrix = [
    #     [1, 0, 1, 1],
    #     [0, 1, 1, 0],
    #     [1, 1, 0, 0]
    # ]

    test_matrix = [
        [1, 1, 0, 1],
        [0, 1, 1, 1],
        [1, 1, 1, 0]
    ]

    try:
        print("Attempting to solve the test matrix over GF(2)...")
        result = solve_gf2(test_matrix)
        print(f"Solution vector: {result}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()