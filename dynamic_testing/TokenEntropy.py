#!\/bin/python
import numpy as np

k1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGxhZG1pbiIsImlhdCI6MTU5MTQ0NTYxOSwiZXhwIjoxNTkxNDQ5MjE5fQ.g5xxQleLgZzDfiUwus4RM38gL_ggcY5-GwLxDibnFy0"
k2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGxhZG1pbiIsImlhdCI6MTU5MTQ0NTYzMCwiZXhwIjoxNTkxNDQ5MjMwfQ.qr5bJTW41f99xwK3ItFDIzrj8pV7v9cJ7heWyhXxzKI"
k3 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGxhZG1pbiIsImlhdCI6MTU5MTQ0NTYzOCwiZXhwIjoxNTkxNDQ5MjM4fQ.SRTQMB45OuS3IhPAoP1YNhDaXM_HTDUDZKFKnjRSa6k"
k4 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGxhZG1pbiIsImlhdCI6MTU5MTQ0NTY0NiwiZXhwIjoxNTkxNDQ5MjQ2fQ.-OIL1T5T-GRUiMxX9FtfoRGa5H1wHFrCmmQRAhxCnZ0"
k5 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGxhZG1pbiIsImlhdCI6MTU5MTQ0NTY1MiwiZXhwIjoxNTkxNDQ5MjUyfQ.z80eR5uCVK6PoJarHtyFCGWFXFa0EI1ROks9F7T8l6g"

def levenshtein(seq1, seq2):
    size_x = len(seq1) + 1
    size_y = len(seq2) + 1
    matrix = np.zeros ((size_x, size_y))
    for x in range(size_x):
        matrix [x, 0] = x
    for y in range(size_y):
        matrix [0, y] = y

    for x in range(1, size_x):
        for y in range(1, size_y):
            if seq1[x-1] == seq2[y-1]:
                matrix [x,y] = min(
                    matrix[x-1, y] + 1,
                    matrix[x-1, y-1],
                    matrix[x, y-1] + 1
                )
            else:
                matrix [x,y] = min(
                    matrix[x-1,y] + 1,
                    matrix[x-1,y-1] + 1,
                    matrix[x,y-1] + 1
                )
    return (matrix[size_x - 1, size_y - 1])

print(str(levenshtein(k1, k2)))
print(str(levenshtein(k2, k3)))
print(str(levenshtein(k3, k4)))
print(str(levenshtein(k4, k5)))
