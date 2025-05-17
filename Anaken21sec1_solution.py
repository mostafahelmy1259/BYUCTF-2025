import numpy as np

A = np.array([[1, 7, 13, 19, 25, 31],
              [2, 8, 14, 20, 26, 32],
              [3, 9, 15, 21, 27, 33],
              [4, 10, 16, 22, 28, 34],
              [5, 11, 17, 23, 29, 35],
              [6, 12, 18, 24, 30, 36]])
B = np.array([[36, 30, 24, 18, 12, 6],
              [35, 29, 23, 17, 11, 5],
              [34, 28, 22, 16, 10, 4],
              [33, 27, 21, 15, 9, 3],
              [32, 26, 20, 14, 8, 2],
              [31, 25, 19, 13, 7, 1]])
C = np.array([[31, 25, 19, 13, 7, 1],
              [32, 26, 20, 14, 8, 2],
              [33, 27, 21, 15, 9, 3],
              [34, 28, 22, 16, 10, 4],
              [35, 29, 23, 17, 11, 5],
              [36, 30, 24, 18, 12, 6]])
D = np.array([[7, 1, 9, 3, 11, 5],
              [8, 2, 10, 4, 12, 6],
              [19, 13, 21, 15, 23, 17],
              [20, 14, 22, 16, 24, 18],
              [31, 25, 33, 27, 35, 29],
              [32, 26, 34, 28, 36, 30]])
E = np.array([[2, 3, 9, 5, 6, 12],
              [1, 11, 15, 4, 29, 18],
              [7, 13, 14, 10, 16, 17],
              [20, 21, 27, 23, 24, 30],
              [19, 8, 33, 22, 26, 36],
              [25, 31, 32, 28, 34, 35]])
permutes = [A, B, C, D, E]

def permute(blockM, count):
    finalBlockM = np.zeros((6,6))
    for i in range(6):
        for j in range(6):
            index = int(permutes[count][i,j]-1)
            finalBlockM[i,j] = blockM[index//6, index%6]
    return finalBlockM

def permute_inverse(blockM, count):
    finalBlockM = np.zeros((6,6))
    # invert permutation
    for i in range(6):
        for j in range(6):
            index = int(permutes[count][i,j]-1)
            finalBlockM[index//6, index%6] = blockM[i,j]
    return finalBlockM

def add(blockM, count):
    if count == 0:
        for i in range(6):
            for j in range(6):
                if (i+j)%2 == 0:
                    blockM[i,j] +=1
    elif count == 1:
        blockM[3:,3:] = blockM[3:,3:] + blockM[:3,:3]
    elif count == 2:
        blockM[:3,:3] = blockM[3:,3:] + blockM[:3,:3]
    elif count == 3:
        blockM[3:,:3] = blockM[3:,:3] + blockM[:3,3:]
    else:
        blockM[:3,3:] = blockM[3:,:3] + blockM[:3,3:]
    return np.mod(blockM, 3)

def add_inverse(blockM, count):
    if count == 0:
        for i in range(6):
            for j in range(6):
                if (i+j)%2 == 0:
                    blockM[i,j] = (blockM[i,j] - 1) % 3
    elif count == 1:
        blockM[3:,3:] = (blockM[3:,3:] - blockM[:3,:3]) % 3
    elif count == 2:
        blockM[:3,:3] = (blockM[:3,:3] - blockM[3:,3:]) % 3
    elif count == 3:
        blockM[3:,:3] = (blockM[3:,:3] - blockM[:3,3:]) % 3
    else:
        blockM[:3,3:] = (blockM[:3,3:] - blockM[3:,:3]) % 3
    return blockM

def inverse_rearrange(ciphertext, keyNums):
    reducedKeyNums = []
    [reducedKeyNums.append(x) for x in keyNums if x not in reducedKeyNums]

    n = len(reducedKeyNums)
    letterBoxes = [[] for _ in range(n)]
    lengths = [0]*n

    # Calculate how many letters in each box
    for i in range(len(ciphertext)):
        lengths[i % n] += 1

    # Split ciphertext according to sorted keyNums
    sortedKeyNums = sorted(reducedKeyNums)
    pos = 0
    boxes_in_order = []
    for k in sortedKeyNums:
        idx = reducedKeyNums.index(k)
        length = lengths[idx]
        boxes_in_order.append(ciphertext[pos:pos+length])
        pos += length

    # Put boxes back to original order
    for i, k in enumerate(sortedKeyNums):
        idx = reducedKeyNums.index(k)
        letterBoxes[idx] = list(boxes_in_order[i])

    # Rebuild original text by reading in round robin order
    plaintext = []
    for i in range(len(ciphertext)):
        box_idx = i % n
        plaintext.append(letterBoxes[box_idx].pop(0))
    return "".join(plaintext)

def decrypt_block(block, keyNums):
    blockM = np.zeros((6,6))
    # Rebuild the block matrix from 12*6 letters
    # The encrypted block has 12*6=72 letters? No, encryption produces 12 letters per block (6 top + 6 bottom rows)
    # Actually, encrypt outputs 12 letters per block

    # The encrypted letters are split into two halves of 6 letters each for rows:
    # So block is 12 letters for one block

    # Convert letters back to matrix representation
    # From encryption code:
    # for i in range(6):
    #     resultLetterNum = int(9*blockM[i,0]+3*blockM[i,1]+blockM[i,2])
    # for i in range(6):
    #     resultLetterNum = int(9*blockM[i,3]+3*blockM[i,4]+blockM[i,5])

    # So reverse this:

    for i in range(6):
        c = block[i]
        if c == '0':
            num = 0
        else:
            num = ord(c) - 96
        blockM[i,0] = num // 9
        blockM[i,1] = (num % 9) // 3
        blockM[i,2] = num % 3

    for i in range(6):
        c = block[i+6]
        if c == '0':
            num = 0
        else:
            num = ord(c) - 96
        blockM[i,3] = num // 9
        blockM[i,4] = (num % 9) // 3
        blockM[i,5] = num % 3

    # Inverse the permutations and additions in reverse order
    for keyNum in reversed(keyNums):
        blockM = add_inverse(blockM, keyNum % 5)
        blockM = permute_inverse(blockM, (keyNum // 5) % 5)

    # Now convert matrix back to letters
    plaintext = ""
    for col in range(6):
        letterNum = int(9*blockM[0,col] + 3*blockM[1,col] + blockM[2,col])
        if letterNum == 0:
            plaintext += "x"  # padding letter
        else:
            plaintext += chr(letterNum + 96)
    for col in range(6):
        letterNum = int(9*blockM[3,col] + 3*blockM[4,col] + blockM[5,col])
        if letterNum == 0:
            plaintext += "x"
        else:
            plaintext += chr(letterNum + 96)

    return plaintext

def decrypt(ciphertext, key):
    keyNums = [ord(c) - 97 for c in key]

    # Undo final rearrangement
    rearrangedText = inverse_rearrange(ciphertext, keyNums)

    # Split into 12 letter blocks
    blocks = [rearrangedText[i:i+12] for i in range(0, len(rearrangedText), 12)]

    plaintext = ""
    for block in blocks:
        plaintext += decrypt_block(block, keyNums)
    return plaintext

if __name__ == "__main__":
    ciphertext = "cnpiaytjyzggnnnktjzcvuzjexxkvnrlfzectovhfswyphjt"
    key = "orygwktcjpb"

    plaintext = decrypt(ciphertext, key)
    print("Decrypted plaintext:")
    print(plaintext)
