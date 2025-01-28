# chaincrypt
A two-file dependent encryption mechanism

**chaincrypt** implements a secure encryption mechanism where two files are encrypted in a way that they are mutually dependent for decryption. Each encrypted file contains part of the key required to decrypt the other, ensuring that both files must be present to access the original data.

**How It Works**:

1. A master key is randomly generated and split into two parts: key1 and key2.

2. File 1 is encrypted using key1, and File 2 is encrypted using key2.

3. Each encrypted file contains:

- An IV (Initialization Vector)

- The counterpart decryption key (key2 in File 1 and key1 in File 2)

- The encrypted content

4. During decryption, both files are required to retrieve the necessary keys and reconstruct the original data.
