use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use rand::Rng;

// Type alias for AES-128-CBC mode with PKCS7 padding
// This simplifies the creation of cipher instances by specifying the block cipher (Aes128) and padding scheme (Pkcs7)
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

// Constants used in the encryption process
const KEY_SIZE: usize = 32; // 256-bit master key (composed of two 128-bit keys)
const IV_SIZE: usize = 16;  // 128-bit Initialization Vector (IV)
const PART_SIZE: usize = 16; // Each key segment is 16 bytes

// The main function where the program execution begins
// It returns an io::Result<()> to handle any input/output errors that may occur
fn main() -> io::Result<()> {
    // Prompt the user to enter the path of the first file to encrypt
    println!("Enter the path of the first file:");
    let mut file_path1 = String::new(); // Create a mutable String to store the user's input
    io::stdin().read_line(&mut file_path1)?; // Read a line from standard input and store it in file_path1
    let file_path1 = file_path1.trim(); // Remove any leading and trailing whitespace from the input

    // Prompt the user to enter the path of the second file to encrypt
    println!("Enter the path of the second file:");
    let mut file_path2 = String::new(); // Create another mutable String for the second file path
    io::stdin().read_line(&mut file_path2)?; // Read the second file path from standard input
    let file_path2 = file_path2.trim(); // Trim whitespace from the second file path

    // Generate a random master key (32 bytes) using a cryptographically secure random number generator
    let master_key: [u8; KEY_SIZE] = rand::thread_rng().gen();

    // Split the master key into two 16-byte segments
    let key1 = &master_key[..PART_SIZE]; // First 16 bytes for the first encryption
    let key2 = &master_key[PART_SIZE..]; // Last 16 bytes for the second encryption

    // Print the lengths of the key segments to verify their sizes
    println!("Key1 length: {}", key1.len()); // Should print 16
    println!("Key2 length: {}", key2.len()); // Should print 16

    // Read the contents of the first file to be encrypted
    let data1 = fs::read(file_path1)?; // Read the entire file into a byte vector
    // Read the contents of the second file to be encrypted
    let data2 = fs::read(file_path2)?; // Read the entire file into a byte vector

    // Generate random Initialization Vectors (IVs) for each file
    let iv1 = rand::thread_rng().gen::<[u8; IV_SIZE]>(); // Generate a random 16-byte IV for the first file
    let iv2 = rand::thread_rng().gen::<[u8; IV_SIZE]>(); // Generate a random 16-byte IV for the second file

    // Print the lengths of the IVs to verify their sizes
    println!("IV1 length: {}", iv1.len()); // Should print 16
    println!("IV2 length: {}", iv2.len()); // Should print 16

    // Create cipher instances for encryption using the generated keys and IVs
    // cipher1 uses key1 and iv1 to encrypt data1
    // cipher2 uses key2 and iv2 to encrypt data2
    let cipher1 = Aes128Cbc::new_from_slices(key1, &iv1)
        .expect("Encryption error: InvalidKeyIvLength (cipher1)"); // Handle errors if key or IV lengths are incorrect

    let cipher2 = Aes128Cbc::new_from_slices(key2, &iv2)
        .expect("Encryption error: InvalidKeyIvLength (cipher2)"); // Handle errors for the second cipher

    // Encrypt the data from the first file
    let encrypted_data1 = cipher1.encrypt_vec(&data1); // Encrypt data1 and store the ciphertext in encrypted_data1
    // Encrypt the data from the second file
    let encrypted_data2 = cipher2.encrypt_vec(&data2); // Encrypt data2 and store the ciphertext in encrypted_data2

    // Determine the output paths for the encrypted files by changing their extensions
    let output_path1 = Path::new(file_path1).with_extension("enc1"); // Change the extension of the first file to .enc1
    let mut file1 = fs::File::create(&output_path1)?; // Create or overwrite the first encrypted file
    file1.write_all(&iv1)?; // Write the IV to the beginning of the encrypted file
    file1.write_all(key2)?;  // Write key2 to the file; this key is needed to decrypt the first file
    file1.write_all(&encrypted_data1)?; // Write the encrypted data to the file

    let output_path2 = Path::new(file_path2).with_extension("enc2"); // Change the extension of the second file to .enc2
    let mut file2 = fs::File::create(&output_path2)?; // Create or overwrite the second encrypted file
    file2.write_all(&iv2)?; // Write the IV to the beginning of the encrypted file
    file2.write_all(key1)?;  // Write key1 to the file; this key is needed to decrypt the second file
    file2.write_all(&encrypted_data2)?; // Write the encrypted data to the file

    // Inform the user that the encryption process was successful and display the paths of the encrypted files
    println!("Files have been successfully encrypted:");
    println!("1. Encrypted file: {:?}", output_path1); // Display the path of the first encrypted file
    println!("2. Encrypted file: {:?}", output_path2); // Display the path of the second encrypted file

    Ok(()) // Return Ok to indicate that the program completed successfully
}
