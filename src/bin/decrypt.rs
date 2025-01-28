use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

// Type alias for AES-128-CBC mode with PKCS7 padding
// This simplifies the creation of cipher instances by specifying the block cipher (Aes128) and padding scheme (Pkcs7)
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

// Constants used in the encryption and decryption process
const IV_SIZE: usize = 16;    // Size of the Initialization Vector (IV) in bytes (128 bits)
const PART_SIZE: usize = 16;  // Size of each key segment in bytes (16 bytes)

// The main function where the program execution begins
// It returns an io::Result<()> to handle any input/output errors that may occur
fn main() -> io::Result<()> {
    // Prompt the user to enter the path of the first encrypted file
    println!("Enter the path of the first encrypted file:");
    let mut enc_path1 = String::new(); // Create a mutable String to store the user's input
    io::stdin().read_line(&mut enc_path1)?; // Read a line from standard input and store it in enc_path1
    let enc_path1 = enc_path1.trim(); // Remove any leading and trailing whitespace from the input

    // Prompt the user to enter the path of the second encrypted file
    println!("Enter the path of the second encrypted file:");
    let mut enc_path2 = String::new(); // Create another mutable String for the second file path
    io::stdin().read_line(&mut enc_path2)?; // Read the second file path from standard input
    let enc_path2 = enc_path2.trim(); // Trim whitespace from the second file path

    // Open and read the first encrypted file
    let mut file1 = fs::File::open(enc_path1)?; // Attempt to open the first encrypted file; return an error if it fails
    let mut iv1 = [0u8; IV_SIZE]; // Initialize a byte array to store the Initialization Vector (IV) for the first file
    file1.read_exact(&mut iv1)?; // Read exactly IV_SIZE bytes from the file and store them in iv1

    let mut key2 = [0u8; PART_SIZE]; // Initialize a byte array to store the second part of the key from the first file
    file1.read_exact(&mut key2)?; // Read exactly PART_SIZE bytes and store them in key2

    let mut encrypted_data1 = Vec::new(); // Create a mutable vector to hold the remaining encrypted data from the first file
    file1.read_to_end(&mut encrypted_data1)?; // Read the rest of the file and append it to encrypted_data1

    // Open and read the second encrypted file
    let mut file2 = fs::File::open(enc_path2)?; // Attempt to open the second encrypted file
    let mut iv2 = [0u8; IV_SIZE]; // Initialize a byte array for the IV of the second file
    file2.read_exact(&mut iv2)?; // Read IV_SIZE bytes for iv2

    let mut key1 = [0u8; PART_SIZE]; // Initialize a byte array to store the first part of the key from the second file
    file2.read_exact(&mut key1)?; // Read PART_SIZE bytes and store them in key1

    let mut encrypted_data2 = Vec::new(); // Create a mutable vector for the encrypted data from the second file
    file2.read_to_end(&mut encrypted_data2)?; // Read the remaining data and store it in encrypted_data2

    // Create cipher instances for decryption using the extracted keys and IVs
    // cipher1 uses key1 and iv1 to decrypt encrypted_data1
    // cipher2 uses key2 and iv2 to decrypt encrypted_data2
    let cipher1 = Aes128Cbc::new_from_slices(&key1, &iv1)
        .expect("Decryption error: InvalidKeyIvLength (cipher1)"); // Handle errors if key or IV lengths are incorrect

    let cipher2 = Aes128Cbc::new_from_slices(&key2, &iv2)
        .expect("Decryption error: InvalidKeyIvLength (cipher2)"); // Handle errors for the second cipher

    // Decrypt the data from the first encrypted file
    let decrypted_data1 = cipher1.decrypt_vec(&encrypted_data1)
        .expect("Decryption failed (decrypted_data1)"); // Attempt to decrypt and handle potential errors

    // Decrypt the data from the second encrypted file
    let decrypted_data2 = cipher2.decrypt_vec(&encrypted_data2)
        .expect("Decryption failed (decrypted_data2)"); // Attempt to decrypt and handle potential errors

    // Determine the original file paths by changing the file extensions to indicate decryption
    let original_path1 = Path::new(enc_path1).with_extension("dec1.txt"); // Change the extension of the first file
    let original_path2 = Path::new(enc_path2).with_extension("dec2.txt"); // Change the extension of the second file

    // Write the decrypted data to the new files with the updated paths
    fs::write(&original_path1, decrypted_data1)?; // Save the decrypted data of the first file
    fs::write(&original_path2, decrypted_data2)?; // Save the decrypted data of the second file

    // Inform the user that the decryption process was successful and display the paths of the decrypted files
    println!("Files have been successfully decrypted:");
    println!("1. Decrypted file: {:?}", original_path1); // Display the path of the first decrypted file
    println!("2. Decrypted file: {:?}", original_path2); // Display the path of the second decrypted file

    Ok(()) // Return Ok to indicate that the program completed successfully
}
