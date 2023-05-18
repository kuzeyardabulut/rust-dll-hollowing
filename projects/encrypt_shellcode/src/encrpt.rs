use anyhow::{anyhow, Ok};

use chacha20poly1305::{
    aead::stream,
    XChaCha20Poly1305,
    KeyInit,
};
pub trait FileEncryptor {
    fn encrypt_data(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error>;
}

pub struct XChaCha20Poly1305Encryptor<'a> {
    pub key: &'a [u8; 32],
    pub nonce: &'a [u8; 19],
}

impl<'a> FileEncryptor for XChaCha20Poly1305Encryptor<'a> {
    fn encrypt_data(&self, data: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
         // Initialize an AEAD encryption scheme with the provided key
         let aead = XChaCha20Poly1305::new(self.key.as_ref().into());

         // Initialize a stream encryptor with the provided nonce
         let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, self.nonce.as_ref().into());
 
         // Set the buffer length
         const BUFFER_LEN: usize = 500;
 
         // Initialize an empty vector to hold the encrypted data
         let mut encrypted_data: Vec<u8> = Vec::new();
 
         // Loop through the data, encrypting each buffer of data
         let mut offset = 0;
         loop {
             let read_count = (data.len() - offset).min(BUFFER_LEN);
 
             if read_count == BUFFER_LEN {
                 let buffer_slice = &data[offset..offset + BUFFER_LEN];
 
                 // Encrypt the buffer and add it to the encrypted data vector
                 let ciphertext = stream_encryptor
                     .encrypt_next(buffer_slice)
                     .map_err(|err| anyhow!("Encrypting large file: {}", err))?;


                 encrypted_data.extend_from_slice(&ciphertext);
                 offset += BUFFER_LEN;
             } else {
                
                 // If the buffer length is less than the expected length, encrypt the remaining data
                 if read_count > 0 {
                     let buffer_slice = &data[offset..];
                     
                     // Encrypt the remaining data and add it to the encrypted data vector
                     let ciphertext = stream_encryptor
                         .encrypt_last(buffer_slice)
                         .map_err(|err| anyhow!("Encrypting large file: {}", err))?;

                         encrypted_data.extend_from_slice(&ciphertext);
                        }
                 break;
             }
         }
         Ok(encrypted_data)
     }   
}