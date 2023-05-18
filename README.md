# DLL Hollowing
This project is a Rust Workspace project consisting of two parts: "encrypt_shellcode" and "injector". The Injector, implemented in Rust, writes the shellcode to the "AddressOfEntryPoint" of a target DLL file that is already running within a target process. This allows the malicious shellcode to execute, and it loads the malicious DLL file into a different .exe using the "LoadLibrary" function. To conceal our shellcode from antivirus software, we encrypt it before embedding it into the application. The encryption process is handled by the "encrypt_shellcode" component. It encrypts the embedded shellcode and prepares it for use in the injector project, also saving it to a .bin file.


## Usage
1. Clone or download the project from the GitHub repository: link to the repository

2. Install the Rust programming language and its dependencies if not already installed.

3. Replace the BUF variable embedded in the project named "encrypt shellcode" with the shellcode you want.

4. Run the "encrypt_shellcode" project by executing the following command in the project directory:
```$ cargo run --release --bin encrypt_shellcode -- shellcode.bin```

5. Once the encryption process is complete, the encrypted shellcode will be printed and saved as a .bin file in the project directory.

5. Then we will change the shellcode in the BUF variable in the project named "injector".

6. Run the "Injector" project and enter the path of a .dll file running in the target process to inject the encrypted shellcode into the target process.
```$ cargo run --release --bin injector -- C:\Windows\System32\amsi.dll```

Note: If you want to change the target process, change the variable TARGET_PROCESS_NAME inside the "Injector" project.

7. The "injector" project will decrypt the encrypted shellcode and execute the malicious code by writing the actual shellcode to the "AddressOfEntryPoint" specified in the target DLL.

8. This malicious shell code will also load a malicious .dll into a different process with a "LoadLibrary".


## Disclaimer
This injector is for educational purposes only. Please do not use it for any malicious activities. The author is not responsible for any damages or legal issues caused by the misuse of this code.


## License
This code is licensed under the MIT License. Please see the [LICENSE](https://github.com/kuzeyardabulut/rust-dll-hollowing/blob/main/LICENSE) file for more details.


## Contributions
Contributions are welcome! If you find any bugs or have any suggestions for improvement, please create a pull request.

