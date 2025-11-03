#include <iostream>
#include <string>
#include <filesystem>
#include <chrono>

#ifdef _WIN32
    #include <conio.h>
#else
    #include <termios.h>
    #include <unistd.h>
#endif

namespace fs = std::filesystem;

// Forward declaration 
class CryptographyEngine;

// ============================================================================
// SECURE PASSWORD INPUT (Platform-specific)
// ============================================================================

std::string getPassword(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();
    std::string password;

#ifdef _WIN32
    // Windows: Use _getch() to hide password input
    while (true) {
        int ch = _getch();
        
        // Enter key pressed
        if (ch == '\r' || ch == '\n') {
            break;
        }
        // Backspace pressed
        if (ch == '\b') {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";  // Erase the asterisk
                std::cout.flush();
            }
        }
        // Regular character (skip special keys like arrows)
        else if (ch != 0 && ch != 224) {
            password += ch;
            std::cout << '*';  // Display asterisk instead of character
            std::cout.flush();
        }
    }
#else
    // Linux/macOS: Use termios to disable echo
    struct termios old_settings, new_settings;
    tcgetattr(STDIN_FILENO, &old_settings);
    new_settings = old_settings;
    new_settings.c_lflag &= ~ECHO;  // Disable echo
    
    tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);  // Restore settings
#endif
    
    std::cout << std::endl;
    return password;
}

// ============================================================================
// ARGUMENT PARSER
// ============================================================================

void printUsage(const char* programName) {
    std::cout << "\n========== CipherGuard - File Encryption Tool ==========" << std::endl;
    std::cout << "\nUsage: " << programName << " <command> [options]\n" << std::endl;
    std::cout << "Commands:\n" << std::endl;
    std::cout << "  encrypt <input> <output>    Encrypt a file (AES-256-GCM)" << std::endl;
    std::cout << "  decrypt <input> <output>    Decrypt a file" << std::endl;
    std::cout << "  test                        Run encryption/decryption tests\n" << std::endl;
    std::cout << "Examples:\n" << std::endl;
    std::cout << "  " << programName << " encrypt document.txt document.txt.enc" << std::endl;
    std::cout << "  " << programName << " decrypt document.txt.enc document.txt" << std::endl;
    std::cout << "  " << programName << " test\n" << std::endl;
    std::cout << "========================================================\n" << std::endl;
}

// ============================================================================
// ENCRYPTION COMMAND
// ============================================================================

bool encryptCommand(const std::string& inputFile, const std::string& outputFile) {
    // Check if input file exists
    if (!fs::exists(inputFile)) {
        std::cerr << "Error: Input file not found: " << inputFile << std::endl;
        return false;
    }

    // Get password from user
    std::string password = getPassword("Enter encryption password: ");
    std::string confirm = getPassword("Confirm password: ");

    // Validate passwords match
    if (password != confirm) {
        std::cerr << "Error: Passwords do not match" << std::endl;
        return false;
    }

    // Validate password strength
    if (password.length() < 8) {
        std::cerr << "Error: Password must be at least 8 characters long" << std::endl;
        return false;
    }

    // Encrypt the file
    std::cout << "\n[*] Encrypting file..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();

    if (!CryptographyEngine::encryptFile(inputFile, outputFile, password)) {
        std::cerr << "Encryption failed" << std::endl;
        return false;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Get file sizes
    uintmax_t originalSize = fs::file_size(inputFile);
    uintmax_t encryptedSize = fs::file_size(outputFile);

    // Display success message
    std::cout << "\n[+] Encryption successful!" << std::endl;
    std::cout << "    Input file: " << inputFile << " (" << originalSize << " bytes)" << std::endl;
    std::cout << "    Output file: " << outputFile << " (" << encryptedSize << " bytes)" << std::endl;
    std::cout << "    Encryption time: " << duration.count() << " ms" << std::endl;
    std::cout << "    Overhead: " << (encryptedSize - originalSize) << " bytes (salt, IV, tag)" << std::endl;
    std::cout << std::endl;

    return true;
}

// ============================================================================
// DECRYPTION COMMAND
// ============================================================================

bool decryptCommand(const std::string& inputFile, const std::string& outputFile) {
    // Check if encrypted file exists
    if (!fs::exists(inputFile)) {
        std::cerr << "Error: Encrypted file not found: " << inputFile << std::endl;
        return false;
    }

    // Get password from user
    std::string password = getPassword("Enter decryption password: ");

    // Decrypt the file
    std::cout << "\n[*] Decrypting file..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();

    if (!CryptographyEngine::decryptFile(inputFile, outputFile, password)) {
        std::cerr << "Decryption failed" << std::endl;
        return false;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Get file sizes
    uintmax_t encryptedSize = fs::file_size(inputFile);
    uintmax_t decryptedSize = fs::file_size(outputFile);

    // Display success message
    std::cout << "\n[+] Decryption successful!" << std::endl;
    std::cout << "    Input file: " << inputFile << " (" << encryptedSize << " bytes)" << std::endl;
    std::cout << "    Output file: " << outputFile << " (" << decryptedSize << " bytes)" << std::endl;
    std::cout << "    Decryption time: " << duration.count() << " ms" << std::endl;
    std::cout << std::endl;

    return true;
}

// ============================================================================
// TEST COMMAND
// ============================================================================

bool testCommand() {
    std::cout << "\n========== CipherGuard Test Suite ==========" << std::endl;

    const std::string testPassword = "TestPassword123!";

    // Test 1: Text file encryption/decryption
    std::cout << "\n[Test 1] Text File Encryption/Decryption" << std::endl;
    std::string testContent = "This is a secret message! !@#$%^&*()";

    // Create test file
    std::ofstream testFile("test_text.txt");
    testFile << testContent;
    testFile.close();
    std::cout << "  [*] Created test file (text)" << std::endl;

    // Encrypt
    if (!CryptographyEngine::encryptFile("test_text.txt", "test_text.txt.enc", testPassword)) {
        std::cerr << "  [!] Encryption failed" << std::endl;
        return false;
    }
    std::cout << "  [+] Encryption successful" << std::endl;

    // Decrypt
    if (!CryptographyEngine::decryptFile("test_text.txt.enc", "test_text.txt.dec", testPassword)) {
        std::cerr << "  [!] Decryption failed" << std::endl;
        return false;
    }
    std::cout << "  [+] Decryption successful" << std::endl;

    // Verify integrity
    std::ifstream original("test_text.txt"), decrypted("test_text.txt.dec");
    std::string origContent((std::istreambuf_iterator<char>(original)), std::istreambuf_iterator<char>());
    std::string decContent((std::istreambuf_iterator<char>(decrypted)), std::istreambuf_iterator<char>());

    if (origContent == decContent) {
        std::cout << "  [+] Content verification PASSED" << std::endl;
    } else {
        std::cerr << "  [!] Content mismatch - FAILED" << std::endl;
        return false;
    }

    // Test 2: Binary file encryption/decryption
    std::cout << "\n[Test 2] Binary File Encryption/Decryption" << std::endl;
    unsigned char binaryData[] = {0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC};

    std::ofstream binaryFile("test_binary.bin", std::ios::binary);
    binaryFile.write((char*)binaryData, sizeof(binaryData));
    binaryFile.close();
    std::cout << "  [*] Created test file (binary)" << std::endl;

    if (!CryptographyEngine::encryptFile("test_binary.bin", "test_binary.bin.enc", testPassword)) {
        std::cerr << "  [!] Encryption failed" << std::endl;
        return false;
    }
    std::cout << "  [+] Encryption successful" << std::endl;

    if (!CryptographyEngine::decryptFile("test_binary.bin.enc", "test_binary.bin.dec", testPassword)) {
        std::cerr << "  [!] Decryption failed" << std::endl;
        return false;
    }
    std::cout << "  [+] Decryption successful" << std::endl;

    // Test 3: Wrong password detection
    std::cout << "\n[Test 3] Wrong Password Detection" << std::endl;
    if (CryptographyEngine::decryptFile("test_text.txt.enc", "wrong_output.txt", "WrongPassword123")) {
        std::cerr << "  [!] Should have rejected wrong password" << std::endl;
        return false;
    }
    std::cout << "  [+] Correctly rejected wrong password" << std::endl;

    // Cleanup test files
    fs::remove("test_text.txt");
    fs::remove("test_text.txt.enc");
    fs::remove("test_text.txt.dec");
    fs::remove("test_binary.bin");
    fs::remove("test_binary.bin.enc");
    fs::remove("test_binary.bin.dec");

    std::cout << "\n========== All Tests PASSED ==========" << std::endl;
    std::cout << "[+] CipherGuard is working correctly!\n" << std::endl;

    return true;
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

int main(int argc, char* argv[]) {
    // Parse command-line arguments
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    // Test command
    if (command == "test") {
        bool success = testCommand();
        return success ? 0 : 1;
    }

    // Encrypt command
    if (command == "encrypt") {
        if (argc != 4) {
            std::cerr << "Usage: " << argv[0] << " encrypt <input_file> <output_file>" << std::endl;
            return 1;
        }
        bool success = encryptCommand(argv[2], argv[3]);
        return success ? 0 : 1;
    }

    // Decrypt command
    if (command == "decrypt") {
        if (argc != 4) {
            std::cerr << "Usage: " << argv[0] << " decrypt <input_file> <output_file>" << std::endl;
            return 1;
        }
        bool success = decryptCommand(argv[2], argv[3]);
        return success ? 0 : 1;
    }

    // Unknown command
    std::cerr << "Error: Unknown command '" << command << "'" << std::endl;
    printUsage(argv[0]);
    return 1;
}
