#include "crypto.h"
#include <fstream>
#include <iostream> // For error reporting
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// Define constants for GCM parameters
constexpr int GCM_IV_SIZE = 12;  // Recommended IV size for GCM
constexpr int GCM_TAG_SIZE = 16; // Authentication tag size

// Helper function to print OpenSSL errors for debugging
void handle_openssl_errors() {
    unsigned long err_code;
    while ((err_code = ERR_get_error())) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        std::cerr << "OpenSSL Error: " << err_buf << std::endl;
    }
}

// Helper function to read a whole file into a byte vector.
byte_vec read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return {};
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    byte_vec buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return buffer;
    }
    return {};
}

// Helper function to write a byte vector to a file.
bool write_file(const std::string& path, const byte_vec& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

namespace {
    // RAII wrapper for OpenSSL initialization
    struct OpenSSLInit {
        OpenSSLInit() {
            OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | 
                              OPENSSL_INIT_ADD_ALL_CIPHERS |
                              OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
        }
        ~OpenSSLInit() {
            OPENSSL_cleanup();
        }
    };
    static OpenSSLInit openssl_init;

    // Secure memory zeroing
    void secure_zero(void* ptr, size_t size) {
        OPENSSL_cleanse(ptr, size);
    }
}

bool crypto::derive_key_from_password(const std::string& password, const byte_vec& salt, byte_vec& key) {
    key.resize(KEY_SIZE);
    int result = PKCS5_PBKDF2_HMAC(
        password.c_str(),
        password.length(),
        salt.data(),
        salt.size(),
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        KEY_SIZE,
        key.data()
    );
    if (result != 1) {
        secure_zero(key.data(), key.size());
        handle_openssl_errors();
        return false;
    }
    return true;
}

bool crypto::encrypt_file(const std::string& input_path, const std::string& output_path, const std::string& password) {
    if (input_path.empty() || output_path.empty()) {
        std::cerr << "Error: Invalid file paths." << std::endl;
        return false;
    }

    byte_vec plaintext = read_file(input_path);
    if (plaintext.empty() && !std::ifstream(input_path).is_open()) {
        std::cerr << "Error: Could not read input file." << std::endl;
        return false;
    }

    byte_vec salt(SALT_SIZE);
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        handle_openssl_errors();
        return false;
    }

    byte_vec key;
    if (!derive_key_from_password(password, salt, key)) {
        secure_zero(salt.data(), salt.size());
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_openssl_errors();
        return false;
    }

    byte_vec iv(GCM_IV_SIZE);
    // Cleanup and error handling for RAND_bytes failure
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        handle_openssl_errors();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 1. Initialize encryption operation.
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_errors();
        return false;
    }
    // 2. Set IV length.
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_errors();
        return false;
    }
    // 3. Provide key and IV.
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_errors();
        return false;
    }

    // Initialize ciphertext with extra space for padding
    byte_vec ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    // 4. Encrypt plaintext.
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_errors();
        return false;
    }
    int ciphertext_len = len;

    // 5. Finalize encryption.
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_errors();
        return false;
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    byte_vec tag(GCM_TAG_SIZE);
    // 6. Get the authentication tag.
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_errors();
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    // 7. Assemble the output file: [salt][iv][tag][ciphertext]
    byte_vec output_data;
    output_data.reserve(salt.size() + iv.size() + tag.size() + ciphertext.size());
    output_data.insert(output_data.end(), salt.begin(), salt.end());
    output_data.insert(output_data.end(), iv.begin(), iv.end());
    output_data.insert(output_data.end(), tag.begin(), tag.end());
    output_data.insert(output_data.end(), ciphertext.begin(), ciphertext.end());
    
    // After encryption is complete
    secure_zero(key.data(), key.size());
    secure_zero(salt.data(), salt.size());
    
    return write_file(output_path, output_data);
}

bool crypto::decrypt_file(const std::string& input_path, const std::string& output_path, const std::string& password) {
    if (input_path.empty() || output_path.empty()) {
        std::cerr << "Error: Invalid file paths." << std::endl;
        return false;
    }

    byte_vec encrypted_data = read_file(input_path);
    if (encrypted_data.empty()) {
        std::cerr << "Error: Could not read encrypted file." << std::endl;
        return false;
    }

    if (encrypted_data.size() < (SALT_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE)) {
        std::cerr << "Error: File is corrupted or not properly encrypted." << std::endl;
        return false;
    }

    // 1. Deconstruct the file: [salt][iv][tag][ciphertext]
    auto current = encrypted_data.begin();
    byte_vec salt(current, current + SALT_SIZE);
    current += SALT_SIZE;
    byte_vec iv(current, current + GCM_IV_SIZE);
    current += GCM_IV_SIZE;
    byte_vec tag(current, current + GCM_TAG_SIZE);
    current += GCM_TAG_SIZE;
    byte_vec ciphertext(current, encrypted_data.end());

    byte_vec key;
    if (!derive_key_from_password(password, salt, key)) {
        secure_zero(salt.data(), salt.size());
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_openssl_errors();
        return false;
    }

    // 2. Initialize decryption.
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_errors();
        return false;
    }
    // 3. Set IV length.
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_errors();
        return false;
    }
    // 4. Provide key and IV.
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_errors();
        return false;
    }

    byte_vec plaintext(ciphertext.size());
    int len = 0;
    // 5. Decrypt ciphertext.
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_errors();
        return false;
    }
    int plaintext_len = len;

    // 6. Set the expected authentication tag. THIS MUST BE DONE BEFORE FINALIZING.
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_errors();
        return false;
    }

    // 7. Finalize decryption. This is the step that performs the authentication check.
    // If the tag does not match, this function will fail.
    int result = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    
    EVP_CIPHER_CTX_free(ctx);

    // After decryption is complete
    secure_zero(key.data(), key.size());
    secure_zero(salt.data(), salt.size());
    
    if (result > 0) {
        // Success! Authentication passed.
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return write_file(output_path, plaintext);
    } else {
        secure_zero(plaintext.data(), plaintext.size());
        // Failure! Authentication failed. This means the password was wrong OR the file was tampered with.
        std::cerr << "Error: Decryption failed. The password may be incorrect or the file is corrupt." << std::endl;
        handle_openssl_errors();
        return false;
    }
}