#include <iostream>
#include <string>
#include <termios.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

// #include <openssl/aes.h>
// #include <openssl/evp.h>
#include <openssl/ssl.h>
#include <assert.h>

namespace signature {

    void sign( EVP_PKEY* private_key, const unsigned char* mensage, size_t mensage_length, unsigned char** hash_encoded, size_t* hash_encoded_length ) {

        EVP_MD_CTX* signature_context = EVP_MD_CTX_create();

        if ( EVP_DigestSignInit( signature_context ,NULL, EVP_sha256(), NULL, private_key ) <= 0 ) { // Set up sign contex
            utils::print_error_exit( "Erro initializing signature context" );
        }
        if ( EVP_DigestSignUpdate( signature_context, mensage, mensage_length ) <= 0 ) { // Update the contex with the original message
            utils::print_error_exit( "Erro setting up signature context" );
        }
        if ( EVP_DigestSignFinal( signature_context, NULL, hash_encoded_length ) <= 0 ) { // Get the hash message length
            utils::print_error_exit( "Erro getting hash length" );
        }
        *hash_encoded = ( unsigned char* )malloc( *hash_encoded_length );
        if (EVP_DigestSignFinal( signature_context, *hash_encoded, hash_encoded_length ) <= 0 ) { // Get the hash message 
            utils::print_error_exit( "Erro getting hash" );
        }
        EVP_MD_CTX_cleanup( signature_context );
    }

    void verify_signature( EVP_PKEY* public_key, unsigned char* hash, size_t hash_length, const char* mensage, size_t mensage_length ) {
        
        EVP_MD_CTX* verification_context = EVP_MD_CTX_create();

        if ( EVP_DigestVerifyInit( verification_context, NULL, EVP_sha256(), NULL, public_key ) <= 0 ) { // Set up verification contex
            utils::print_error_exit( "Erro initializing verification context" );
        }
        if ( EVP_DigestVerifyUpdate( verification_context, mensage, mensage_length ) <= 0 ) { // Update the contex with the original message
            utils::print_error_exit( "Erro setting up verification context" );
        }
        int AuthStatus = EVP_DigestVerifyFinal(verification_context, hash, hash_length); // Verify if mensage hash is equal newly calculated hash
        if ( AuthStatus == 1 ) {  // Signature OK
            std::cout << "Valid Signature" << std::endl;
            EVP_MD_CTX_cleanup(verification_context);
        } else if( AuthStatus == 0 ) { // Signature/Key Not Ok
            std::cout << "Invalid Signature" << std::endl;
            EVP_MD_CTX_cleanup(verification_context);
        } else { // Verification method failed
            EVP_MD_CTX_cleanup(verification_context);
            utils::print_error_exit( "Erro in verification method" );
        }
    }
}