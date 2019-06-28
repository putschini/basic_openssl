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

#include "certificate.h"
#include "utils.h"
#include "signature.h"


void creat_public_key ( int argc, char** argv ) {
    if ( argc < 4 ) {
        print_exit( "argc < 4" );
    }
    std::string certificate_file( argv[2] );
    std::string public_key_file( argv[3] );
    std::string password = get_password();
    certificate::creat_public_key( certificate_file, password, public_key_file );
}

void creat_private_key ( int argc, char** argv ) {
    if ( argc < 4 ) {
        print_exit( "argc < 4" );
    }
    std::string certificate_file( argv[2] );
    std::string private_key_file( argv[3] );
    std::string password = get_password();
    certificate::creat_private_key( certificate_file, password, private_key_file );
}

void sign ( EVP_PKEY* private_key, std::string file_to_sign ) {
    char* file_content;
    certificate::read_file( file_to_sign, &file_content );
    
    unsigned char* sign_str_encoded;
    size_t sign_str_encoded_length;

    RSA256Sign( private_key, (unsigned char*) file_content, strlen( file_content ), &sign_str_encoded, &sign_str_encoded_length );

    char* sign_str_decode;
    Base64Encode( sign_str_encoded, sign_str_encoded_length, &sign_str_decode );


    //TODO :: create funtion for writing in files
    BIO*  out = BIO_new_file("digest.sha256", "w");
    BIO_write( out, sign_str_decode, strlen(sign_str_decode) );
    BIO_free_all( out );
}

void sign_with_certificate ( int argc, char** argv ) {
    if ( argc < 4 ) {
        print_exit( "argc < 4" );
    }
    std::string certificate_file( argv[2] );
    std::string file_to_sign( argv[3] );
    std::string password = get_password();
    EVP_PKEY* private_key;
    private_key = certificate::read_private_key_form_certificate( certificate_file, password );
    sign( private_key, file_to_sign );
}

// read_private_key_from_file will ask for password
void sign_with_pem_file ( int argc, char** argv ) {
    if ( argc < 4 ) {
        print_exit( "argc < 4" );
    }
    std::string pem_file( argv[2] );
    std::string file_to_sign( argv[3] );
    EVP_PKEY* private_key;
    private_key = certificate::read_private_key_from_file( pem_file  );
    sign( private_key, file_to_sign );
}

void rsa_verify ( int argc, char** argv ) {

}

void certificate_verify ( int argc, char** argv ) {
    if ( argc < 3 ) {
        print_exit( "argc < 3" );
    }
    std::string certificate_file( argv[2] );
    std::string password = get_password();
    certificate::certificate_verify( certificate_file, password );
}

int main ( int argc, char** argv ) {

  if ( argc < 2 ) {
    print_exit( "argc < 2" );
  }
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  std::string plainText = "My secret message My secret message1.\n";

  std::string option ( argv[1] );
  if ( option == "creat_public_key" ) {
    creat_public_key( argc, argv );
  } else if ( option == "creat_private_key" ) {
    creat_public_key( argc, argv );
  } else if ( option == "sign_with_certificate" ) {
    sign_with_certificate( argc, argv );
  } else if ( option == "sign_with_pem_file" ){
    sign_with_pem_file( argc, argv );

  }else if ( option == "rsa_verify" ) {
    EVP_PKEY* publickey = certificate::read_public_key( "pubkey.pem" );
    char* encMessage;
    certificate::read_file( "digest.sha256", &encMessage );
    
     unsigned char* messagedecode;
    size_t messagedecodelength;
    Base64Decode(encMessage, &messagedecode, &messagedecodelength );

    bool valid = false;
    RSAVerifySignature( publickey, messagedecode, messagedecodelength, plainText.c_str(), plainText.length(), &valid );

    if( valid )
      std::cout << "VALID" << std::endl;
    else
      std::cout << "NOT VALID" << std::endl;

  } else if ( option == "certificate_verify" ) {
        certificate_verify( argc, argv );
  } else {
    print_exit( "Unknow argument" );
    return 1;
  }

  return 0;
}