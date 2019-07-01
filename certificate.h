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

namespace certificate {

  // TODO  CHANGE RETURNS TO BOOLEANS 
  bool read_pk12_certificate( std::string file_name, std::string password, EVP_PKEY** private_key, X509** certificate, STACK_OF(X509)** ca ){

      EVP_PKEY* pkey;
      X509 *c;
      STACK_OF(X509) *a;

      BIO* certbio = BIO_new(BIO_s_file());
      if( !BIO_read_filename(certbio, file_name.c_str()) ) { //
          fprintf(stderr, "Error opening file %s\n", file_name.c_str() );
          exit(1);
      }

      PKCS12* p12 = d2i_PKCS12_bio(certbio, NULL);

      if (!p12) {
          fprintf(stderr, "Error reading PKCS#12 file\n");
          ERR_print_errors_fp(stderr);
          return false;
      }
      if (!PKCS12_parse(p12, password.c_str(), &pkey, &c, &a)) {
          fprintf(stderr, "Error parsing PKCS#12 file\n");
          ERR_print_errors_fp(stderr);
          return false;
      }

      *private_key = pkey;
      *certificate = c;
      *ca = a;

      BIO_free_all( certbio );
      PKCS12_free( p12 );

      return true;
  }

  void creat_private_key( std::string certificate_file, std::string pass, std::string private_key_file ) {
    EVP_PKEY* private_key;
    X509 *certificate;
    STACK_OF(X509) *ca;

    std::cout << std::endl;

    if( !read_pk12_certificate( certificate_file, pass, &private_key, &certificate, &ca ) ) {
        std::cout << "asdf" << std::endl;
    }

    BIO*  pembio = BIO_new_file(private_key_file.c_str(), "w");
    if( pembio == NULL ) {
        fprintf(stderr, "Error opening file %s\n", private_key_file.c_str() );
        exit(1);
    }

    if( !PEM_write_bio_PKCS8PrivateKey( pembio, private_key, EVP_des_ede3_cbc(), (char*)pass.c_str(), pass.length(), 0, NULL ) ) {
        fprintf(stderr, "Error writing public key to file %s\n", private_key_file.c_str() );
        exit(1);
    }

    BIO_free_all( pembio );
    X509_free(certificate);
    EVP_PKEY_free(private_key);
  }

  void creat_public_key( std::string certificate_file, std::string pass, std::string pub_key_file ){
      EVP_PKEY* private_key;
      X509 *certificate;
      STACK_OF(X509) *ca;

      read_pk12_certificate( certificate_file, pass, &private_key, &certificate, &ca );

      EVP_PKEY* pubkey = X509_get_pubkey(certificate);

      BIO*  pembio = BIO_new_file(pub_key_file.c_str(), "w");
      if( pembio == NULL ) { 
          fprintf(stderr, "Error opening file %s\n", pub_key_file.c_str() );
          exit(1);
      }

      if( !PEM_write_bio_PUBKEY( pembio, pubkey ) ) { //
          fprintf(stderr, "Error writing public key to file %s\n", pub_key_file.c_str() );
          exit(1);
      }

      BIO_free_all( pembio );
      X509_free(certificate);
      EVP_PKEY_free(pubkey);
      EVP_PKEY_free(private_key);
  }

  EVP_PKEY* read_private_key_form_certificate( std::string certificate_file, std::string pass ){

      EVP_PKEY* private_key;
      X509 *certificate;
      STACK_OF(X509) *ca = NULL;

      read_pk12_certificate( certificate_file, pass, &private_key, &certificate, &ca );


      // BIO* certbio = BIO_new(BIO_s_file());
      // if( !BIO_read_filename(certbio, file.c_str())  ){
      //     fprintf(stderr, "Error opening file %s\n", file.c_str() );
      //     exit(1);
      // }

      // PKCS12* p12 = d2i_PKCS12_bio(certbio, NULL);

      // if (!p12) {
      //     fprintf(stderr, "Error reading PKCS#12 file\n");
      //     ERR_print_errors_fp(stderr);
      //     exit (1);
      // }
      // if (!PKCS12_parse(p12, pass.c_str(), &private_key, &certificate, &ca)) {
      //     fprintf(stderr, "Error parsing PKCS#12 file\n");
      //     ERR_print_errors_fp(stderr);
      //     exit (1);
      // }
      
      BIO_free_all(certbio);
      sk_X509_pop_free(ca, X509_free);
      X509_free(certificate);

      return private_key;
  }


  EVP_PKEY* read_private_key_from_file( std::string file ){

      EVP_PKEY* private_key;

      BIO* certbio = BIO_new(BIO_s_file());
      if( !BIO_read_filename(certbio, file.c_str())  ){
          fprintf(stderr, "Error opening file %s\n", file.c_str() );
          exit(1);
      }
      // PEM_read_bio_PrivateKey will ask for password
      private_key = PEM_read_bio_PrivateKey( certbio, NULL, 0, NULL );

      BIO_free_all(certbio);
      return private_key;
  }


  EVP_PKEY* read_public_key( std::string file ){

    EVP_PKEY* public_key;

    BIO* pubBio = BIO_new(BIO_s_file());
    if( !BIO_read_filename(pubBio, file.c_str()) ){
        fprintf(stderr, "Error opening file %s\n", file.c_str() );
        exit(1);
    }
    public_key = PEM_read_bio_PUBKEY( pubBio, NULL, NULL, NULL );
    if( public_key == NULL ){
        fprintf(stderr, "Error reading Public Key file\n");
        ERR_print_errors_fp(stderr);
        exit (1); 
    }
    return public_key;
  }

  // void test_read_public_key(){
  //   EVP_PKEY* public_key = read_public_key( "pubkey.pem" );
  //   if( public_key != NULL ){
  //     std::cout << "OK" << std::endl;
  //     PEM_write_PUBKEY( stdout, public_key );
  //   }
  // }

  void read_file( std::string file, char** content ){
      BIO* bio = BIO_new(BIO_s_file());
      if( !BIO_read_filename(bio, file.c_str()) ){
          fprintf(stderr, "Error opening file %s\n", file.c_str() );
          exit(1);
      }
      BIO* result = BIO_new(BIO_s_mem());
      char inbuf[64];
      size_t inlen;

      while( (inlen = BIO_read(bio, inbuf, sizeof(inbuf))) > 0 ){
          BIO_write(result, inbuf, inlen);
      }

      BUF_MEM *bufferPtr;
      BIO_get_mem_ptr(result, &bufferPtr);
      *content = (*bufferPtr).data;
      BIO_free_all(bio);
  }

  bool certificate_verify( std::string certificate_file, std::string password ){
      EVP_PKEY* privatekey;
      X509* certificate;
      STACK_OF(X509)* ca;

      X509_STORE_CTX *verify_ctx;
      verify_ctx = X509_STORE_CTX_new();
      
      std::cout << std::endl; // TODO :: Understand why this is needed

      read_pk12_certificate( certificate_file, password, &privatekey, &certificate, &ca );

      if ( !X509_STORE_CTX_init( verify_ctx, NULL, certificate, NULL ) ){
          fprintf(stderr, "Error initializing X509_STORE_CTX\n");
          exit (1); 
      }
      X509_STORE_CTX_trusted_stack( verify_ctx, ca );

      BIO* outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
      if (ca != NULL && sk_X509_num(ca) > 0) {
          for (int i = 0; i < sk_X509_num(ca); i++)
              PEM_write_bio_X509_AUX(outbio, sk_X509_value(ca, i));
      }

      int ret = X509_verify_cert(verify_ctx);
      if( ret == 0 ){ // Validation failed
          X509 *error_cert;
          X509_NAME *certsubject;
          error_cert  = X509_STORE_CTX_get_current_cert(verify_ctx);
          certsubject = X509_NAME_new();
          certsubject = X509_get_subject_name(error_cert);
          BIO* outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
          // BIO_printf(outbio, "Verification failed cert:\n");
          X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
          BIO_printf(outbio, "\n");
      }else if( ret < 0 ){
          std::cout << "ERROR" << std::endl;
          // erro in the function call
      }else{
          std::cout << "CERTIFICATE OK" << std::endl;
          
      }
  }
}