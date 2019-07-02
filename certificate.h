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
#include "utils.h"

namespace certificate {

    // TODO  CHANGE RETURNS TO BOOLEANS 
    void read_pk12_certificate( std::string file_name, std::string password, EVP_PKEY** private_key, X509** certificate, STACK_OF(X509)** ca ) {

        EVP_PKEY* pkey;
        X509 *c;
        STACK_OF(X509) *a;

        BIO* certbio = BIO_new(BIO_s_file());
        if( !BIO_read_filename(certbio, file_name.c_str()) )
            utils::print_error_exit( "Error opening file " + file_name );

        PKCS12* p12 = d2i_PKCS12_bio(certbio, NULL);

        if (!p12)
            utils::print_error_exit( "Error reading PKCS#12 file" );

        if (!PKCS12_parse(p12, password.c_str(), &pkey, &c, &a))
            utils::print_error_exit( "Error parsing PKCS#12 file" );

        *private_key = pkey;
        *certificate = c;
        *ca = a;

        BIO_free_all( certbio );
        PKCS12_free( p12 );

    }

    void creat_private_key( std::string certificate_file, std::string pass, std::string private_key_file ) {
        EVP_PKEY* private_key;
        X509 *certificate;
        STACK_OF(X509) *ca;

        read_pk12_certificate( certificate_file, pass, &private_key, &certificate, &ca );

        BIO*  pembio = BIO_new_file(private_key_file.c_str(), "w");

        if( pembio == NULL ) 
            utils::print_error_exit( "Error opening file " + private_key_file );

        if( !PEM_write_bio_PKCS8PrivateKey( pembio, private_key, EVP_des_ede3_cbc(), (char*)pass.c_str(), pass.length(), 0, NULL ) )
            utils::print_error_exit( "Error writing public key to file " + private_key_file );

        BIO_free_all( pembio );
        X509_free(certificate);
        EVP_PKEY_free(private_key);
    }

    void creat_public_key( std::string certificate_file, std::string pass, std::string pub_key_file ) {
        EVP_PKEY* private_key;
        X509 *certificate;
        STACK_OF(X509) *ca;

        read_pk12_certificate( certificate_file, pass, &private_key, &certificate, &ca );

        EVP_PKEY* pubkey = X509_get_pubkey(certificate);

        BIO*  pembio = BIO_new_file(pub_key_file.c_str(), "w");

        if( pembio == NULL ) 
            utils::print_error_exit( "Error opening file " + pub_key_file );

        if( !PEM_write_bio_PUBKEY( pembio, pubkey ) )
            utils::print_error_exit( "Error writing public key to file " + pub_key_file );

        BIO_free_all( pembio );
        sk_X509_pop_free(ca, X509_free);
        X509_free(certificate);
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(private_key);
    }

    EVP_PKEY* read_private_key_form_certificate( std::string certificate_file, std::string pass ) {
        EVP_PKEY* private_key;
        X509 *certificate;
        STACK_OF(X509) *ca = NULL;

        read_pk12_certificate( certificate_file, pass, &private_key, &certificate, &ca );

        sk_X509_pop_free(ca, X509_free);
        X509_free(certificate);

        return private_key;
    }


    EVP_PKEY* read_private_key_from_file( std::string file ) {
        EVP_PKEY* private_key;

        BIO* certbio = BIO_new(BIO_s_file());
        if( !BIO_read_filename(certbio, file.c_str())  )
            utils::print_error_exit( "Error opening file " + file );

        // PEM_read_bio_PrivateKey will ask for password
        private_key = PEM_read_bio_PrivateKey( certbio, NULL, 0, NULL );

        BIO_free_all(certbio);
        return private_key;
    }


    EVP_PKEY* read_public_key( std::string file ){
        EVP_PKEY* public_key;

        BIO* pubBio = BIO_new(BIO_s_file());
        if( !BIO_read_filename(pubBio, file.c_str()) )
            utils::print_error_exit( "Error opening file " + file );

        public_key = PEM_read_bio_PUBKEY( pubBio, NULL, NULL, NULL );
        
        if( public_key == NULL )
            utils::print_error_exit( "Error reading Public Key file" );

        return public_key;
    }

    bool certificate_verify( std::string certificate_file, std::string password ){
        EVP_PKEY* privatekey;
        X509* certificate;
        STACK_OF(X509)* ca;

        X509_STORE_CTX *verify_ctx;
        verify_ctx = X509_STORE_CTX_new();

        read_pk12_certificate( certificate_file, password, &privatekey, &certificate, &ca );

        if ( !X509_STORE_CTX_init( verify_ctx, NULL, certificate, NULL ) )
            utils::print_error_exit( "Error initializing X509_STORE_CTX" );

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
            utils::print_error_exit( "Error on X509_verify_cert" );
            // erro in the function call
        }else{
            std::cout << "CERTIFICATE OK" << std::endl;
        }
    }
}