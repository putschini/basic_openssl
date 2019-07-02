#pragma once
#include <string>

#include <openssl/bio.h>
#include <openssl/ssl.h>

namespace utils {

    void print_error_exit( std::string message ) {
        std::cout << message << std::endl;
        ERR_print_errors_fp( stdout );
        exit(1);
    }

    void print_exit( std::string message ) {
        std::cout << message << std::endl;
        exit(1);
    }

    void read_file( std::string file, char** content ) {
        BIO* bio = BIO_new(BIO_s_file());
        if( !BIO_read_filename(bio, file.c_str()) ) {
            print_error_exit( "Error opening file" + file );
        }
        BIO* result = BIO_new(BIO_s_mem());
        char inbuf[512];
        size_t inlen;

        while( (inlen = BIO_read(bio, inbuf, sizeof(inbuf))) > 0 ) {
            BIO_write(result, inbuf, inlen);
        }

        BUF_MEM *bufferPtr;
        BIO_get_mem_ptr(result, &bufferPtr);
        *content = (*bufferPtr).data;
        BIO_free_all( bio );
    }

    size_t calculate_decode_length( const char* base64_message ) {
        size_t len = strlen(base64_message);
        int padding = 0;
        if (base64_message[len-1] == '=' && base64_message[len-2] == '=') //last two chars are =
            padding = 2;
        else if (base64_message[len-1] == '=') //last char is =
            padding = 1;
        return (len*3)/4 - padding;
    }

    void base_64_decode( const char* base64_message, unsigned char** message, size_t* message_length ) {
        BIO *bio, *b64;

        int decodeLen = calculate_decode_length( base64_message );
        *message = (unsigned char*) malloc( decodeLen + 1 );
        (*message)[decodeLen] = '\0';

        bio = BIO_new_mem_buf( base64_message, -1 );
        b64 = BIO_new( BIO_f_base64() );
        bio = BIO_push( b64, bio );

        *message_length = BIO_read( bio, *message, strlen( base64_message ) );
        BIO_free_all(bio);
    }

    void base_64_encode( const unsigned char* message, size_t message_length, char** base64_message ) {
        BIO *bio, *b64;
        BUF_MEM *aux_ptr;

        b64 = BIO_new( BIO_f_base64() );
        bio = BIO_new( BIO_s_mem() );
        bio = BIO_push( b64, bio );

        BIO_write( bio, message, message_length );
        BIO_flush( bio );
        BIO_get_mem_ptr( bio, &aux_ptr );
        BIO_set_close( bio, BIO_NOCLOSE );
        BIO_free_all( bio );

        *base64_message = ( *aux_ptr ).data;
    }

    std::string get_password() {
        std::cout << "Certificate password" << std::endl;
        std::string password;
        struct termios tty;
        tcgetattr(STDIN_FILENO, &tty);
        tty.c_lflag &= ~ECHO;
        (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
        std::cin >> password;
        return password;
    }
}
