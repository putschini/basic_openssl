#include <string>

#include <openssl/bio.h>
#include <openssl/ssl.h>

namespace utils {

    size_t calcDecodeLength( const char* base64_message ) {
        size_t len = strlen(base64_message);
        int padding = 0;
        if (base64_message[len-1] == '=' && base64_message[len-2] == '=') //last two chars are =
            padding = 2;
        else if (base64_message[len-1] == '=') //last char is =
            padding = 1;
        return (len*3)/4 - padding;
}

    void Base64Decode(const char* base64_message, unsigned char** message, size_t* message_length) {
        BIO *bio, *b64;

        int decodeLen = calcDecodeLength( base64_message );
        *message = (unsigned char*) malloc( decodeLen + 1 );
        (*message)[decodeLen] = '\0';

        bio = BIO_new_mem_buf( base64_message, -1 );
        b64 = BIO_new( BIO_f_base64() );
        bio = BIO_push( b64, bio );

        *message_length = BIO_read( bio, *message, strlen( base64_message ) );
        BIO_free_all(bio);
    }

    void Base64Encode( const unsigned char* message, size_t message_length, char** base64_message ) {
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

    std::string get_password(){
        std::cout << "Certificate password" << std::endl;
        struct termios tty;
        tcgetattr(STDIN_FILENO, &tty);
        tty.c_lflag &= ~ECHO;
        (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
        std::cin >> pass;
        return pass;
    }

    void print_error_exit( std::string message ){
        std::cout << message << std::endl;
        ERR_print_errors_fp( stdout );
        exit(1);
    }

    void print_exit( std::string message ){
        std::cout << message << std::endl;
        exit(1);
    }
}