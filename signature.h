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

bool RSA256Sign( EVP_PKEY* privatekey, const unsigned char* Msg, size_t MsgLen, unsigned char** EncMsg, size_t* MsgLenEnc) {

  EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();

  if ( EVP_DigestSignInit(m_RSASignCtx ,NULL, EVP_sha256(), NULL, privatekey) <= 0 ) { // Set up sign contex
      fprintf(stderr, "EVP_DigestSignInit\n");
      ERR_print_errors_fp(stderr);
      return false;
  }
  if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) { // Update the contex with the original message
      fprintf(stderr, "EVP_DigestSignUpdate\n");
      ERR_print_errors_fp(stderr);
      return false;
  }
  if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) { // Get the hash message length
      fprintf(stderr, "EVP_DigestSignFinal\n");
      ERR_print_errors_fp(stderr);
      return false;
  }
  // std::cout << *MsgLenEnc << std::endl << std::endl;
  *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
  if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) { // Get the hash message 
      fprintf(stderr, "EVP_DigestSignFinal\n");
      ERR_print_errors_fp(stderr);
      return false;
  }
  EVP_MD_CTX_cleanup(m_RSASignCtx);
  return true;
}

bool RSAVerifySignature( EVP_PKEY* pubKey, unsigned char* MsgHash, size_t MsgHashLen, const char* Msg, size_t MsgLen, bool* Authentic) 
{
  *Authentic = false;
  EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

  if ( EVP_DigestVerifyInit( m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0 ) { // Set up verification contex
    return false;
  }
  if ( EVP_DigestVerifyUpdate( m_RSAVerifyCtx, Msg, MsgLen ) <= 0 ) { // Update the contex with the original message
    return false;
  }
  int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen); // Verify if mensage hash is equal newly calculated hash
  if ( AuthStatus == 1 ) {  // Signature OK
    *Authentic = true;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return true;
  } else if( AuthStatus == 0 ) { // Signature/Key Not Ok
    *Authentic = false;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return true;
  } else { // Verification method failed
    *Authentic = false;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return false;
  }
}
