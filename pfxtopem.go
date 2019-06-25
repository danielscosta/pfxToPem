package pfxtopem

// #cgo LDFLAGS: -static -static-libgcc -lcrypto -ldl
// #include <openssl/pem.h>
// #include <openssl/err.h>
// #include <openssl/pkcs12.h>
// #include <openssl/bio.h>
// #include <stdio.h>
// #include <stdlib.h>
//
// static char** convert(char* certByteArray, int size, char* password) {
// 	EVP_PKEY *pkey;
// 	X509 *cert;
// 	STACK_OF(X509) *ca = NULL;
// 	PKCS12 *p12;
// 	OpenSSL_add_all_algorithms();
//  ERR_load_BIO_strings();
// 	ERR_load_crypto_strings();
//  FILE *fp = fmemopen(certByteArray, size, "r");
//  p12 = d2i_PKCS12_fp(fp, NULL);
//  if (!p12) {
//		ERR_print_errors_fp(stderr);
//		exit (1);
//  }
//  if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
//		ERR_print_errors_fp(stderr);
//		exit (1);
//  }
//  PKCS12_free(p12);
//  fclose(fp);
//  char *keyPemArray = NULL; 
//  int sizeOfKeyPemArray = 0;
//  char *certPemArray = NULL;
//  int sizeOfCertPemArray = 0;
//  if (pkey) {
//		BIO *bio = BIO_new(BIO_s_mem());
//		PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
//		int p;
//      char r[1024];
//      for(;;) {
//      	p = BIO_read(bio, r, 1023);
//          if(p <= 0) break;
//			sizeOfKeyPemArray += p;
//			char *aux = malloc(sizeOfKeyPemArray + 1);
//			for(int i=0; i < sizeOfKeyPemArray; i++) {
//	        	if(i < sizeOfKeyPemArray - p) {
//					aux[i] = keyPemArray[i];
//				} else {
//					aux[i] = r[i - (sizeOfKeyPemArray - p)];
//				}
//			}
//			aux[sizeOfKeyPemArray] = '\0';
//			if(keyPemArray != NULL) {
//				free(keyPemArray);
//			}
//			keyPemArray = aux;
//          r[p] = 0;
//      }
//		BIO_free_all(bio);
//	}
//	if (cert) {
//		BIO *bio = BIO_new(BIO_s_mem());
//		PEM_write_bio_X509(bio, cert);
//		int p;
//      char r[1024];
//      for(;;) {
//      	p = BIO_read(bio, r, 1023);
//          if(p <= 0) break;
//			sizeOfCertPemArray += p;
//			char *aux = malloc(sizeOfCertPemArray + 1);
//			for(int i=0; i < sizeOfCertPemArray; i++) {
//	        	if(i < sizeOfCertPemArray - p) {
//					aux[i] = certPemArray[i];
//				} else {
//					aux[i] = r[i - (sizeOfCertPemArray - p)];
//				}
//			}
//			aux[sizeOfCertPemArray] = '\0';
//			if(certPemArray != NULL) {
//				free(certPemArray);
//			}
//			certPemArray = aux;
//          r[p] = 0;
//      }
//		BIO_free_all(bio);
//  }
//	sk_X509_pop_free(ca, X509_free);
//	X509_free(cert);
//	EVP_PKEY_free(pkey);
//  char **pemValues = malloc(sizeof(char*)*2);
//  pemValues[0] = keyPemArray;
//  pemValues[1] = certPemArray;
//  return pemValues;
// }
import "C"
import "unsafe"
import "encoding/base64"

// Convert - PFX TO PEM from openssl lib
func Convert(certBase64 string, password string) ([]byte, []byte) {

	certByteArray, _ := base64.StdEncoding.DecodeString(certBase64)
	
	cCertByteArraySize := C.int(len(certByteArray))

	cPassword := C.CString(password)
	
	cPemValues := C.convert((*C.char)(unsafe.Pointer(&certByteArray[0])), 
			  cCertByteArraySize, 
			  cPassword)

	C.free(unsafe.Pointer(cPassword))	

	cPemValuesArray := (*[1 << 30]*C.char)(unsafe.Pointer(cPemValues))[:2:2]

	keyPem := C.GoString(cPemValuesArray[0])
	certPem := C.GoString(cPemValuesArray[1])

	return []byte(keyPem), []byte(certPem)
}
