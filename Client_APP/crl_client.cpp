#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/bio.h>
#include <syslog.h>

#include "crl_client.h"

using namespace ssl_util;
using namespace std;

#define CRLS_CACHE_TMP_CLIENT  "/home/monzurul/my_project/SSL/crls_client.tmp"
#define TRUSTED_CRL_CLIENT     "/home/monzurul/my_project/SSL/crls.crt"


static int connect_server(const char *ser_ip, const char *ser_port)
{
    int skt;
    struct sockaddr_in addr;
    struct in_addr host_addr;

    if (inet_aton(ser_ip, &host_addr) == 0) return -1;

    skt = socket(AF_INET, SOCK_STREAM, 0);
    if (skt < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(ser_port));
    addr.sin_addr.s_addr = host_addr.s_addr;

    if (connect(skt, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(skt);
        printf("%s connection failed \n", __FUNCTION__);
        skt = -1;
    }

    return skt;
}

static SSL_CTX* init_openssl(void)
{
    SSL_CTX *ctx = NULL;

    if (!SSL_library_init()) {
        exit(-1);
    }

    //OpenSSL_add_all_algorithms();

    SSL_load_error_strings();

    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        ctx = SSL_CTX_new(TLS_client_method());
    #else
        ctx = SSL_CTX_new(TLSv1_2_client_method());
    #endif

    return ctx;
}

static char *server_ip = NULL;

static void timeout_handler(int sig)
{
    printf("Failed connecting to the server [%s].", server_ip ? server_ip : "Unknown");
    debug_print("Failed connecting to the server [%s].", server_ip ? server_ip : "Unknown");

    exit(-1);
}

int main(int argc, char *argv[])
{
    SSL_CTX *ssl_ctx;
    X509_STORE *store;
    SSL *ssl_con;
    int skt;
    int ret = 0;
    struct sigaction sa;

    char buf[1024];
    char input[1024];
    int bytes;

    if (argc < 3) {
        printf("usage: %s Server_IP Server_Port\n", argv[0]);
        return -1;
    }

    printf("staring get_server_crl_app \n");

    server_ip = argv[1];

    sa.sa_handler = timeout_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        printf("Failed registering handler for SIGALRM!\n");
        return -1;
    }

    ssl_ctx = init_openssl();
    if (!ssl_ctx) {
        return -1;
    }

    skt = connect_server(argv[1], argv[2]);

    printf("%s connection succeded \n", __FUNCTION__);

    if (skt >= 0) {

        /* verify truststore, check cert */
        if (SSL_CTX_load_verify_locations(ssl_ctx, TRUSTED_CERTIFICATE, NULL) != 1) {
            printf("%s SSL_CTX_load_verify_locations failed \n", __FUNCTION__);
            debug_print("%s SSL_CTX_load_verify_locations failed \n", __FUNCTION__);
            goto err_exit;
        }
        
        //set peer certificate verification parameters
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, cert_verify_callback);

        SSL_CTX_set_verify_depth(ssl_ctx, 6);

        // manipulate SSL options
        SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

        if (SSL_CTX_set_cipher_list(ssl_ctx, CIPHER_LIST) != 1) {
            printf("%s SSL_CTX_set_cipher_list failed \n", __FUNCTION__);
            debug_print("%s SSL_CTX_set_cipher_list failed \n", __FUNCTION__); 
            goto err_exit;
        }

        //manipulate X509 certificate verification storage
        store = SSL_CTX_get_cert_store(ssl_ctx);
    
        cache_crls_init(CRLS_CACHE_TMP_CLIENT);

        //X509_STORE_set_verify_cb() sets the verification callback of ctx to verify_cb overwriting the previous callback
        X509_STORE_set_lookup_crls_cb(store, crl_http_callback);

        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

        /* create new SSL connection state */
        ssl_con = SSL_new(ssl_ctx);

        /* attach the socket descriptor */
        SSL_set_fd(ssl_con, skt);

        //alarm(20); // to prevent SSL_connect from blocking for ever...

        /* perform the connection */
        printf("%s performing SSL_connect \n", __FUNCTION__);
        ret = SSL_connect(ssl_con);

        if (ret == 1) {
            printf(" ssl connection successful \n");
            int update_crls_with_cache_ret = update_crls_with_cache(TRUSTED_CRL_CLIENT);

            pid_t cpid = fork();

            /*Fork system call is used to create a new process*/

            if (cpid == 0)
            {
                while (1)
                {
                    printf("\nMESSAGE TO SERVER:");
                    fgets(input, sizeof(input), stdin);
                    SSL_write(ssl_con, input, strlen(input)); /* encrypt & send message */
                }
            }
            else
            {
                while (1)
                {
                    bytes = SSL_read(ssl_con, buf, sizeof(buf)); /* get request */
                    if (bytes > 0)
                    {
                        buf[bytes] = 0;
                        printf("\nMESSAGE FROM SERVER: %s\n", buf);
                        fflush(stdout);
                        printf("\nMESSAGE TO SERVER:");
                        fflush(stdout);
                    }
                }
            }
   
        } else {
            printf("Failed connecting to server (%s)!\n", argv[1]);
            ret = -1;
        }

        //alarm(0);

        /* release connection state */
        SSL_shutdown(ssl_con); 
        SSL_free(ssl_con);

err_exit:
        SSL_CTX_free(ssl_ctx);
        close(skt);
        printf("%s closing connection \n", __FUNCTION__);
    } else {
        ret = -1;
    }

    return ret;
}

