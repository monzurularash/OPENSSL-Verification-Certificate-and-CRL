#ifndef _CRL_CLIENT_HDR
#define _CRL_CLIENT_HDR

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#define debug_print(args...) ({ \
                                    syslog(LOG_INFO, "func:line (%s:%d) ", __FUNCTION__, __LINE__); \
                                    syslog(LOG_INFO, args); \
})



namespace ssl_util{

#define FN_MAX_LEN   128 

#define TRUSTED_CERTIFICATE  		"/home/monzurul/my_project/SSL/cacert.pem"  

#define CIPHER_LIST         "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:AES128-SHA256:AES128-SHA"


int load_cert_crl_http(const char *url, X509 **pcert, X509_CRL **pcrl);
int cache_crl_to_crls(X509_CRL *crl);

int cert_verify_callback(int ok, X509_STORE_CTX* store_ctx);

STACK_OF(X509_CRL) *crl_http_callback(X509_STORE_CTX *store, X509_NAME *nm);

const char *get_dp_url(DIST_POINT *dp);

X509_CRL *load_HTTP_crl(const char *infile);

int cache_crls_init(const char *file);
int update_crls_with_cache(const char *to_f);

static char cache_fname[FN_MAX_LEN] = {0};

int cert_verify_callback(int ok, X509_STORE_CTX* store)
{
    char data[256];
    int last;

    debug_print("executing\n");

    printf("%s OK=%d \n", __FUNCTION__,ok);
    debug_print("%s OK=%d \n", __FUNCTION__,ok);

    if(!ok)
    {
        X509* cert =  X509_STORE_CTX_get_current_cert(store);
        int depth  =  X509_STORE_CTX_get_error_depth(store);
        int err  =  X509_STORE_CTX_get_error(store);

        // store->crls is NULL, very interesting!!!

        #if OPENSSL_VERSION_NUMBER >= 0x10100000L
            STACK_OF(X509)* certs = X509_STORE_CTX_get1_chain(store);
            last = sk_X509_num(certs) -1;
            sk_X509_pop_free(certs, X509_free);
        #else
            last = sk_X509_num(store->chain) -1;
        #endif
        printf("last = %d \n", last);

        //skip checking root CA against CRL, which is pointless!
        
        #if OPENSSL_VERSION_NUMBER >= 0x10100000L
            if ( (X509_get_extension_flags(cert) & EXFLAG_SS)
        #else
            if ( (cert->ex_flags & EXFLAG_SS)
        #endif
            && (last == depth)
            && (err == X509_V_ERR_UNABLE_TO_GET_CRL) ){

                return 1;
            }

        printf("%s X509 [Certificate Verify Fail]: Error with certificate at depth (%d)\n", __FUNCTION__, depth);

        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        printf("%s X509 [Certificate Verify Fail]: Issuer = %s\n", __FUNCTION__, data);

        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        printf("%s X509 [Certificate Verify Fail]: Subject = %s\n", __FUNCTION__, data);

        printf("%s X509 [Certificate Verify Fail]: Error (%d:%s)\n", __FUNCTION__, err, X509_verify_cert_error_string(err));

    } 

    return ok;
}

STACK_OF(X509_CRL)* crl_http_callback(X509_STORE_CTX *store, X509_NAME *nm)
{
    X509 *cert;
    STACK_OF(X509_CRL) *crls = NULL;
    STACK_OF(DIST_POINT) *crldp;
    X509_CRL *crl = NULL;
    const char *urlptr;

    cert = X509_STORE_CTX_get_current_cert(store);
    if (!cert) {
        goto out;
    }

    crls = sk_X509_CRL_new_null();
    if (!crls) {
        debug_print("Null crls pointer...\n");
        goto out;
    }

    crldp = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    if (!crldp) {
        debug_print(" No CRLDP... \n ");
        goto out;
    }
    debug_print(" found crl dp \n ");

    int i;
    for (i = 0; i < sk_DIST_POINT_num(crldp); i++) { 
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        urlptr = get_dp_url(dp);
        if (urlptr) {
            printf(" Got URL \n");
            debug_print(" Got URL \n ");
            crl = load_HTTP_crl(urlptr);
            break;
        }
    }

    //MY ADDITION
    if (i != sk_DIST_POINT_num(crldp)) 
    {   printf("downloaded CRL\n"); 
        debug_print(" downloaded CRL \n "); 
    }

    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl) {
        cache_crl_to_crls(crl);
        sk_X509_CRL_push(crls, crl);
    }

out:
    return crls;

}

const char* get_dp_url(DIST_POINT *dp)
{
    GENERAL_NAMES *gens;
    GENERAL_NAME *gen;
    int i, gtype;
    ASN1_STRING *uri;
    if (!dp->distpoint || dp->distpoint->type != 0)
        return NULL;
    gens = dp->distpoint->name.fullname;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        uri = (ASN1_STRING *)GENERAL_NAME_get0_value(gen, &gtype);
        if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {

        #if OPENSSL_VERSION_NUMBER >= 0x10100000L
            char *uptr = (char *)ASN1_STRING_get0_data(uri);
        #else
            char *uptr = (char *)ASN1_STRING_data(uri);
        #endif

            if (!strncmp(uptr, "http://", 7))
                return uptr;
        }
    }
    return NULL;
}

int cache_crls_init(const char *file)
{
    int ret = 0;
    FILE *crls_fp;

    memset(cache_fname, 0, sizeof(cache_fname));
    snprintf(cache_fname, sizeof(cache_fname)-1, "%s", file);
    crls_fp = fopen(cache_fname, "w");
    if (crls_fp) {
        fclose(crls_fp);
    } else {
        ret = -1;
    }
    return ret;
}

X509_CRL* load_HTTP_crl(const char *infile)
{
    X509_CRL *x = NULL;

    load_cert_crl_http(infile, NULL, &x);     

    return x;
}

int load_cert_crl_http(const char *url, X509 **pcert, X509_CRL **pcrl)
{
    char *host = NULL, *port = NULL, *path = NULL;
    BIO *bio = NULL;
    OCSP_REQ_CTX *rctx = NULL;
    int use_ssl, rv = 0;
    if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl))
        goto err;
    if (use_ssl) {
        goto err;
    }
    //printf("host: %s, port: %s, path: %s\n", host, port, path);

    bio = BIO_new_connect(host);
    if (!bio || !BIO_set_conn_port(bio, port))
        goto err;
    rctx = OCSP_REQ_CTX_new(bio, 2048);
    if (!rctx)
        goto err;
    if (!OCSP_REQ_CTX_http(rctx, "GET", path))
        goto err;
    if (!OCSP_REQ_CTX_add1_header(rctx, "Host", host))
        goto err;
    if (pcert) {
        do {
            rv = X509_http_nbio(rctx, pcert);
        }
        while (rv == -1);
    } else {
        do {
            rv = X509_CRL_http_nbio(rctx, pcrl);
            //printf("rv = %d\n", rv);
        } while (rv == -1);
    }

 err:
    if (host)
        OPENSSL_free(host);
    if (path)
        OPENSSL_free(path);
    if (port)
        OPENSSL_free(port);
    if (bio)
        BIO_free_all(bio);
    if (rctx)
        OCSP_REQ_CTX_free(rctx);
    if (rv != 1) {
        //Failed to load CRL
        //printf("failed to load CRL\n");
    }
    return rv;
}

int cache_crl_to_crls(X509_CRL *crl)
{
    int ret = 0;
    FILE *crls_fp = fopen(cache_fname, "a");

    if (crls_fp) {
        debug_print(" cache_crl_to_crls succedded \n");
        PEM_write_X509_CRL(crls_fp, crl);
        fclose(crls_fp);
    } else {
        debug_print(" cache_crl_to_crls failed \n");
        ret = -1;
    }

    return ret;
}

int update_crls_with_cache(const char *to_f)
{
    int ret = 0;
    char cmd_buf[256];

    //make sure file path not too long!!!

    sprintf(cmd_buf, "mv %s %s", cache_fname, to_f);

    ret = system(cmd_buf);

    return ret;
}

}

#endif