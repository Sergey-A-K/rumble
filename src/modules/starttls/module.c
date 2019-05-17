
//  * File: module.c Author: Humbedooh

#include "../../rumble.h"
#include "../../comm.h"

#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>


#include <gcrypt.h>
#include <errno.h>



// GCRY_THREAD_OPTION_PTHREAD_IMPL;



static const char * _gnutls = "gnutls";
static const char * certfile = "config/server.cert";
static const char * keyfile  = "config/server.key";
static const char * gnutls_defprio = "NORMAL"; // EXPORT ? NORMAL
#define  gnutls_sec_param GNUTLS_SEC_PARAM_NORMAL //GNUTLS_SEC_PARAM_NORMAL; // GNUTLS_SEC_PARAM_LEGACY
static gnutls_dh_params_t dh_server_params = NULL;
#define gnutls_cert_request GNUTLS_CERT_REQUEST // GNUTLS_CERT_IGNORE GNUTLS_CERT_REQUIRE
#define ssl_session_timeout 3600 // One hour
#define gnutls_log_level 2 // arbitrarily chosen level; bump up to 9 for more

static unsigned int dh_bits = 1024;

int init_server_dh(masterHandle *master) {
    int rc;

    rumble_debug(master, _gnutls, "Initialising D-H GnuTLS server params");

    if ((rc = gnutls_dh_params_init(&dh_server_params))){
        rumble_debug(master, _gnutls, "gnutls_dh_params_init() failed");
        return (EXIT_FAILURE);
    }
    /*
    if (!(dh_bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, gnutls_sec_param))){
        rumble_debug(master, _gnutls, "gnutls_sec_param_to_pk_bits() failed");
        return (EXIT_FAILURE);
    }
    */
    rumble_debug(master, _gnutls, "GnuTLS tells us that for D-H PK, is %d bits.", dh_bits);

    if ((rc = gnutls_dh_params_generate2(dh_server_params, dh_bits))){
        rumble_debug(master, _gnutls, "ERROR on gnutls_dh_params_generate2");
        return (EXIT_FAILURE);
    }

    rumble_debug(master, _gnutls, "initialized server D-H parameters");
    return (EXIT_SUCCESS);
}





// GnuTLS calls this function to send data through the transport layer. We set
// this callback with gnutls_transport_set_push_function(). It should behave
// like send() (see the manual for specifics).
ssize_t data_push(gnutls_transport_ptr_t ptr, const void* data, size_t len)
{
    int sockfd = *(socketHandle*)(ptr);
    return send(sockfd, data, len, 0);
}

// GnuTLS calls this function to receive data from the transport layer. We set
// this callback with gnutls_transport_set_pull_function(). It should act like
// recv() (see the manual for specifics).
ssize_t data_pull(gnutls_transport_ptr_t ptr, void* data, size_t maxlen)
{
    int sockfd = *(socketHandle*)(ptr);
    return recv(sockfd, data, maxlen, 0);
}



// Generic STARTTLS handler
// RUMBLE_RETURN_OKAY      Everything went fine, keep going.
// RUMBLE_RETURN_FAILURE   Something went really wrong, abort the connection!
// RUMBLE_RETURN_IGNORE    Module handled the return code, skip to next command.
ssize_t rumble_tls_start(masterHandle *master, sessionHandle *session, const char *arg, const char *extra) {
    (void)arg; // no warn
    gnutls_session_t psess;
    session->client->tls = NULL;
    session->client->recv = NULL;
    session->client->send = NULL;


    gnutls_certificate_credentials_t * x509_cred = calloc(1, sizeof(gnutls_certificate_credentials_t));
    master->_core.tls_credentials = x509_cred;

    switch (session->_tflags & RUMBLE_THREAD_SVCMASK)
    {
        case RUMBLE_THREAD_SMTP: rumble_comm_send(session, "220 OK, starting TLS\r\n"); break;
        case RUMBLE_THREAD_POP3: rumble_comm_send(session, "+OK, starting TLS\r\n");    break;
        case RUMBLE_THREAD_IMAP: rumble_comm_printf(session, "%s OK Begin TLS negotiation now\r\n", extra); break;
    default:                     return (RUMBLE_RETURN_IGNORE);
    }

    rumble_debug(master, _gnutls, "Negotiating TLS");

    int ret = gnutls_init(&psess, GNUTLS_SERVER);
    if (ret != GNUTLS_E_SUCCESS) {
        rumble_debug(master, _gnutls, "FAIL gnutls_init(&psess, GNUTLS_SERVER)=%s", gnutls_strerror_name(ret));
        return (RUMBLE_RETURN_FAILURE);
     }

    rumble_debug(master, _gnutls, "Expanding various TLS configuration options for session credentials.");

    ret = gnutls_certificate_allocate_credentials(x509_cred);
    if (ret != GNUTLS_E_SUCCESS) {
        rumble_debug(master, _gnutls, "FAIL gnutls_certificate_allocate_credentials(x509_cred)=%s", gnutls_strerror_name(ret));
        return (RUMBLE_RETURN_FAILURE);
    }

    rumble_debug(master, _gnutls, "Setting certs");

    ret = gnutls_certificate_set_x509_key_file(*x509_cred, certfile, keyfile, GNUTLS_X509_FMT_PEM);
    if (ret != GNUTLS_E_SUCCESS) {
        rumble_debug(master, _gnutls, "FAIL TLS: cert=%s / key=%s \"%s\"", certfile, keyfile, gnutls_strerror_name(ret));
        return (RUMBLE_RETURN_FAILURE);
    } else rumble_debug(master, _gnutls, "TLS: cert/key registered: cert=%s key=%s", certfile, keyfile);

    rumble_debug(master, _gnutls, "gnutls_certificate_set_x509_system_trust cert_countt=%d",
                 gnutls_certificate_set_x509_system_trust(*x509_cred));



    if (!dh_server_params) {
        rumble_debug(master, _gnutls, "FAIL !dh_server_params");
        return (RUMBLE_RETURN_FAILURE);
    }

    gnutls_certificate_set_dh_params(*x509_cred, dh_server_params);



     ret = gnutls_credentials_set(psess, GNUTLS_CRD_CERTIFICATE, *x509_cred);
     if (ret != GNUTLS_E_SUCCESS) {
         rumble_debug(master, _gnutls, "FAIL gnutls_credentials_set(psess, GNUTLS_CRD_CERTIFICATE, *x509_cred)=%s", gnutls_strerror_name(ret));
         return (RUMBLE_RETURN_FAILURE);
     }

     rumble_debug(master, _gnutls, "GnuTLS using default session cipher/priority \"%s\"", gnutls_defprio);

    const char * errpos;

    gnutls_priority_t priority_cache;

    ret = gnutls_priority_init(&priority_cache, gnutls_defprio, &errpos);
    if ( ret != GNUTLS_E_SUCCESS ) {
        rumble_debug(master, _gnutls, "FAIL gnutls_priority_init(%s)=%s, %s", gnutls_defprio, gnutls_strerror_name(ret), errpos);
        return (RUMBLE_RETURN_FAILURE);
    }

    ret = gnutls_priority_set(psess, priority_cache);
    if ( ret != GNUTLS_E_SUCCESS ) {
        rumble_debug(master, _gnutls, "FAIL gnutls_priority_set(%s)=%s failed, %s", gnutls_defprio, gnutls_strerror_name(ret), errpos);
        return (RUMBLE_RETURN_FAILURE);
    }

    gnutls_db_set_cache_expiration(psess, ssl_session_timeout);

     rumble_debug(master, _gnutls, "TLS: server set certificate verification");

     gnutls_certificate_server_set_request(psess, gnutls_cert_request);

     rumble_debug(master, _gnutls, "TLS: will request OCSP stapling");

//     session->client->tls = 0;

    rumble_debug(master, _gnutls, "Setting D-H prime minimum acceptable bits to %d", dh_bits);
    gnutls_dh_set_prime_bits(psess, dh_bits);


    printf(" 1 \n");


    gnutls_transport_set_ptr(psess, (gnutls_transport_ptr_t) &session->client->socket);
    gnutls_transport_set_push_function(psess, data_push);
    gnutls_transport_set_pull_function(psess, data_pull);
    //gnutls_transport_set_pull_timeout_function(psess, pull_timeout_func);

    ret = gnutls_handshake(psess);

    if (ret == GNUTLS_E_DH_PRIME_UNACCEPTABLE) {
        gnutls_dh_set_prime_bits(psess, dh_bits*2);
        ret = gnutls_handshake(psess);
    }


    session->client->tls = psess;
    if (ret < 0) {
        fprintf(stderr, "*** TLS Handshake failed\n");
        gnutls_perror(ret);
        session->client->tls = NULL;
        return (RUMBLE_RETURN_FAILURE);
    }
    fprintf(stderr, "*** TLS Handshake OK\n");

    session->client->recv = (dummyTLS_recv) gnutls_record_recv;
    session->client->send = (dummyTLS_send) gnutls_record_send;



    return (RUMBLE_RETURN_IGNORE);
}


// gnutls_system_recv_timeout



// Generic STOPTLS handler (or called when a TLS connection is closed)
ssize_t rumble_tls_stop(sessionHandle *session, const char *junk) {
    (void)junk; // no warn
    if (session->client->tls) {
        //printf("Stopping TLS\n");
        gnutls_bye((gnutls_session_t) session->client->tls, GNUTLS_SHUT_RDWR);
        gnutls_deinit((gnutls_session_t) session->client->tls);
        session->client->tls = NULL;
    }

    session->client->recv = NULL;
    session->client->send = NULL;
    return (0);
}


static void gnutls_logger_cb(int level, const char *message) {
    if (strlen(message) < 1) printf("GnuTLS<%d> empty debug mess\n", level);
    else printf("GnuTLS<%d>: %s\n", level, message);
}


// GnuTLS will call this function whenever there is a new audit log message.
static void gnutls_audit_cb(gnutls_session_t psess, const char* message) {
    (void) psess;
    printf("GnuTLS Audit: %s", message);
}

//------------------------------------------------------------------------//
// Standard module initialization function
rumblemodule rumble_module_init(void *master, rumble_module_info *modinfo) {
    fflush(stdout);
    modinfo->title       = "GNUTLS module";
    modinfo->description = "Enables STARTTLS transport for rumble.";
    modinfo->author      = "Humbedooh [humbedooh@users.sf.net]";

    rumble_debug(master, _gnutls, "Initializing %s (this may take a while)...", modinfo->title);


    const char * gcry_ver = gcry_check_version (GCRYPT_VERSION);
    if ( gcry_ver ) rumble_debug(master, _gnutls, "Libgcrypt=%s", gcry_ver);
    else {
        rumble_debug(master, _gnutls, "Libgcrypt version mismatch");
        return (EXIT_FAILURE);
    }

    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    //gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);


    const char * gnutls_ver = gnutls_check_version(NULL);
    if ( gnutls_ver ) rumble_debug(master, _gnutls, "Libgnutls=%s", gnutls_ver);
    else {
        rumble_debug(master, _gnutls, "Libgnutls version mismatch");
        return (EXIT_FAILURE);
    }




    if (init_server_dh(master)) return (EXIT_FAILURE);

    rumble_debug(master, _gnutls, "GnuTLS global init required.");

    if (gnutls_global_init()) {
        rumble_debug(master, _gnutls, "FAIL gnutls_global_init");
        return (EXIT_FAILURE);
    }

    rumble_debug(master, _gnutls, "TLS module init [OK]");


    // Enable logging (for debugging).
    gnutls_global_set_log_level(gnutls_log_level);
    gnutls_global_set_log_function(gnutls_logger_cb);
    // Enable logging (for auditing).
    gnutls_global_set_audit_log_function(gnutls_audit_cb);



    // Hook the module to STARTTLS requests.
    rumbleService *svc;
    svc = comm_serviceHandleExtern((masterHandle *) master, "smtp");
    if (svc) {
        rumble_service_add_command(svc, "STARTTLS", rumble_tls_start);
        rumble_service_add_capability(svc, "STARTTLS");
    }

    svc = comm_serviceHandleExtern((masterHandle *) master, "pop3");
    if (svc) {
        rumble_service_add_command(svc, "STLS", rumble_tls_start);
        rumble_service_add_capability(svc, "STLS");
    }

    svc = comm_serviceHandleExtern((masterHandle *) master, "imap4");
    if (svc) {
        rumble_service_add_command(svc, "STARTTLS", rumble_tls_start);
        rumble_service_add_capability(svc, "STARTTLS");
    }

    // Hook onto services closing connections
    rumble_hook_function(master, RUMBLE_HOOK_SMTP + RUMBLE_HOOK_CLOSE, rumble_tls_stop);
    rumble_hook_function(master, RUMBLE_HOOK_POP3 + RUMBLE_HOOK_CLOSE, rumble_tls_stop);
    rumble_hook_function(master, RUMBLE_HOOK_IMAP + RUMBLE_HOOK_CLOSE, rumble_tls_stop);
    return (EXIT_SUCCESS);   // Tell rumble that the module loaded okay.
}
