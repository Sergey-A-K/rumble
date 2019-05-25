
//  * File: module.c Author: Humbedooh

#include "../../rumble.h"
#include "../../comm.h"

#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>

#include <gcrypt.h>
#include <errno.h>

#ifndef GNUTLS_LOGLEVEL
#define GNUTLS_LOGLEVEL 0
#endif

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static const char * _gnutls = "gnutls";
static const char * certfile = "config/server.cert";
static const char * keyfile  = "config/server.key";
static const char * gnutls_defprio = "NORMAL"; // EXPORT ? NORMAL

#define ssl_session_timeout 3600 // One hour
static unsigned int dh_bits = 1024;






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
    (void)arg;
    gnutls_session_t psess;

    session->client->tls_session =  NULL;
    session->client->recv = NULL;
    session->client->send = NULL;

    switch (session->_tflags & RUMBLE_THREAD_SVCMASK)
    {
        case RUMBLE_THREAD_SMTP: rumble_comm_send(session, "220 OK, starting TLS\r\n"); break;
        case RUMBLE_THREAD_POP3: rumble_comm_send(session, "+OK, starting TLS\r\n");    break;
        case RUMBLE_THREAD_IMAP: rumble_comm_printf(session, "%s OK Begin TLS negotiation now\r\n", extra); break;
    default:                     return (RUMBLE_RETURN_IGNORE);
    }

    rumble_debug(master, _gnutls, "GnuTLS negotiating with %s", session->client->addr);

    int ret = gnutls_init(&psess, GNUTLS_SERVER);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(master, _gnutls, "ERR GnuTLS session init: %s, addr: %s", gnutls_strerror_name(ret), session->client->addr);
        return (RUMBLE_RETURN_FAILURE);
    }


    ret = gnutls_credentials_set(psess, GNUTLS_CRD_CERTIFICATE, master->_core.tls_credentials);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(master, _gnutls, "ERR GnuTLS credentials cert set: %s, addr: %s", gnutls_strerror_name(ret), session->client->addr);
        return (RUMBLE_RETURN_FAILURE);
    }

    const char * errpos = 0;
    ret = gnutls_priority_set(psess, master->_core.tls_priority_cache);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(master, _gnutls, "GnuTLS priority [%s] set [%s] [%s] ERROR! Addr: %s", gnutls_defprio, gnutls_strerror_name(ret), errpos, session->client->addr);
        return (RUMBLE_RETURN_FAILURE);
    }

    gnutls_db_set_cache_expiration(psess, ssl_session_timeout);
    gnutls_certificate_server_set_request(psess, GNUTLS_CERT_REQUEST); // GNUTLS_CERT_IGNORE GNUTLS_CERT_REQUIRE
    gnutls_dh_set_prime_bits(psess, dh_bits);
    rumble_debug(master, _gnutls, "GnuTLS Setting D-H prime minimum acceptable bits to %d", dh_bits);

    gnutls_transport_set_ptr(psess, (gnutls_transport_ptr_t) &session->client->socket);
    gnutls_transport_set_push_function(psess, data_push);
    gnutls_transport_set_pull_function(psess, data_pull);
    //gnutls_transport_set_pull_timeout_function(psess, pull_timeout_func);

    ret = gnutls_handshake(psess);
    if (ret == GNUTLS_E_DH_PRIME_UNACCEPTABLE) {
        rumble_debug(master, _gnutls, "GnuTLS Setting D-H prime minimum acceptable bits to %d", dh_bits*2);
        gnutls_dh_set_prime_bits(psess, dh_bits*2);
        ret = gnutls_handshake(psess);
    }

    if (ret != GNUTLS_E_SUCCESS) {
        rumble_debug(master, _gnutls, "GnuTLS fandshake fail addr: %s", gnutls_strerror_name(ret), session->client->addr);
        session->client->tls_session = NULL;
        return (RUMBLE_RETURN_FAILURE);
    }

    session->client->tls_session = psess;
    session->client->recv = (dummyTLS_recv) gnutls_record_recv;
    session->client->send = (dummyTLS_send) gnutls_record_send;
    rumble_debug(master, _gnutls, "GnuTLS handshake to [%s] OK", session->client->addr);
    return (RUMBLE_RETURN_IGNORE);
}


// Generic STOPTLS handler (or called when a TLS connection is closed)
ssize_t rumble_tls_stop(sessionHandle *session, const char *junk) {
    (void)junk; // no warn
    if (session->client->tls_session) {
        gnutls_bye(session->client->tls_session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(session->client->tls_session);
        session->client->tls_session = NULL;
    }
    session->client->recv = NULL;
    session->client->send = NULL;
    return (0);
}


static void gnutls_logger_cb(int level, const char *message) {
    if (strlen(message) < 1) printf("GnuTLS<%d> empty debug mess\n", level);
    else printf("GnuTLS<%d>: %s", level, message);
}


// GnuTLS will call this function whenever there is a new audit log message.
static void gnutls_audit_cb(gnutls_session_t psess, const char* message) {
    (void) psess;
    printf("GnuTLS Audit: %s", message);
}

//------------------------------------------------------------------------//
// Standard module initialization function EXIT_FAILURE/EXIT_SUCCESS
rumblemodule rumble_module_init(void *master, rumble_module_info *modinfo) {
    masterHandle* myMaster = (masterHandle *) master;
    int ret = 0;
    fflush(stdout);

    myMaster->_core.tls_credentials = NULL;
    myMaster->_core.tls_priority_cache = NULL;
    myMaster->_core.tls_dh_params = NULL;

    modinfo->title       = "GnuTLS module";
    modinfo->description = "Enables STARTTLS transport for rumble.";
    modinfo->author      = "Humbedooh [humbedooh@users.sf.net]";

    rumble_debug(master, _gnutls, "Initializing %s (this may take a while)...", modinfo->title);

    const char * gcry_ver = gcry_check_version (GCRYPT_VERSION);
    if (!gcry_ver) {
        rumble_debug(master, _gnutls, "LibGCRYPT version mismatch");
        return (EXIT_FAILURE);
    }

    rumble_debug(master, _gnutls, "LibGCRYPT [%s]", gcry_ver);

    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);


    const char * gnutls_ver = gnutls_check_version(NULL);
    if (!gnutls_ver) {
        rumble_debug(master, _gnutls, "GnuTLS version mismatch");
        return (EXIT_FAILURE);
    }

    rumble_debug(master, _gnutls, "GnuTLS [%s]", gnutls_ver);


    ret = gnutls_dh_params_init(&myMaster->_core.tls_dh_params);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(master, _gnutls, "ERROR on D-H params init [%s]", gnutls_strerror_name(ret));
        return (EXIT_FAILURE);
    }

    rumble_debug(master, _gnutls, "Initialized server D-H parameters [%d]", dh_bits);

    /*
    gnutls_sec_param = GNUTLS_SEC_PARAM_NORMAL, GNUTLS_SEC_PARAM_NORMAL, GNUTLS_SEC_PARAM_LEGACY
    if (!(dh_bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, gnutls_sec_param))){
        rumble_debug(master, _gnutls, "gnutls_sec_param_to_pk_bits() failed");
        return (EXIT_FAILURE);
    } */

    ret = gnutls_dh_params_generate2(myMaster->_core.tls_dh_params, dh_bits);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(master, _gnutls, "ERROR on D-H generate2 [%s]", gnutls_strerror_name(ret));
        return (EXIT_FAILURE);
    }

    ret = gnutls_global_init();
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(master, _gnutls, "ERROR on global init [%s]", gnutls_strerror_name(ret));
        return (EXIT_FAILURE);
    }

    rumble_debug(master, _gnutls, "Global init okay");

    gnutls_global_set_log_level(GNUTLS_LOGLEVEL); // Enable logging (for debugging)
    gnutls_global_set_log_function(gnutls_logger_cb);
    gnutls_global_set_audit_log_function(gnutls_audit_cb); // Enable logging (for auditing)

    myMaster->_core.tls_credentials = calloc(1, sizeof(gnutls_certificate_credentials_t));

    ret = gnutls_certificate_allocate_credentials(&myMaster->_core.tls_credentials);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(master, _gnutls, "ERROR on allocate certificate [%s]", gnutls_strerror_name(ret));
        return (EXIT_FAILURE);
    }

    rumble_debug(master, _gnutls, "Using default session cipher/priority [%s]", gnutls_defprio);

    const char * errpos;
    ret = gnutls_priority_init(&myMaster->_core.tls_priority_cache, gnutls_defprio, &errpos);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(master, _gnutls, "ERROR on priority [%s] init [%s] pos [%s]", gnutls_defprio, gnutls_strerror_name(ret), errpos);
        return (EXIT_FAILURE);
    }

    ret = gnutls_certificate_set_x509_key_file(myMaster->_core.tls_credentials, certfile, keyfile, GNUTLS_X509_FMT_PEM);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(master, _gnutls, "ERROR on set cert=[%s] key=[%s] \"%s\"", certfile, keyfile, gnutls_strerror_name(ret));
        return (EXIT_FAILURE);
    }

    rumble_debug(master, _gnutls, "Registered cert/key");

    ret = gnutls_certificate_set_x509_system_trust(myMaster->_core.tls_credentials); //TODO check for zero
    rumble_debug(master, _gnutls, "Certs count [%d]", ret);

    gnutls_certificate_set_dh_params(myMaster->_core.tls_credentials, myMaster->_core.tls_dh_params);


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

    rumble_debug(master, _gnutls, "Module added hooks. Init completed!");

    return (EXIT_SUCCESS);
}
