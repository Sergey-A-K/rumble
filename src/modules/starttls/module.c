
//  * File: module.c Author: Humbedooh

#include "../../rumble.h"
#include "../../comm.h"

#include <gnutls/gnutls.h>
#include <gnutls/ocsp.h>

#include <gcrypt.h>
#include <errno.h>



GCRY_THREAD_OPTION_PTHREAD_IMPL;

static const char * _gnutls = "GnuTLS";
static const char * certfile = "config/server.cert";
static const char * keyfile  = "config/server.key";
static const char * gnutls_defprio = "NORMAL"; // EXPORT ? NORMAL

#define ssl_session_timeout 3600 // One hour
static unsigned int dh_bits = 1024;
static masterHandle* myMaster = 0;





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
    session->client->tls_recv = NULL;
    session->client->tls_send = NULL;

    switch (session->_tflags & RUMBLE_THREAD_SVCMASK)
    {
        case RUMBLE_THREAD_SMTP: rumble_comm_send(session, "220 OK, starting TLS\r\n"); break;
        case RUMBLE_THREAD_POP3: rumble_comm_send(session, "+OK, starting TLS\r\n");    break;
        case RUMBLE_THREAD_IMAP: rumble_comm_printf(session, "%s OK Begin TLS negotiation now\r\n", extra); break;
    default: return (RUMBLE_RETURN_IGNORE);
    }

    rumble_debug(master, _gnutls, "<~> %s init...", session->client->addr);

    int ret = gnutls_init(&psess, GNUTLS_SERVER);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(master, _gnutls, "<~> %s session init FAILURE: <%s>", session->client->addr, gnutls_strerror_name(ret));
        return (RUMBLE_RETURN_FAILURE);
    }


    ret = gnutls_credentials_set(psess, GNUTLS_CRD_CERTIFICATE, master->_core.tls_credentials);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(master, _gnutls, "<~> %s credentials set FAILURE: <%s>", session->client->addr, gnutls_strerror_name(ret));
        return (RUMBLE_RETURN_FAILURE);
    }

    const char * errpos = 0;
    ret = gnutls_priority_set(psess, master->_core.tls_priority_cache);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(master, _gnutls, "<~> %s priority <%s> set <%s> FAILURE: <%s>",
            session->client->addr, gnutls_defprio, gnutls_strerror_name(ret), errpos);
        return (RUMBLE_RETURN_FAILURE);
    }

    gnutls_db_set_cache_expiration(psess, ssl_session_timeout);
    gnutls_certificate_server_set_request(psess, GNUTLS_CERT_REQUEST); // GNUTLS_CERT_IGNORE GNUTLS_CERT_REQUIRE
    gnutls_dh_set_prime_bits(psess, dh_bits);

#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
    rumble_debug(master, _gnutls, "Setting D-H prime minimum acceptable bits to %d", dh_bits);
#endif

    gnutls_transport_set_ptr(psess, (gnutls_transport_ptr_t) &session->client->socket);
    gnutls_transport_set_push_function(psess, data_push);
    gnutls_transport_set_pull_function(psess, data_pull);
    //gnutls_transport_set_pull_timeout_function(psess, pull_timeout_func);

    ret = gnutls_handshake(psess);
    if (ret == GNUTLS_E_DH_PRIME_UNACCEPTABLE) {
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
        rumble_debug(master, _gnutls, "Setting D-H prime minimum acceptable bits to %d", dh_bits*2);
#endif
        gnutls_dh_set_prime_bits(psess, dh_bits*2);
        ret = gnutls_handshake(psess);
    }

    if (ret != GNUTLS_E_SUCCESS) {
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
        rumble_debug(master, _gnutls, "<~> %s handshake FAILURE: %d <%s>", session->client->addr, ret, gnutls_strerror_name(ret));
#endif
        rumble_debug(master, _gnutls, "<~> %s session fail", session->client->addr);
        return (RUMBLE_RETURN_FAILURE);
    }

    session->client->tls_session = psess;
    session->client->tls_recv = (dummyTLS_recv) gnutls_record_recv;
    session->client->tls_send = (dummyTLS_send) gnutls_record_send;
// #if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
    rumble_debug(master, _gnutls, "<~> %s session ok", session->client->addr);
// #endif
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
    session->client->tls_recv = NULL;
    session->client->tls_send = NULL;

#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
    rumble_debug(myMaster, _gnutls, "<~> %s session stop", session->client->addr);
#endif

    return (0);
}

#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
static void gnutls_logger_cb(int level, const char *message) {
    if (strlen(message) < 1) rumble_debug(myMaster, _gnutls, "D%d: empty debug message!\n", level);
    else rumble_debug(myMaster, _gnutls, "D%d: %s", level, message);
}

// GnuTLS will call this function whenever there is a new audit log message.
static void gnutls_audit_cb(gnutls_session_t psess, const char* message) {
    (void) psess;
    rumble_debug(myMaster, _gnutls, "Audit: %s", message);
}
#endif

//------------------------------------------------------------------------//
// Standard module initialization function EXIT_FAILURE/EXIT_SUCCESS
rumblemodule rumble_module_init(void *master, rumble_module_info *modinfo) {
    myMaster = (masterHandle *) master;
    int ret = 0;
    fflush(stdout);

    myMaster->_core.tls_credentials = NULL;
    myMaster->_core.tls_priority_cache = NULL;
    myMaster->_core.tls_dh_params = NULL;

    modinfo->title       = "GnuTLS module";
    modinfo->description = "Enables STARTTLS transport for rumble.";
    modinfo->author      = "Humbedooh [humbedooh@users.sf.net]";

    rumble_debug(myMaster, _gnutls, "Initializing %s...", modinfo->title);

    const char * gcry_ver = gcry_check_version (GCRYPT_VERSION);
    if (!gcry_ver) {
        rumble_debug(myMaster, _gnutls, "LibGCRYPT version mismatch!");
        return (EXIT_FAILURE);
    }

    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);

    const char * gnutls_ver = gnutls_check_version(NULL);
    if (!gnutls_ver) {
        rumble_debug(myMaster, _gnutls, "GnuTLS version mismatch!");
        return (EXIT_FAILURE);
    }

    rumble_debug(myMaster, _gnutls, "LibGCRYPT version: <%s>, GnuTLS version: <%s>", gcry_ver, gnutls_ver);

    ret = gnutls_dh_params_init(&myMaster->_core.tls_dh_params);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(myMaster, _gnutls, "D-H params init FAILURE: <%s>", gnutls_strerror_name(ret));
        return (EXIT_FAILURE);
    }

    /*
    gnutls_sec_param = GNUTLS_SEC_PARAM_NORMAL, GNUTLS_SEC_PARAM_NORMAL, GNUTLS_SEC_PARAM_LEGACY
    if (!(dh_bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, gnutls_sec_param))){
        rumble_debug(myMaster, _gnutls, "gnutls_sec_param_to_pk_bits() failed");
        return (EXIT_FAILURE);
    } */

    ret = gnutls_dh_params_generate2(myMaster->_core.tls_dh_params, dh_bits);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(myMaster, _gnutls, "D-H generate2 FAILURE: <%s>", gnutls_strerror_name(ret));
        return (EXIT_FAILURE);
    }

    ret = gnutls_global_init();
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(myMaster, _gnutls, "Global init FAILURE: <%s>", gnutls_strerror_name(ret));
        return (EXIT_FAILURE);
    }

#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
    #ifndef GNUTLS_LOGLEVEL
    #define GNUTLS_LOGLEVEL 2
    #endif
    rumble_debug(myMaster, _gnutls, "Set log level %d", GNUTLS_LOGLEVEL);
    gnutls_global_set_log_level(GNUTLS_LOGLEVEL);           // Enable logging (for debugging)
    gnutls_global_set_log_function(gnutls_logger_cb);       // Register logging callback
    gnutls_global_set_audit_log_function(gnutls_audit_cb);  // Enable logging (for auditing)
#endif

    myMaster->_core.tls_credentials = calloc(1, sizeof(gnutls_certificate_credentials_t));

    ret = gnutls_certificate_allocate_credentials(&myMaster->_core.tls_credentials);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(myMaster, _gnutls, "Allocate certificate FAILURE: <%s>", gnutls_strerror_name(ret));
        return (EXIT_FAILURE);
    }

    const char * errpos;
    ret = gnutls_priority_init(&myMaster->_core.tls_priority_cache, gnutls_defprio, &errpos);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(myMaster, _gnutls, "Priority <%s> init FAILURE: <%s> pos <%s>",
            gnutls_defprio, gnutls_strerror_name(ret), errpos);
        return (EXIT_FAILURE);
    }

    ret = gnutls_certificate_set_x509_key_file(myMaster->_core.tls_credentials, certfile, keyfile, GNUTLS_X509_FMT_PEM);
    if (ret) { // GNUTLS_E_SUCCESS
        rumble_debug(myMaster, _gnutls, "Set cert <%s> and key <%s> FAILURE: <%s>",
            certfile, keyfile, gnutls_strerror_name(ret));
        return (EXIT_FAILURE);
    }

    ret = gnutls_certificate_set_x509_system_trust(myMaster->_core.tls_credentials);
    if (ret == 0) { // Not zero!
        rumble_debug(myMaster, _gnutls, "Set system trust for cert <%s> and key <%s> FAILURE: <%s>",
            certfile, keyfile, gnutls_strerror_name(ret));
        return (EXIT_FAILURE);
    }

    gnutls_certificate_set_dh_params(myMaster->_core.tls_credentials, myMaster->_core.tls_dh_params);

    rumble_debug(myMaster, _gnutls, "Registered key. Total certs: %d, priority: <%s>, D-H bits: %d",
        ret, gnutls_defprio, dh_bits);


    // Hook the module to STARTTLS requests.
    rumbleService * svc = comm_serviceHandleExtern(myMaster, "smtp");
    if (svc) {
        rumble_service_add_command(svc, "STARTTLS", rumble_tls_start);
        rumble_service_add_capability(svc, "STARTTLS");
    }

    svc = comm_serviceHandleExtern(myMaster, "pop3");
    if (svc) {
        rumble_service_add_command(svc, "STLS", rumble_tls_start);
        rumble_service_add_capability(svc, "STLS");
    }

    svc = comm_serviceHandleExtern(myMaster, "imap4");
    if (svc) {
        rumble_service_add_command(svc, "STARTTLS", rumble_tls_start);
        rumble_service_add_capability(svc, "STARTTLS");
    }

    // Hook onto services closing connections
    rumble_hook_function(myMaster, RUMBLE_HOOK_SMTP + RUMBLE_HOOK_CLOSE, rumble_tls_stop);
    rumble_hook_function(myMaster, RUMBLE_HOOK_POP3 + RUMBLE_HOOK_CLOSE, rumble_tls_stop);
    rumble_hook_function(myMaster, RUMBLE_HOOK_IMAP + RUMBLE_HOOK_CLOSE, rumble_tls_stop);
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
    rumble_debug(myMaster, _gnutls, "Added hooks. Init [OK]");
#endif
    return (EXIT_SUCCESS);
}
