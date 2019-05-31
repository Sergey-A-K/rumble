// printf("rumble_smtp, line %d\n", __LINE__);

#include "rumble.h"
#include "servers.h"
#include "comm.h"
#include "private.h"
#include "database.h"

#if (RUMBLE_DEBUG & RUMBLE_DEBUG_SMTP)
#define SMTP_LOG(x ...) rumble_debug(NULL, "smtp", x);
#else
#define SMTP_LOG(x ...)
#endif

const char *rumble_smtp_reply_code(unsigned int code) {
    switch (code)
    {
        case 200:       return ("200 OK\r\n");
        case 211:       return ("211 System status, or system help reply\r\n");
        case 214:       return ("214 Help message\r\n");
        case 220:       return ("220 <%s> (ESMTPSA) Service ready\r\n");
        case 221:       return ("221 <%s> Service closing transmission channel\r\n");
        case 221220:    return ("221 2.2.0 Service closing transmission channel\r\n");
        case 235:       return ("235 Authentication successful\r\n");
        case 250:       return ("250 Requested mail action okay, completed\r\n");
        case 250200:    return ("250 2.0.0 Requested mail action okay, completed\r\n");
        case 251:       return ("251 User not local; will forward to <forward-path>\r\n");
        case 354:       return ("354 Start mail input; end with <CRLF>.<CRLF>\r\n");
        case 421:       return ("421 <domain> Service not available, closing transmission channel\r\n");
        case 421422:    return ("421 4.2.2 Transaction timeout exceeded, closing transmission channel\r\n");
        case 450:       return ("450 Requested mail action not taken: mailbox unavailable\r\n");
        case 451:       return ("451 Requested action aborted: local error in processing\r\n");
        case 452:       return ("452 Requested action not taken: insufficient system storage\r\n");
        case 500:       return ("500 Syntax error, command unrecognized\r\n");
        case 501:       return ("501 Syntax error in parameters or arguments\r\n");
        case 502:       return ("502 Command not implemented\r\n");
        case 503:       return ("503 Bad sequence of commands\r\n");
        case 504:       return ("504 Command parameter not implemented\r\n");
        case 521:       return ("521 <domain> does not accept mail (see rfc1846)\r\n");
        case 530:       return ("530 Access denied\r\n");
        case 550:       return ("550 Requested action not taken: mailbox unavailable\r\n");
        case 551:       return ("551 User not local; please try <forward-path>\r\n");
        case 552:       return ("552 Requested mail action aborted: exceeded storage allocation\r\n");
        case 553:       return ("553 Requested action not taken: mailbox name not allowed\r\n");
        case 554:       return ("554 Transaction failed\r\n");
        case 504552:    return ("504 5.5.2 HELO rejected: A fully-qualified hostname is required.\r\n");
        default:        return ("200 OK\r\n");
    }
}


// Run hooks for data filtering prior to adding the message to the queue
const char * queue_query = "INSERT INTO queue (id,fid, sender, recipient, flags) VALUES (NULL,%s,%s,%s,%s)";




void rumble_master_init_smtp(masterHandle *master) {
    (void) master;
    const char * smtpport = rumble_config_str(master, "smtpport");
    rumbleService * svc = comm_registerService(master, "smtp", rumble_smtp_init, smtpport, RUMBLE_INITIAL_THREADS);
    // Set stack size for service to 128kb (should be enough)
    svc->settings.stackSize = 128 * 1024;
    if (rumble_config_int(master, "enablesmtp")) {
        SMTP_LOG("Launching SMTP service");
        int rc = comm_startService(svc);
        if (rc) {
            // Commands
            SMTP_LOG("Adding SMTP commands and capabilities");
            rumble_service_add_command(svc, "MAIL", rumble_server_smtp_mail);
            rumble_service_add_command(svc, "RCPT", rumble_server_smtp_rcpt);
            rumble_service_add_command(svc, "HELO", rumble_server_smtp_helo);
            rumble_service_add_command(svc, "EHLO", rumble_server_smtp_ehlo);
            rumble_service_add_command(svc, "NOOP", rumble_server_smtp_noop);
            rumble_service_add_command(svc, "DATA", rumble_server_smtp_data);
            rumble_service_add_command(svc, "VRFY", rumble_server_smtp_vrfy);
            rumble_service_add_command(svc, "RSET", rumble_server_smtp_rset);
            rumble_service_add_command(svc, "AUTH", rumble_server_smtp_auth);
            // Capabilities
            rumble_service_add_capability(svc, "EXPN");
            rumble_service_add_capability(svc, "VRFY");
            rumble_service_add_capability(svc, "PIPELINING");
            rumble_service_add_capability(svc, "8BITMIME");
            rumble_service_add_capability(svc, "AUTH LOGIN PLAIN");
            rumble_service_add_capability(svc, "DSN");
            rumble_service_add_capability(svc, "SIZE");
            rumble_service_add_capability(svc, "ENHANCEDSTATUSCODES");
            rumble_service_add_capability(svc, "XVERP");
            svc->cue_hooks  = cvector_init();
            svc->init_hooks = cvector_init();
            svc->exit_hooks = cvector_init();
            SMTP_LOG("Adding SMTP commands OK");
        } else {
            SMTP_LOG("ABORT: Couldn't create socket for SMTP!");
            exit(EXIT_SUCCESS);
        }
    }
}



//    Main loop

void *rumble_smtp_init(void *T) {
    rumbleThread    *thread = (rumbleThread *) T;
    rumbleService   *svc = thread->svc;
    masterHandle    *master = svc->master;
    // Initialize a session handle and wait for incoming connections.
    sessionHandle   session;
    sessionHandle   *sessptr = &session;
    sessionHandle   *s;
    d_iterator      iter;
    c_iterator      citer;
    svcCommandHook  *hook;

    rumble_rw_start_read(master->domains.rrw);
    session.dict = dvector_init();
    session.recipients = dvector_init();
    session.sender = 0;
    session.client = (clientHandle *) malloc(sizeof(clientHandle));
    session.client->tls_session = 0;
    session.client->tls_recv = 0;
    session.client->tls_send = 0;
    session.client->rejected = 0;
    session._master = svc->master;
    session._svc = svc;
    session._tflags = RUMBLE_THREAD_SMTP; // Identify the thread/session as SMTP
    const char * myName = rumble_get_dictionary_value(master->_core.conf, "servername");
    myName = myName ? myName : "??";
    rumble_rw_stop_read(master->domains.rrw);

    while (1) {
        comm_accept(svc->socket, session.client);
        pthread_mutex_lock(&svc->mutex); // Check for return 0 - ok
        thread->status = 1;
        dvector_add(svc->handles, (void *) sessptr);
        svc->traffic.sessions++;
        pthread_mutex_unlock(&svc->mutex);
        session.flags = 0;
        session._tflags += 0x00100000; // job count ( 0 through 4095)
        session.sender = 0;
        session._svc = svc;
        session.client->rejected = 0;
        SMTP_LOG("Accepted connection from %s on SMTP", session.client->addr);
        ssize_t rc = RUMBLE_RETURN_OKAY;
        // Check for hooks on accept()
        rc = rumble_server_schedule_hooks(master, sessptr, RUMBLE_HOOK_ACCEPT + RUMBLE_HOOK_SMTP);

        if (rc == RUMBLE_RETURN_OKAY) {
            rumble_comm_printf(sessptr, rumble_smtp_reply_code(220), myName); // Hello!
        } else {
            svc->traffic.rejections++;
            session.client->rejected = 1;
            SMTP_LOG("SMTP session was blocked by an external module!");
        }

        while (rc != RUMBLE_RETURN_FAILURE) {
            rc = 421; // Default: Service not available, closing...
            char * line = rumble_comm_read(sessptr);
            if (!line) break;
            rc = 500; // Default: Syntax error, command unrecognized
            char cmd[9], arg[1001];
            memset(cmd, 0, 9);
            memset(arg, 0, 1001);

            // Parse incoming commands
            if (sscanf(line, "%8[^\t \r\n]%*[ \t]%1000[^\r\n]", cmd, arg)) {
                rumble_string_upper(cmd);
                SMTP_LOG("%s said: %s %s", session.client->addr, cmd, arg);
                if (!strcmp(cmd, "QUIT")) { // bye!
                    rc = RUMBLE_RETURN_FAILURE;
                    free(line);
                    break;
                } else {
                    cforeach((svcCommandHook *), hook, svc->commands, citer) { // Call hook
                        if (!strcmp(cmd, hook->cmd)) rc = hook->func(master, &session, arg, 0);
                    }
                }
            }
            free(line);

            if (rc == RUMBLE_RETURN_IGNORE) {
                SMTP_LOG("a module replied to %s instead of me", session.client->addr);
                // Skip to next line.
                continue;
            } else if (rc == RUMBLE_RETURN_FAILURE) {
                svc->traffic.rejections++;
                session.client->rejected = 1;
                break; // Abort!
            } else {
                // Bad command thing.
                rumble_comm_send(sessptr, rumble_smtp_reply_code(rc));
                SMTP_LOG("I said to %s: %s", session.client->addr, rumble_smtp_reply_code(rc));
            }
        }
        SMTP_LOG("Closing connection from %s on SMTP", session.client->addr);
        if (rc == 421) { // Transaction timeout exceeded
            rumble_comm_send(sessptr, rumble_smtp_reply_code(421422));
        } else { //Service closing transmission channel. Bye!
            rumble_comm_send(sessptr, rumble_smtp_reply_code(221220));
        }

        // Run pre-close hooks and close socket
        rumble_server_schedule_hooks(master, sessptr, RUMBLE_HOOK_CLOSE + RUMBLE_HOOK_SMTP);
        comm_addEntry(svc, session.client->brecv + session.client->bsent, session.client->rejected);
        disconnect(session.client->socket);

        // Clean up after the session
        rumble_clean_session(sessptr);

        // ================================================== //
        // ** Update thread statistics **
        pthread_mutex_lock(&(svc->mutex));

        dforeach((sessionHandle *), s, svc->handles, iter) {
            if (s == sessptr) {
                dvector_delete(&iter);
                break;
            }
        }

        // ================================================== //
        // Check if we were told to go kill ourself::(

        if ((session._tflags & RUMBLE_THREAD_DIE) || svc->enabled != 1 || thread->status == -1) {

#if RUMBLE_DEBUG & RUMBLE_DEBUG_THREADS
        SMTP_LOG("<smtp::threads>I (%#lx) was told to die :(", (uintptr_t) pthread_self());
#endif
            rumbleThread * t;
            cforeach((rumbleThread *), t, svc->threads, citer) {
                if (t == thread) {
                    cvector_delete(&citer);
                    break;
                }
            }
            pthread_mutex_unlock(&svc->mutex);
            pthread_exit(0);
        }
        pthread_mutex_unlock(&svc->mutex);
        // What for?
        myName = rumble_get_dictionary_value(master->_core.conf, "servername");
        myName = myName ? myName : "??";
    } // Loop
    pthread_exit(0);

}


// Command specific routines
ssize_t rumble_server_smtp_mail(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    (void)extra_data;
    // First, check for the right sequence of commands.
    if (!(session->flags & RUMBLE_SMTP_HAS_HELO)) return (503); // We need a HELO/EHLO first
    if ((session->flags & RUMBLE_SMTP_HAS_MAIL)) return (503);  // And we shouldn't have gotten a MAIL FROM yet

    // Try to fetch standard syntax: MAIL FROM: [whatever] <user@domain.tld>
    session->sender = rumble_parse_mail_address(parameters);
    if (session->sender) {
        // Fire events scheduled for pre-processing run
        ssize_t rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
            RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_BEFORE + RUMBLE_CUE_SMTP_MAIL, parameters);
        if (rc != RUMBLE_RETURN_OKAY) {
            // Something went wrong, let's clean up and return.
            rumble_free_address(session->sender);
            session->sender = 0;
            return (rc);
        }
        uint32_t max = rumble_config_int(master, "messagesizelimit");
        uint32_t size = atoi(rumble_get_dictionary_value(session->sender->flags, "SIZE"));
        if (max != 0 && size != 0 && size > max) {
            rumble_free_address(session->sender);
            session->sender = 0;
            return (552); // message too big
        }
        // Look for a BATV signature, and if found, confirm that it's valid
        if (strstr(session->sender->tag, "prvs=")) {
            rumbleKeyValuePair * entry;
            d_iterator iter;
            dforeach((rumbleKeyValuePair *), entry, master->_core.batv, iter) {
                if (!strcmp(entry->key, session->sender->tag)) {
                    dvector_delete(&iter);
                    session->flags |= RUMBLE_SMTP_HAS_BATV;
                    free((char*)entry->key);
                    free(entry);
                    break;
                }
            }
            if (!(session->flags & RUMBLE_SMTP_HAS_BATV)) {
                rumble_free_address(session->sender);
                session->sender = 0;
                return (530); // bounce is invalid or too old
            }
        }
        // Check if it's a supposed (but fake or very very old) bounce
        if (!strlen(session->sender->domain) && !(session->flags & RUMBLE_SMTP_HAS_BATV)) {
            rumble_free_address(session->sender);
            session->sender = 0;
            return (530); // bounce is invalid or too old
        }

        // Fire post-processing hooks
        rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
            RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_SMTP_MAIL, parameters);
        if (rc != RUMBLE_RETURN_OKAY) return (rc);
        session->flags |= RUMBLE_SMTP_HAS_MAIL;
        return (250);
    }
    return (501); // Syntax error in MAIL FROM parameter
}


ssize_t rumble_server_smtp_rcpt(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    (void)extra_data;
    // First, check for the right sequence of commands. */
    if (!(session->flags & RUMBLE_SMTP_HAS_MAIL)) return (503);

    // Allocate stuff and start parsing
    address * recipient = rumble_parse_mail_address(parameters);
    if (recipient) {
        dvector_add(session->recipients, recipient);
        // Fire events scheduled for pre-processing run
        ssize_t rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
            RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_BEFORE + RUMBLE_CUE_SMTP_RCPT, parameters);
        if (rc != RUMBLE_RETURN_OKAY) {
            dvector_pop(session->recipients); // pop the last element from the vector
            rumble_free_address(recipient);   // flush the memory
            recipient = 0;
            return (rc);
        }
        // Check if recipient is local
        uint32_t isLocalDomain = rumble_domain_exists(recipient->domain);
        uint32_t isLocalUser = isLocalDomain ? rumble_account_exists(session, recipient->user, recipient->domain) : 0;
        if (isLocalUser) {
            SMTP_LOG("Running local RCPT for %s@%s (%s)",
                recipient->user, recipient->domain, recipient->raw);
            //If everything went fine, set the RCPT flag and return with code 250. ;
            //>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<< ;
            //>>>>>>>>>>>>>>>>>>>>>> !!! TODO !!! <<<<<<<<<<<<<<<<<<<<<<< ;
            //Check if user has space in mailbox for this msg! ;
            //>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<< ;
            rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
                RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_SMTP_RCPT, parameters);
            if (rc != RUMBLE_RETURN_OKAY) {
                dvector_pop(session->recipients); // pop the last element from the vector
                rumble_free_address(recipient);   // flush the memory
                recipient = 0;
                return (rc);
            }
            SMTP_LOG("Message from %s can be delivered to <%s@%s>.",
                session->client->addr, recipient->user, recipient->domain);
            session->flags |= RUMBLE_SMTP_HAS_RCPT;
            return (250);
        }
        // If rec isn't local, check if client is allowed to relay
        if (!isLocalDomain) {
            if (session->flags & RUMBLE_SMTP_CAN_RELAY) {
                if (rumble_config_int(master, "blockoutgoingmail")) {
                    rc = RUMBLE_RETURN_FAILURE;
                } else {
                    // Check for domain-specific blocking
                    SMTP_LOG("checking domain options for %s", session->sender->domain);
                    rumble_domain * dmn = rumble_domain_copy(session->sender->domain);
                    if (dmn) {
                        SMTP_LOG("Flags for %s are: %X", dmn->name, dmn->flags);
                        if (dmn->flags && RUMBLE_DOMAIN_NORELAY) rc = RUMBLE_RETURN_FAILURE;
                        rumble_domain_free(dmn);
                    } else {
                        // Fire events scheduled for pre-processing run
                        SMTP_LOG("domain %s wasn't found?!", session->sender->domain);
                        rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
                            RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_SMTP_RCPT, parameters);
                    }
                }
                if (rc != RUMBLE_RETURN_OKAY) {
                    dvector_pop(session->recipients); // pop the last element from the vector
                    rumble_free_address(recipient);   // flush the memory
                    recipient = 0;
                    return (rc);
                }
                session->flags |= RUMBLE_SMTP_HAS_RCPT;
                SMTP_LOG("Message from %s can be delivered to <%s@%s> (relay).",
                    session->client->addr, recipient->user, recipient->domain);
                return (251);
            }
            // Not local and no relaying allowed, return 530
            ((rumbleService*)session->_svc)->traffic.rejections++;
            session->client->rejected = 1;
            dvector_pop(session->recipients);
            rumble_free_address(recipient);
            recipient = 0;
            return (530);
        }
        // Domain is local but user doesn't exist, return 550
        dvector_pop(session->recipients);
        rumble_free_address(recipient);
        recipient = 0;
        ((rumbleService*)session->_svc)->traffic.rejections++;
        session->client->rejected = 1;
        return (550);
    } // else SMTP_LOG("...", parameters);
    return (501); // Syntax error in RCPT TO parameter
}

ssize_t rumble_server_smtp_helo(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    (void)extra_data;
    ssize_t rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
        RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_BEFORE + RUMBLE_CUE_SMTP_HELO, parameters);
    if (rc != RUMBLE_RETURN_OKAY) return (rc);
    int strictHelo = atoi(rumble_get_dictionary_value(master->_core.conf, "enforcefqdn")); // TODO Drop this ?
    if (strictHelo) {

        SMTP_LOG("rumble_server_smtp_helo: EnforceFQDN is %u", strictHelo);
        char tmp[130];
        rc = sscanf(parameters, "%128[%[a-zA-Z0-9%-].%1[a-zA-Z0-9%-]%1[a-zA-Z0-9.%-]", tmp, tmp, tmp);
        if (rc < 3) {
            SMTP_LOG("rumble_server_smtp_helo: Bad HELO: %s", parameters);
            return (504552); // simple test for FQDN
        }
    }
    session->flags |= RUMBLE_SMTP_HAS_HELO;
    rumble_add_dictionary_value(session->dict, "helo", parameters);
    return (250);
}


ssize_t rumble_server_smtp_ehlo(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    (void)extra_data;
    char        *el;
    c_iterator  iter;

    ssize_t rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
        RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_BEFORE + RUMBLE_CUE_SMTP_HELO, parameters);
    if (rc != RUMBLE_RETURN_OKAY) return (rc);

    int strictHelo = atoi(rumble_get_dictionary_value(master->_core.conf, "enforcefqdn")); // TODO Drop this ?
    if (strictHelo) {
        SMTP_LOG("rumble_server_smtp_ehlo: EnforceFQDN is %u", strictHelo);
        char * tmp = (char*)malloc(128);
        rc = sscanf(parameters, "%128[%[a-zA-Z0-9%-].%1[a-zA-Z0-9%-]%1[a-zA-Z0-9.%-]", tmp, tmp, tmp);
        free(tmp);
        if (rc < 3) {
            SMTP_LOG("rumble_server_smtp_ehlo: Bad HELO: %s", parameters);
            return (504552); // simple test for FQDN
        }
    }
    session->flags |= RUMBLE_SMTP_HAS_EHLO;
    rumble_comm_send(session, "250-Extended commands follow\r\n");
    cforeach((char *), el, ((rumbleService*)session->_svc)->capabilities, iter) {
        rumble_comm_printf(session, "250-%s\r\n", el);
    }
    rumble_comm_send(session, "250 Done\r\n");
    rumble_add_dictionary_value(session->dict, "helo", parameters);
    return (RUMBLE_RETURN_IGNORE);
}

ssize_t rumble_server_smtp_data(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    (void)extra_data;
    address     *el;
    d_iterator  iter;
    // First, check for the right sequence of commands.
    if (!(session->flags & RUMBLE_SMTP_HAS_RCPT)) return (503);
    ssize_t rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
        RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_BEFORE + RUMBLE_CUE_SMTP_DATA, parameters);
    if (rc != RUMBLE_RETURN_OKAY) return (rc);

    // Make a unique filename and try to open the storage folder for writing
    char * fid = rumble_create_filename();
    const char * sf = rumble_config_str(master, "storagefolder");
    char * filename = (char *) calloc(1, strlen(sf) + 26); // TODO Check for
    if (!filename) merror();
    sprintf(filename, "%s/%s", sf, fid);
    SMTP_LOG("Writing to file %s...\n", filename);
    FILE * fp = fopen(filename, "wb");
    if (!fp) {
        SMTP_LOG("Error: Couldn't open file <%s> for writing", filename);
        free(fid);
        free(filename);
        return (451); // Couldn't open file for writing :/
    }
    // Add the server signature
    char * log = (char *) calloc(1, 1024);
    if (!log) merror();
    char * now = rumble_mtime(); // TODO Localtime or UTC ? Check for
    // sprintf(log, "Received: from %s <%s> by %s (rumble) with ESMTPA id <%s>; %s\r\n",
    sprintf(log, "Received: from localhost by %s with ESMTPA id <%s>; %s\r\n",
        // spy hack :)
        // rumble_get_dictionary_value(session->dict, "helo"),
        // session->client->addr,
        rumble_config_str(master, "servername"),
        fid,
        now);
    free(now);
    fwrite(log, strlen(log), 1, fp);
    free(log);
    rumble_comm_send(session, rumble_smtp_reply_code(354));
    // Save the message
    while (1) {
        // Check for broken connection
        char * line = rumble_comm_read(session);
        if (!line) {
            fclose(fp);
            free(fid);
            free(filename);
            return (RUMBLE_RETURN_FAILURE);
        }
        if (!strcmp(line, ".\r\n")) {
            free(line);
            // We're done here.
            break;
        }
        if (fwrite(line, strlen(line), 1, fp) != 1) {
            // Writing failed?
            free(line);
            fclose(fp);
            free(fid);
            free(filename);
            return (452);
        } else {
            free(line);
        }
    }
    fclose(fp);
    // Run hooks for data filtering prior to adding the message to the queue
    rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
        RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_SMTP_DATA, filename);
    if (rc == RUMBLE_RETURN_OKAY) {
        dforeach((address *), el, session->recipients, iter) {
            // sprintf(tmp, "<%s>", user);
            //char *sql = "INSERT INTO queue (id,fid, sender, recipient, flags) VALUES (NULL,%s,%s,%s,%s)";
            //sprintf(sql, "<%s>", user);
            radb_run_inject(master->_core.mail, queue_query, fid,
                session->sender->raw, el->raw, session->sender->_flags);
        }
    }
    free(filename);
    free(fid);
    return (250);
}


ssize_t rumble_server_smtp_rset(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    (void)master; (void)extra_data;
    // Fire events scheduled for pre-processing run
    ssize_t rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
        RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_BEFORE + RUMBLE_CUE_SMTP_RSET, parameters);
    if (rc != RUMBLE_RETURN_OKAY) return (rc);
    // Reset the session handle
    session->flags = session->flags & RUMBLE_SMTP_HAS_EHLO; // don't lose the HELO/EHLO flag
    rumble_clean_session(session);
    // Fire post-processing hooks
    rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
        RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_SMTP_HELO, parameters);
    if (rc != RUMBLE_RETURN_OKAY) return (rc);
    else return (250);
}


ssize_t rumble_server_smtp_vrfy(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    (void)master; (void)extra_data;
    char * user   = (char*)calloc(1, 129);
    char * domain = (char*)calloc(1, 129);
    if (sscanf(parameters, "%128[^@\"]@%128[^\"]", user, domain)) {
        // Fire events scheduled for pre-processing run
        ssize_t rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
            RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_BEFORE + RUMBLE_CUE_SMTP_VRFY, parameters);
        if (rc != RUMBLE_RETURN_OKAY) return (rc);
        // Check if account exists */
        return (rumble_account_exists(session, user, domain) ? 250 : 550);
    } else return (501);
}


ssize_t rumble_server_smtp_noop(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    (void)master; (void)extra_data;
    // Fire events scheduled for pre-processing run
    ssize_t rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
        RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_BEFORE + RUMBLE_CUE_SMTP_NOOP, parameters);
    if (rc != RUMBLE_RETURN_OKAY) return (rc);
    // Do...nothing ;
    // Fire post-processing hoo
    rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
        RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_SMTP_NOOP, parameters);
    if (rc != RUMBLE_RETURN_OKAY) return (rc);
    return (250);
}


ssize_t rumble_server_smtp_auth(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    (void)master; (void)extra_data;
    ssize_t rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
        RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_BEFORE + RUMBLE_CUE_SMTP_AUTH, parameters);
    if (rc != RUMBLE_RETURN_OKAY) return (rc);

    char method[31], digest[1025];
    memset(method, 0, 31);
    memset(digest, 0, 1025);
    if (sscanf(parameters, "%30s %1024s", method, digest) < 1) return (501);
    rumble_string_lower(method);
    char * pass = "";
    char * user = "";
    address * addr = 0;
    rumble_mailbox * OK = 0;

    // LOGIN method
    if (!strcmp(method, "login")) { // TODO Upper and use const ?
        rumble_comm_send(session, "334 VXNlcm5hbWU6\r\n"); // Username
        char * line = rumble_comm_read(session);
        if (!sscanf(line, "%s", digest)) user = "";
        else user = rumble_decode_base64(digest);
        free(line);
        rumble_comm_send(session, "334 UGFzc3dvcmQ6\r\n"); // Password
        line = rumble_comm_read(session);
        if (!sscanf(line, "%s", digest)) pass = "";
        else pass = rumble_decode_base64(digest);
        free(line);
        sprintf(digest, "<%s>", user);
        addr = rumble_parse_mail_address(digest);
        SMTP_LOG("%s trying to auth login with [%s]", session->client->addr, user);
        if (addr) OK = rumble_account_data_auth(0, addr->user, addr->domain, pass);
        free(user);
        strcpy(digest, pass);
        free(pass);
        pass = digest;
        rumble_free_address(addr);
        addr = 0;
    }

    if (!strcmp(method, "plain")) { // PLAIN method
        char * buffer = rumble_decode_base64(digest);
        user = buffer + 1;
        pass = buffer + 2 + strlen(user);
        sprintf(digest, "<%s>", user);
        addr = rumble_parse_mail_address(digest);
        SMTP_LOG("%s trying to auth plain with [%s]", session->client->addr, user);
        if (addr) OK = rumble_account_data_auth(0, addr->user, addr->domain, pass);
        free(buffer);
        rumble_free_address(addr);
        addr = 0;
    }

    rc = rumble_service_schedule_hooks((rumbleService*)session->_svc, session,
        RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_SMTP_AUTH, (const char*)OK);

    if (OK) {
        session->flags |= RUMBLE_SMTP_CAN_RELAY;
        rumble_free_account(OK);
        free(OK);
        return (235);
    } else {
        session->flags -= (session->flags & RUMBLE_SMTP_CAN_RELAY);
        if (rc == RUMBLE_RETURN_FAILURE) return rc;
        return (530);
    }
}
