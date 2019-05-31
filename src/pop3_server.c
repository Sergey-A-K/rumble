#include "rumble.h"
#include "servers.h"
#include "comm.h"

#include "private.h"
#include "mailman.h"


// #if (RUMBLE_DEBUG & RUMBLE_DEBUG_POP3)
//         rumble_debug(NULL, "pop3", );
// #endif

#define POP3LOG(x ...) rumble_debug(NULL, "pop3", x);
#define POP3TRACE(x ...) rumble_debug(NULL, "pop3", x);
// #define POP3TRACE(x)
const char *rumble_pop3_reply_code(unsigned int code) {
    switch (code) {
        case 101:   return ("+OK <%s> Greetings!\r\n");
        case 102:   return ("+OK Closing transmission channel.\r\n");
        case 103:   return ("-ERR Connection timed out!\r\n");
        case 104:   return ("+OK\r\n");
        case 105:   return ("-ERR Unrecognized command.\r\n");
        case 106:   return ("-ERR Wrong credentials given.\r\n");
        case 107:   return ("-ERR Invalid syntax.\r\n");
        case 108:   return ("-ERR Couldn't open folder INBOX!\r\n");
        case 109:   return ("-ERR Couldn't open letter no.\r\n");
        case 110:   return ("-ERR No such letter.\r\n");

    default:
        return ("+OK\r\n");
    }
}


void rumble_master_init_pop3(masterHandle *master) {
    (void) master;
    const char * pop3port = rumble_config_str(master, "pop3port");
    rumbleService * svc = comm_registerService(master, "pop3", rumble_pop3_init, pop3port, RUMBLE_INITIAL_THREADS);
    // Set stack size for service to 256kb (should be enough)
    svc->settings.stackSize = 256 * 1024;
    if (rumble_config_int(master, "enablepop3")) {
        POP3LOG("Launching POP3 service...");
        int rc = comm_startService(svc);
        if (rc) {
            POP3LOG("Adding POP3 commands and capabilities");
            rumble_service_add_command(svc, "CAPA", rumble_server_pop3_capa);
            rumble_service_add_command(svc, "USER", rumble_server_pop3_user);
            rumble_service_add_command(svc, "PASS", rumble_server_pop3_pass);
            rumble_service_add_command(svc, "TOP", rumble_server_pop3_top);
            rumble_service_add_command(svc, "UIDL", rumble_server_pop3_uidl);
            rumble_service_add_command(svc, "DELE", rumble_server_pop3_dele);
            rumble_service_add_command(svc, "RETR", rumble_server_pop3_retr);
            rumble_service_add_command(svc, "LIST", rumble_server_pop3_list);
            rumble_service_add_command(svc, "STAT", rumble_server_pop3_stat);
            // Capabilities
            rumble_service_add_capability(svc, "TOP");
            rumble_service_add_capability(svc, "UIDL");
            rumble_service_add_capability(svc, "PIPELINING");
            svc->cue_hooks  = cvector_init();
            svc->init_hooks = cvector_init();
            svc->exit_hooks = cvector_init();
            POP3LOG("Adding POP3 commands OK");
        } else {
            POP3LOG("ABORT: Couldn't create socket for POP3!");
            exit(EXIT_SUCCESS);
        }
    }
}


// Main loop
void *rumble_pop3_init(void *T) {

    rumbleThread    *thread = (rumbleThread *) T;
    rumbleService   *svc = thread->svc;
    masterHandle    *master = svc->master;
    // Initialize a session handle and wait for incoming connections.
    sessionHandle   session;
    sessionHandle   *sessptr = &session;

    session.dict = dvector_init();
    session.recipients = dvector_init();
    session._svcHandle = (accountSession *) malloc(sizeof(accountSession));
    session.client = (clientHandle *) malloc(sizeof(clientHandle));
    session._master = svc->master;
    session._svc = svc;
    accountSession * pops = (accountSession *) session._svcHandle;
    pops->account = 0;
    pops->bag = 0;
    pops->folder = 0;
    session._tflags = RUMBLE_THREAD_POP3; // Identify the thread/session as POP3
    const char * myName = rumble_get_dictionary_value(master->_core.conf, "servername");
    myName = myName ? myName : "??";
    c_iterator      citer;
    while (1) {
        comm_accept(svc->socket, session.client);
        pthread_mutex_lock(&svc->mutex);
        dvector_add(svc->handles, (void *) sessptr);
        svc->traffic.sessions++;
        pthread_mutex_unlock(&svc->mutex);
        session.flags = 0;
        session._tflags += 0x00100000; // job count ( 0 through 4095)
        session.sender = 0;
        session._svc = svc;
        session.client->rejected = 0;
        pops->account = 0;
        pops->bag = 0;
        pops->folder = 0;
        POP3LOG("Accepted connection from %s on POP3", session.client->addr);

        // Check for hooks on accept()
        ssize_t rc = RUMBLE_RETURN_OKAY;
        rc = rumble_server_schedule_hooks(master, sessptr, RUMBLE_HOOK_ACCEPT + RUMBLE_HOOK_POP3);
        if (rc == RUMBLE_RETURN_OKAY) rumble_comm_printf(sessptr, rumble_pop3_reply_code(101), myName); // Hello!
        else {
            svc->traffic.rejections++;
            session.client->rejected = 1;
        }

        // Parse incoming commands
        char * cmd = (char *) malloc(9);
        char * arg = (char *) malloc(1024);
        if (!cmd || !arg) merror();

        while (rc != RUMBLE_RETURN_FAILURE) {
            memset(cmd, 0, 9);
            memset(arg, 0, 1024);
            char * line = rumble_comm_read(sessptr);
            rc = 421;
            if (!line) break; // Abort!
            rc = 105; //105  ERR Unrecognized command
            if (sscanf(line, "%8[^\t \r\n]%*[ \t]%1000[^\r\n]", cmd, arg)) {
                rumble_string_upper(cmd);
                POP3TRACE("%s said: %s %s", session.client->addr, cmd, arg);
                if (!strcmp(cmd, "QUIT")) {
                    rc = RUMBLE_RETURN_FAILURE;
                    free(line);
                    break;
                }  // bye!
                svcCommandHook * hook;
                cforeach((svcCommandHook *), hook, svc->commands, citer) {
                    if (!strcmp(cmd, hook->cmd)) rc = hook->func(master, &session, arg, 0);
                }
            }
            free(line);
            if (rc == RUMBLE_RETURN_IGNORE) continue; // Skip to next line.
            else if (rc == RUMBLE_RETURN_FAILURE) {
                svc->traffic.rejections++;
                session.client->rejected = 1;
                break; // Abort!
            } else rumble_comm_send(sessptr, rumble_pop3_reply_code(rc)); // Bad command thing.
        } // while

        // Cleanup
        POP3LOG("Closing connection from %s on POP3", session.client->addr);

        if (rc == 421) rumble_comm_send(sessptr, rumble_pop3_reply_code(103)); // timeout!
        else rumble_comm_send(sessptr, rumble_pop3_reply_code(102)); // bye!
        // Close socket and run pre-close hooks.

        rumble_server_schedule_hooks(master, sessptr, RUMBLE_HOOK_CLOSE + RUMBLE_HOOK_POP3);
        comm_addEntry(svc, session.client->brecv + session.client->bsent, session.client->rejected);
        disconnect(session.client->socket);
        // Start cleaning up after the session
        free(arg);
        free(cmd);
        rumble_clean_session(sessptr);
        mailman_commit(pops->bag, pops->folder, 1); // Delete letters marked "expunged" to prevent IMAP mixup
        rumble_free_account(pops->account);
        mailman_close_bag(pops->bag);
        // Update the thread stats
        pthread_mutex_lock(&(svc->mutex));
        sessionHandle *s;
        d_iterator iter;
        dforeach((sessionHandle *), s, svc->handles, iter) {
            if (s == sessptr) {
                dvector_delete(&iter);
                break;
            }
        }

        // Check if we were told to go kill ourself :(
        if ((session._tflags & RUMBLE_THREAD_DIE) || svc->enabled != 1 || thread->status == -1) {
            rumbleThread    *t;
            POP3TRACE("threads>I (%#lx) was told to die :(", (uintptr_t) pthread_self());
            cforeach((rumbleThread *), t, svc->threads, citer) {
                if (t == thread) {
                    cvector_delete(&citer);
                    break;
                }
            }
            pthread_mutex_unlock(&svc->mutex);
            // free(session._svcHandle);
            pthread_exit(0);
        }
        pthread_mutex_unlock(&svc->mutex);
    }
    pthread_exit(0);
}


ssize_t rumble_server_pop3_capa(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    if (!session) return (RUMBLE_RETURN_FAILURE);
    char *el;
    c_iterator iter;
    rumble_comm_send(session, "+OK Here's what I got:\r\n");
    cforeach((char *), el, ((rumbleService *) session->_svc)->capabilities, iter) rumble_comm_printf(session, "%s\r\n", el);
    rumble_comm_send(session, ".\r\n");
    return (RUMBLE_RETURN_IGNORE);
}


// ======================================================================== //
ssize_t rumble_server_pop3_user(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    if (!session) return (RUMBLE_RETURN_FAILURE);

    if (session->flags & RUMBLE_POP3_HAS_AUTH) {
        POP3LOG("USER !!auth addr %s", session->client->addr);
        return (105); // -ERR Unrecognized command.
    }
    if (!strlen(parameters)) {
        POP3LOG("USER !strlen(parameters) %s", session->client->addr);
        return (107); // invalid syntax
    }
    rumble_flush_dictionary(session->dict);
    rumble_add_dictionary_value(session->dict, "user", parameters);
    session->flags |= RUMBLE_POP3_HAS_USER;
    return (104); // +OK User begin
}


ssize_t rumble_server_pop3_pass(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    if (!session) return (RUMBLE_RETURN_FAILURE);
    accountSession *pops = (accountSession *) session->_svcHandle;
    const char * dict_user = rumble_get_dictionary_value(session->dict, "user");

    if (session->flags & RUMBLE_POP3_HAS_AUTH) {
        POP3LOG("PASS auth! User: %s, addr %s", dict_user, session->client->addr);
        return (105); // -ERR Unrecognized command.
    }

    if (!parameters) {
        POP3LOG("PASS params for pass - NULL! User: %s, addr %s", dict_user, session->client->addr);
        return (107); // -ERR Invalid syntax
    }

    if (!(session->flags & RUMBLE_POP3_HAS_USER)) {
        POP3LOG("PASS params has user! User: %s, addr %s", dict_user, session->client->addr);
        return (105); // -ERR Unrecognized command.
    }

    char usr[128], dmn[128];
    memset(usr, 0, 128);
    memset(dmn, 0, 128);

    if (sscanf(dict_user, "%127[^@]@%127c", usr, dmn) == 2) {
        POP3LOG("PASS %s requested access to %s@%s", session->client->addr, usr, dmn);
        pops->account = rumble_account_data_auth(0, usr, dmn, parameters);
        if (pops->account) {
            POP3LOG("PASS %s's request for %s@%s was granted", session->client->addr, usr, dmn);
            session->flags |= RUMBLE_POP3_HAS_AUTH;
            pops->bag = mailman_get_bag( pops->account->uid,
                strlen(pops->account->domain->path) ? pops->account->domain->path : rumble_get_dictionary_value(master->_core.conf, "storagefolder"));
            pops->folder = mailman_get_folder(pops->bag, "INBOX");
            ssize_t rc = rumble_service_schedule_hooks((rumbleService *) session->_svc, session,
                RUMBLE_HOOK_POP3 + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_POP3_PASS, (const char*) pops->account);
                if (rc == RUMBLE_RETURN_FAILURE) return (RUMBLE_RETURN_FAILURE);
                return (104);
        } else {
            POP3LOG("PASS %s's request for %s@%s was denied (wrong password)", session->client->addr, usr, dmn);
            ssize_t rc = rumble_service_schedule_hooks((rumbleService *) session->_svc, session,
                RUMBLE_HOOK_POP3 + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_POP3_PASS, NULL);
            if (rc == RUMBLE_RETURN_FAILURE) return (RUMBLE_RETURN_FAILURE); // Bye!
            return (106); // Wrong credentials given
        }
    }
    POP3LOG("PASS %s Wrong credentials for User %s, addr %s", dict_user, session->client->addr);
    return (106); // bad user/pass given
}

        /*
        if ((pops->account = rumble_account_data(0, usr, dmn))) {
            char * tmp = rumble_sha256(parameters);
            int n = strcmp(tmp, pops->account->hash);
            free(tmp);
            if (n) {
                POP3LOG("PASS %s's request for %s@%s was denied (wrong password)", session->client->addr, usr, dmn);
                rumble_free_account(pops->account);
                free(pops->account);
                pops->account = 0;
                ssize_t rc = rumble_service_schedule_hooks(
                    (rumbleService *) session->_svc, session,
                    RUMBLE_HOOK_POP3 + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_POP3_PASS,
                    (const char*) pops->account);
                if (rc == RUMBLE_RETURN_FAILURE) return (RUMBLE_RETURN_FAILURE); // Bye!
                return (106); // Wrong credentials given
            } else {
                POP3LOG("PASS %s's request for %s@%s was granted", session->client->addr, usr, dmn);
                session->flags |= RUMBLE_POP3_HAS_AUTH;
                pops->bag = mailman_get_bag(
                    pops->account->uid,
                    strlen(pops->account->domain->path) ? pops->account->domain->path : rumble_get_dictionary_value(master->_core.conf, "storagefolder"));
                pops->folder = mailman_get_folder(pops->bag, "INBOX");
                ssize_t rc = rumble_service_schedule_hooks(
                    (rumbleService *) session->_svc, session,
                    RUMBLE_HOOK_POP3 + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_POP3_PASS,
                    (const char*) pops->account);
                if (rc == RUMBLE_RETURN_FAILURE) return (RUMBLE_RETURN_FAILURE);
                return (104);
            }
        }
    }
    POP3LOG("PASS %s Wrong credentials for User %s, addr %s", dict_user, session->client->addr);
    return (106); // bad user/pass given
}
*/



ssize_t rumble_server_pop3_list(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    if (!session) return (RUMBLE_RETURN_FAILURE);
    accountSession *pops = (accountSession *) session->_svcHandle;
    if (!(session->flags & RUMBLE_POP3_HAS_AUTH)) {
        POP3LOG("LIST auth! %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
        return (105); // -ERR Unrecognized command.
    }
    mailman_folder * folder = pops->folder; //mailman_get_folder(pops->bag, "INBOX");

    if (!folder) {
        POP3LOG("LIST Couldn't open folder INBOX for %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
        return (108); // -ERR Couldn't open folder INBOX
    } else {
        unsigned letters = 0;
        rumble_comm_send(session, "+OK\r\n");
        rumble_rw_start_read(pops->bag->lock);
        for (unsigned j = 0; j < folder->size; j++) {
            mailman_letter * letter = &folder->letters[j];
            if (!letter->inuse) continue;
            letters++;
            if (!(letter->flags & RUMBLE_LETTER_DELETED)) {
                rumble_comm_printf(session, "%u %u\r\n", letters, letter->size);
            }
        }
        rumble_rw_stop_read(pops->bag->lock);
        rumble_comm_send(session, ".\r\n");
        POP3LOG("LIST done, found %u letters %s@%s %s", letters, pops->account->user, pops->account->domain->name, session->client->addr);
    }
    return (RUMBLE_RETURN_IGNORE);
}


ssize_t rumble_server_pop3_stat(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    if (!session) return (RUMBLE_RETURN_FAILURE);
    accountSession *pops = (accountSession *) session->_svcHandle;
    if (!(session->flags & RUMBLE_POP3_HAS_AUTH)) {
        POP3LOG("STAT auth! %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
        return (105); // -ERR Unrecognized command.
    }
    unsigned letters = 0, total = 0;
    mailman_folder * folder = pops->folder; //mailman_get_folder(pops->bag, "INBOX");
    if (!folder) {
        POP3LOG("STAT Couldn't open folder INBOX for %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
        return (108); // -ERR Couldn't open folder INBOX
    } else {
        rumble_rw_start_read(pops->bag->lock);
        mailman_update_folder(folder, pops->account->uid, 0);
        for (unsigned j = 0; j < folder->size; j++) {
            mailman_letter * letter = &folder->letters[j];
            if (!letter->inuse) continue;
            letters++;
            if (!(letter->flags & RUMBLE_LETTER_DELETED)) total += letter->size;
        }
        rumble_rw_stop_read(pops->bag->lock);
    }
    rumble_comm_printf(session, "+OK %u %u\r\n", letters, total);
    POP3LOG("STAT done, found %u letters, %u bytes total. %s@%s %s", letters, total, pops->account->user, pops->account->domain->name, session->client->addr);
    return (RUMBLE_RETURN_IGNORE);
}

ssize_t rumble_server_pop3_uidl(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    if (!session) return (RUMBLE_RETURN_FAILURE);
    accountSession *pops = (accountSession *) session->_svcHandle;

    if (!(session->flags & RUMBLE_POP3_HAS_AUTH)) {
        POP3LOG("UIDL auth! %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
        return (105); // -ERR Unrecognized command.
    }
    unsigned letters = 0;
    mailman_folder *  folder = pops->folder;// mailman_get_folder(pops->bag, "INBOX");
    if (!folder) {
        POP3LOG("UIDL Couldn't open folder INBOX for %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
        return (108); // -ERR Couldn't open folder INBOX
    } else {
        rumble_comm_send(session, "+OK\r\n");
        rumble_rw_start_read(pops->bag->lock);
        for (unsigned j = 0; j < folder->size; j++) {
            mailman_letter * letter = &folder->letters[j];
            if (!letter->inuse) continue;
            letters++;
            if (!(letter->flags & RUMBLE_LETTER_DELETED)) {
                rumble_comm_printf(session, "%u %lu\r\n", letters, letter->id);
            }
        }
        rumble_rw_stop_read(pops->bag->lock);
        rumble_comm_send(session, ".\r\n");
    }
    POP3LOG("UIDL return. letters=%d %s@%s %s", letters, pops->account->user, pops->account->domain->name, session->client->addr);
    return (RUMBLE_RETURN_IGNORE);
}




ssize_t rumble_server_pop3_dele(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    if (!session) return (RUMBLE_RETURN_FAILURE);
    accountSession *pops = (accountSession *) session->_svcHandle;

    if (!(session->flags & RUMBLE_POP3_HAS_AUTH)) {
        POP3LOG("DELE auth! %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
        return (105); // -ERR Unrecognized command.
    }
    if (!parameters) {
        POP3LOG("DELE params NULL! %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
        return (107); // -ERR Invalid syntax
    }

    uint8_t found = 0;
    int i = 0;

    if (parameters) {
        i = atoi(parameters);

        int letters = 0;
        mailman_folder * folder = pops->folder; //mailman_get_folder(pops->bag, "INBOX");
        if (!folder) {
            POP3LOG("DELE Couldn't open folder INBOX for %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
            return (108); // -ERR Couldn't open folder INBOX
        } else {
            rumble_rw_start_write(pops->bag->lock); // lock bag
            for (unsigned k = 0; k < folder->size; k++) {
                mailman_letter * letter = &folder->letters[k];
                if (!letter->inuse) continue;
                letters++;
                if (letters == i) {
                    letter->flags |= RUMBLE_LETTER_EXPUNGE; // Used to be _DELETED, but that was baaad.
                    POP3LOG("DELE Marked letter #%lu as EXPUNGE %s@%s %s", letter->id, pops->account->user, pops->account->domain->name, session->client->addr);
                    found = 1;
                    break;
                }
            }
            rumble_rw_stop_write(pops->bag->lock); // unlock bag
        }
    }
    if (found) {
        return (104);
    } else {
        POP3LOG("DELE No such letter %d %s@%s %s", i, pops->account->user, pops->account->domain->name, session->client->addr);
        return (110);
    }
//     return (RUMBLE_RETURN_IGNORE);
}


ssize_t rumble_server_pop3_retr(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    if (!session) return (RUMBLE_RETURN_FAILURE);
    accountSession *pops = (accountSession *) session->_svcHandle;
    if (!(session->flags & RUMBLE_POP3_HAS_AUTH)) {
        POP3LOG("RETR auth! %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
        return (105); // -ERR Unrecognized command.
    }
    if (!parameters) {
        POP3LOG("RETR params NULL! %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
        return (107); // -ERR Invalid syntax
    }

    if (parameters) {
        int i = atoi(parameters);
        mailman_folder * folder = pops->folder; //mailman_get_folder(pops->bag, "INBOX");
        if (!folder) {
            POP3LOG("RETR Couldn't open folder INBOX for %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
            return (108); // -ERR Couldn't open folder INBOX
        } else {
            int letters = 0;
            mailman_letter  *letter;
            FILE * fp = 0;
            rumble_rw_start_read(pops->bag->lock); // lock bag
            for (unsigned k = 0; k < folder->size; k++) {
                letter = &folder->letters[k];
                if (!letter->inuse) continue;
                letters++;
                if (letters == i) {
                    fp = mailman_open_letter(pops->bag, folder, letter->id); // TODO check and set flags
                    break;
                }
            }
            rumble_rw_stop_read(pops->bag->lock);

            if (fp) {
                rumble_comm_send(session, "+OK\r\n");
                char buffer[2049];
                while (!feof(fp)) {
                    if (!fgets(buffer, 2048, fp)) break;
                    rumble_comm_send(session, buffer);
                }
                fclose(fp);
                rumble_comm_send(session, "\r\n.\r\n");
            } else { // Might as well delete the letter if it doesn't exist :(
                // TODO remove duplcate code
                POP3LOG("RETR Couldn't open letter no %d for %s@%s %s", i, pops->account->user, pops->account->domain->name, session->client->addr);

                rumble_rw_start_write(pops->bag->lock); // lock bag
                letters = 0;
                for (unsigned k = 0; k < folder->size; k++) {
                    letter = &folder->letters[k];
                    if (!letter->inuse) continue;
                    letters++;
                    if (letters == i) {
                        // Used to be RUMBLE_LETTER_DELETED, but that was baaad.
                        letter->flags |= RUMBLE_LETTER_EXPUNGE;
                        POP3LOG("RETR Marked letter #%lu as EXPUNGE %s@%s %s", letter->id, pops->account->user, pops->account->domain->name, session->client->addr);
                        break;
                    }
                }
                rumble_rw_stop_write(pops->bag->lock); // unlock bag

                return (109); // -ERR Couldn't open letter no.
            }
        }
    }

    return (RUMBLE_RETURN_IGNORE);
}


ssize_t rumble_server_pop3_top(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    if (!session) return (RUMBLE_RETURN_FAILURE);
    accountSession *pops = (accountSession *) session->_svcHandle;
    if (!(session->flags & RUMBLE_POP3_HAS_AUTH)) {
        POP3LOG("TOP auth! %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
        return (105); // -ERR Unrecognized command.
    }

    if (!parameters) {
        POP3LOG("TOP params NULL! %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
        return (107); // -ERR Invalid syntax
    }

    int i, lines;
    if (sscanf(parameters, "%i %i", &i, &lines) != 2) {
        POP3LOG("TOP parameters incorrect! %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
        return (107); // -ERR Invalid syntax
    } else {
        mailman_folder * folder = pops->folder;//mailman_get_folder(pops->bag, "INBOX");
        if (!folder) {
            POP3LOG("TOP Couldn't open folder INBOX for %s@%s %s", pops->account->user, pops->account->domain->name, session->client->addr);
            return (108); // -ERR Couldn't open folder INBOX
        } else {
            FILE * fp =0;
            int letters = 0;
            rumble_rw_start_read(pops->bag->lock);
            for (unsigned k = 0; k < folder->size; k++) {
                mailman_letter * letter = &folder->letters[k];
                if (!letter->inuse) continue;
                letters++;
                if (letters == i) {
                    fp = mailman_open_letter(pops->bag, folder, letter->id);
                    break;
                }
            }
            rumble_rw_stop_read(pops->bag->lock);

            if (fp) {
                rumble_comm_send(session, "+OK\r\n");
                char buffer[2049];
                while (!feof(fp) && lines) {
                    lines--;
                    if (!fgets(buffer, 2048, fp)) break;
                    rumble_comm_send(session, buffer);
                }
                fclose(fp);
                rumble_comm_send(session, ".\r\n");
            } else {
                POP3LOG("TOP Couldn't open letter no %d %s@%s %s", i, pops->account->user, pops->account->domain->name, session->client->addr);
                return (109); // -ERR Couldn't open letter no.
            }
        }
    }
    return (RUMBLE_RETURN_IGNORE);
}

// POP3TRACE("%s:%d:%s(): 105 !auth %s@%s %s", __FILE__, __LINE__, __func__, pops->account->user, pops->account->domain->name, session->client->addr);
