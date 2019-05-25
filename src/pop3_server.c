#include "rumble.h"
#include "servers.h"
#include "comm.h"
#include "reply_codes.h"
#include "private.h"
#include "mailman.h"

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
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_POP3)
        rumble_debug(NULL, "pop3", "Accepted connection from %s on POP3", session.client->addr);
#endif

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
            if (!line) break;
            rc = 105; // default return code is "500 unknown command thing"
            if (sscanf(line, "%8[^\t \r\n]%*[ \t]%1000[^\r\n]", cmd, arg)) {
                rumble_string_upper(cmd);
                //  rumble_debug(NULL, "pop3", "%s said: %s %s", session.client->addr, cmd, arg);
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
        }

        // Cleanup
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_POP3)
        rumble_debug(NULL, "pop3", "Closing connection from %s on POP3", session.client->addr);
#endif
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
#if RUMBLE_DEBUG & RUMBLE_DEBUG_THREADS
            printf("<pop3::threads>I (%#lx) was told to die :(\n", (uintptr_t) pthread_self());
#endif

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
    char        *el;
    c_iterator  iter;
    rumble_comm_send(session, "+OK Here's what I got:\r\n");
    cforeach((char *), el, ((rumbleService *) session->_svc)->capabilities, iter) {
        rumble_comm_printf(session, "%s\r\n", el);
    }
    rumble_comm_send(session, ".\r\n");
    return (RUMBLE_RETURN_IGNORE);
}



ssize_t rumble_server_pop3_user(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    if (session->flags & RUMBLE_POP3_HAS_AUTH) return (105);
    if (!strlen(parameters)) return (107); // invalid syntax
    rumble_flush_dictionary(session->dict);
    rumble_add_dictionary_value(session->dict, "user", parameters);
    session->flags |= RUMBLE_POP3_HAS_USER;
    return (104);
}



ssize_t rumble_server_pop3_pass(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {

    char usr[128], dmn[128];
    accountSession  *pops = (accountSession *) session->_svcHandle;
    if (!strlen(parameters)) return (107);
    if (!(session->flags & RUMBLE_POP3_HAS_USER)) return (105);
    if (session->flags & RUMBLE_POP3_HAS_AUTH) return (105);
    memset(usr, 0, 128);
    memset(dmn, 0, 128);
    if (sscanf(rumble_get_dictionary_value(session->dict, "user"), "%127[^@]@%127c", usr, dmn) == 2) {
        rumble_debug(NULL, "pop3", "%s requested access to %s@%s\n", session->client->addr, usr, dmn);
        if ((pops->account = rumble_account_data(0, usr, dmn))) {
            char * tmp = rumble_sha256(parameters);
            int n = strcmp(tmp, pops->account->hash);
            free(tmp);
            if (n) {
                rumble_debug(NULL, "pop3", "%s's request for %s@%s was denied (wrong password)\n", session->client->addr, usr, dmn);
                rumble_free_account(pops->account);
                free(pops->account);
                pops->account = 0;
                ssize_t rc = rumble_service_schedule_hooks((rumbleService *) session->_svc, session,
                    RUMBLE_HOOK_POP3 + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_POP3_PASS, (const char*) pops->account);
                if (rc == RUMBLE_RETURN_FAILURE) return rc;
                return (106);
            } else {
                rumble_debug(NULL, "pop3", "%s's request for %s@%s was granted\n", session->client->addr, usr, dmn);
                session->flags |= RUMBLE_POP3_HAS_AUTH;
                pops->bag = mailman_get_bag(pops->account->uid,
                    strlen(pops->account->domain->path) ? pops->account->domain->path : rumble_get_dictionary_value(master->_core.conf, "storagefolder"));
                pops->folder = mailman_get_folder(pops->bag, "INBOX");
                ssize_t rc = rumble_service_schedule_hooks((rumbleService *) session->_svc, session,
                    RUMBLE_HOOK_POP3 + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_POP3_PASS, (const char*) pops->account);
                if (rc == RUMBLE_RETURN_FAILURE) return rc;
                return (104);
            }
        }
    }
    return (106); // bad user/pass given
}


ssize_t rumble_server_pop3_list(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    int i = 0, j = 0;
    accountSession  *pops = (accountSession *) session->_svcHandle;
    if (!(session->flags & RUMBLE_POP3_HAS_AUTH)) return (105); /* Not authed?! :( */
    rumble_comm_send(session, "+OK\r\n");
    rumble_rw_start_read(pops->bag->lock);
    mailman_folder * folder = mailman_get_folder(pops->bag, "INBOX");
    for (j = 0; j < folder->size; j++) {
        mailman_letter * letter = &folder->letters[j];
        if (!letter->inuse) continue;
        i++;
        if (!(letter->flags & RUMBLE_LETTER_DELETED))
            rumble_comm_printf(session, "%u %u\r\n", i, letter->size);
    }
    rumble_rw_stop_read(pops->bag->lock);
    rumble_comm_send(session, ".\r\n");
    return (RUMBLE_RETURN_IGNORE);
}


ssize_t rumble_server_pop3_stat(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    uint32_t n = 0, s = 0, j = 0;
    accountSession  *pops = (accountSession *) session->_svcHandle;
    printf("Doing stat\n");
    if (!(session->flags & RUMBLE_POP3_HAS_AUTH)) return (105); /* Not authed?! :( */
    rumble_rw_start_read(pops->bag->lock);
    mailman_folder * folder = mailman_get_folder(pops->bag, "INBOX");
    if (!folder) {
        rumble_comm_send(session, "-ERR Temporary error\r\n");
        return (RUMBLE_RETURN_IGNORE);
    }
    mailman_update_folder(folder, pops->account->uid, 0);
    for (j = 0; j < folder->size; j++) {
        mailman_letter * letter = &folder->letters[j];
        if (!letter->inuse) continue;
        n++;
        if (!(letter->flags & RUMBLE_LETTER_DELETED)) s += letter->size;
    }
    rumble_rw_stop_read(pops->bag->lock);
    rumble_comm_printf(session, "+OK %u %u\r\n", n, s);
    printf("stat done, found %u letters, %u bytes total\n", n, s);
    return (RUMBLE_RETURN_IGNORE);
}

ssize_t rumble_server_pop3_uidl(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {

    int i = 0, j = 0;
    accountSession  *pops = (accountSession *) session->_svcHandle;
    if (!(session->flags & RUMBLE_POP3_HAS_AUTH)) return (105); /* Not authed?! :( */
    rumble_comm_send(session, "+OK\r\n");
    rumble_rw_start_read(pops->bag->lock);
    mailman_folder *  folder = mailman_get_folder(pops->bag, "INBOX");
    if (folder) {
        i = 0;
        for (j = 0; j < folder->size; j++) {
            mailman_letter * letter = &folder->letters[j];
            if (!letter->inuse) continue;
            i++;
            if (!(letter->flags & RUMBLE_LETTER_DELETED)) rumble_comm_printf(session, "%u %lu\r\n", i, letter->id);
        }
    } else printf("No INBOX folder??\n");
    rumble_rw_stop_read(pops->bag->lock);
    rumble_comm_send(session, ".\r\n");
    return (RUMBLE_RETURN_IGNORE);
}


ssize_t rumble_server_pop3_dele(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    int k, j = 0, found = 0, i = atoi(parameters);
    accountSession  *pops = (accountSession *) session->_svcHandle;
    if (!(session->flags & RUMBLE_POP3_HAS_AUTH)) return (105); // Not authed?! :(
    printf("DELE called for letter %u\n", i);
    mailman_folder * folder = mailman_get_folder(pops->bag, "INBOX");
    rumble_rw_start_write(pops->bag->lock);
    for (k = 0; k < folder->size; k++) {
        mailman_letter * letter = &folder->letters[k];
        if (!letter->inuse) continue;
        j++;
        if (j == i) {
            letter->flags |= RUMBLE_LETTER_EXPUNGE; // Used to be _DELETED, but that was baaad.
            printf("pop3: Marked letter #%lu as deleted\n", letter->id);
            found = 1;
            break;
        }
    }
    rumble_rw_stop_write(pops->bag->lock);
    if (found) rumble_comm_send(session, "+OK\r\n");
    else rumble_comm_send(session, "-ERR No such letter.\r\n");
    return (RUMBLE_RETURN_IGNORE);
}


ssize_t rumble_server_pop3_retr(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    int j, i, k;
    accountSession  *pops = (accountSession *) session->_svcHandle;
    FILE * fp = 0;
    if (!(session->flags & RUMBLE_POP3_HAS_AUTH)) return (105); // Not authed?! :(
    i = atoi(parameters);
    rumble_rw_start_read(pops->bag->lock);
    mailman_folder * folder = mailman_get_folder(pops->bag, "INBOX");
    j = 0;
    mailman_letter  *letter;
    for (k = 0; k < folder->size; k++) {
        letter = &folder->letters[k];
        if (!letter->inuse) continue;
        j++;
        if (j == i) {
            fp = mailman_open_letter(pops->bag, folder, letter->id);
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
    } else {
        rumble_comm_printf(session, "-ERR Couldn't open letter no. %d.\r\n", i);
        // Might as well delete the letter if it doesn't exist :(
        folder = mailman_get_folder(pops->bag, "INBOX");
        rumble_rw_start_write(pops->bag->lock);
        j = 0;
        for (k = 0; k < folder->size; k++) {
            letter = &folder->letters[k];
            if (!letter->inuse) continue;
            j++;
            if (j == i) {
                // Used to be _DELETED, but that was baaad.
                letter->flags |= RUMBLE_LETTER_EXPUNGE;
                break;
            }
        }
        rumble_rw_stop_write(pops->bag->lock);
    }
    return (RUMBLE_RETURN_IGNORE);
}


ssize_t rumble_server_pop3_top(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {

    int i, lines, j;
    accountSession  *pops = (accountSession *) session->_svcHandle;
    FILE            *fp =0;
    if (!(session->flags & RUMBLE_POP3_HAS_AUTH)) return (105); // Not authed?!
    if (sscanf(parameters, "%i %i", &i, &lines) == 2) {
        rumble_rw_start_read(pops->bag->lock);
        mailman_folder * folder = mailman_get_folder(pops->bag, "INBOX");
        j = 0;
        for (uint32_t k = 0; k < folder->size; k++) {
            mailman_letter * letter = &folder->letters[k];
            if (!letter->inuse) continue;
            j++;
            if (j == i) {
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
        } else rumble_comm_printf(session, "-ERR Couldn't open letter no. %d.\r\n", i);
        return (RUMBLE_RETURN_IGNORE);
    }
    return (105);
}
