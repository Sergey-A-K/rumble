#include "rumble.h"
#include "servers.h"
#include "comm.h"
#include "private.h"
#include "database.h"
#include "mailman.h"


#define IMAP_LOG(x ...) rumble_debug(NULL, "imap4", x);

#define IMAP_TRA(x ...) rumble_debug(NULL, "imap4", x);



//     Main loop
void rumble_master_init_imap4(masterHandle *master) {
    (void) master;
    const char *imap4port = rumble_config_str(master, "imap4port");
    rumbleService *svc = comm_registerService(master, "imap4", rumble_imap_init, imap4port, RUMBLE_INITIAL_THREADS);

    // Set stack size for service to 512kb (should be enough)
    svc->settings.stackSize = 512 * 1024;
    if (rumble_config_int(master, "enableimap4")) {
        IMAP_LOG("Launching IMAP4 service...");
        int rc = comm_startService(svc);
        if (rc) {
            // Commands
            IMAP_LOG("Adding IMAP4 commands and capabilities");
            rumble_service_add_command(svc, "LOGIN",        rumble_server_imap_login);
            rumble_service_add_command(svc, "LOGOUT",       rumble_server_imap_logout);
            rumble_service_add_command(svc, "NOOP",         rumble_server_imap_noop);
            rumble_service_add_command(svc, "CAPABILITY",   rumble_server_imap_capability);
            rumble_service_add_command(svc, "AUTHENTICATE", rumble_server_imap_authenticate);
            rumble_service_add_command(svc, "SELECT",       rumble_server_imap_select);
            rumble_service_add_command(svc, "EXAMINE",      rumble_server_imap_examine);
            rumble_service_add_command(svc, "CREATE",       rumble_server_imap_create);
            rumble_service_add_command(svc, "DELETE",       rumble_server_imap_delete);
            rumble_service_add_command(svc, "RENAME",       rumble_server_imap_rename);
            rumble_service_add_command(svc, "SUBSCRIBE",    rumble_server_imap_subscribe);
            rumble_service_add_command(svc, "UNSUBSCRIBE",  rumble_server_imap_unsubscribe);
            rumble_service_add_command(svc, "LIST",         rumble_server_imap_list);
            rumble_service_add_command(svc, "LSUB",         rumble_server_imap_lsub);
            rumble_service_add_command(svc, "STATUS",       rumble_server_imap_status);
            rumble_service_add_command(svc, "APPEND",       rumble_server_imap_append);
            rumble_service_add_command(svc, "CHECK",        rumble_server_imap_check);
            rumble_service_add_command(svc, "CLOSE",        rumble_server_imap_close);
            rumble_service_add_command(svc, "EXPUNGE",      rumble_server_imap_expunge);
            rumble_service_add_command(svc, "SEARCH",       rumble_server_imap_search);
            rumble_service_add_command(svc, "FETCH",        rumble_server_imap_fetch);
            rumble_service_add_command(svc, "STORE",        rumble_server_imap_store);
            rumble_service_add_command(svc, "COPY",         rumble_server_imap_copy);
            rumble_service_add_command(svc, "IDLE",         rumble_server_imap_idle);
            rumble_service_add_command(svc, "TEST",         rumble_server_imap_test);
            // Capabilities
            rumble_service_add_capability(svc, "IMAP4rev1");
            rumble_service_add_capability(svc, "IDLE");
            rumble_service_add_capability(svc, "CONDSTORE");
            rumble_service_add_capability(svc, "AUTH=PLAIN");
            rumble_service_add_capability(svc, "LITERAL");
            rumble_service_add_capability(svc, "UIDPLUS");
            rumble_service_add_capability(svc, "ANNOTATEMORE");
            IMAP_LOG("Flushing hooks for IMAP4");
            svc->cue_hooks  = cvector_init();
            svc->init_hooks = cvector_init();
            svc->exit_hooks = cvector_init();
            IMAP_LOG("Adding IMAP4 commands OK");
        } else {
            IMAP_LOG("ABORT: Couldn't create socket for IMAP4!");
            exit(EXIT_SUCCESS);
        }
    }

}






void *rumble_imap_init(void *T) {
    rumbleThread    *thread = (rumbleThread *) T;
    rumbleService   *svc = thread->svc;
    masterHandle    *master = svc->master;
    // Initialize a session handle and wait for incoming connections
    sessionHandle   session, *s;
    sessionHandle   *sessptr = &session;
    d_iterator      iter;
    svcCommandHook  *hook;
    c_iterator      citer;

    session.dict = dvector_init();
    session.recipients = dvector_init();
    session._svcHandle = (accountSession *) malloc(sizeof(accountSession));
    session._svc = svc;
    session.client = (clientHandle *) malloc(sizeof(clientHandle));
    session.client->tls_session = 0;
    session.client->tls_send = 0;
    session.client->tls_recv = 0;
    session._master = svc->master;
    accountSession * pops = (accountSession *) session._svcHandle;
    pops->account = 0;
    pops->bag = 0;
    pops->folder = 0;
    session._tflags = RUMBLE_THREAD_IMAP; // Identify the thread/session as IMAP4
    const char * myName = rumble_get_dictionary_value(master->_core.conf, "servername");
    myName = myName ? myName : "??";
    while (1) {
        comm_accept(svc->socket, session.client);
        pthread_mutex_lock(&svc->mutex);
        dvector_add(svc->handles, (void *) sessptr);
        svc->traffic.sessions++;
        pthread_mutex_unlock(&svc->mutex);
        session.flags = 0;
        session._tflags += 0x00100000; // job count ( 0 through 4095)
        session.sender = 0;
        pops->bag = 0;
        IMAP_LOG("Accepted connection from %s on IMAP4", session.client->addr);

        // Check for hooks on accept()
        ssize_t rc = RUMBLE_RETURN_OKAY;
        rc = rumble_server_schedule_hooks(master, sessptr, RUMBLE_HOOK_ACCEPT + RUMBLE_HOOK_IMAP);
        if (rc == RUMBLE_RETURN_OKAY) rumble_comm_printf(sessptr, "* OK <%s> IMAP4rev1 Service Ready\r\n", myName); // Hello!
        else svc->traffic.rejections++;

        // Parse incoming commands
        char * extra_data = (char*) malloc(32);
        char * cmd =        (char*) malloc(32);
        char * parameters = (char*) malloc(1024);
        if (!cmd || !parameters || !extra_data) merror();
        while (rc != RUMBLE_RETURN_FAILURE) {
            memset(extra_data, 0, 32);
            memset(cmd, 0, 32);
            memset(parameters, 0, 1024);
            char * line = rumble_comm_read(sessptr);
            rc = 421;
            if (!line) break;
            rc = 105; // default return code is "500 unknown command thing"
            if (sscanf(line, "%32s %32s %1000[^\r\n]", extra_data, cmd, parameters)) {
                rumble_string_upper(cmd);
                IMAP_LOG("Client <%p> said: %s %s", &session, cmd, parameters);

                if (!strcmp(cmd, "UID")) { // Set UID flag if requested
                    session.flags |= rumble_mailman_HAS_UID;
                    if (sscanf(parameters, "%32s %1000[^\r\n]", cmd, parameters)) rumble_string_upper(cmd);
                } else
                    session.flags -= (session.flags & rumble_mailman_HAS_UID); // clear UID demand if not there.

                cforeach((svcCommandHook *), hook, svc->commands, citer)
                    if (!strcmp(cmd, hook->cmd)) rc = hook->func(master, &session, parameters, extra_data);

                IMAP_LOG("%s said: <%s> %s %s", session.client->addr, extra_data, cmd, parameters);
                IMAP_LOG("Selected folder is: %"PRId64 "\n", pops->folder);
            }

            free(line);
            if (rc == RUMBLE_RETURN_IGNORE) {
//                 IMAP_LOG("Ignored command: %s %s\n",cmd, parameters);
                continue; // Skip to next line.
            } else if (rc == RUMBLE_RETURN_FAILURE) {
                svc->traffic.rejections++;
                break; // Abort!
            } else rumble_comm_printf(&session, "%s BAD Invalid command!\r\n", extra_data); // Bad command thing.
        }

        // Cleanup
        IMAP_LOG("Closing connection to %s on IMAP4", session.client->addr);
        if (rc == 421) {
            // rumble_comm_printf(&session, "%s BAD Session timed out!\r\n", extra_data);
            //timeout
        } else {
            rumble_comm_send(&session, "* BYE bye!\r\n");
            rumble_comm_printf(&session, "%s OK <%s> signing off for now.\r\n", extra_data, myName);
        }

        // Run hooks scheduled for service closing

        rumble_server_schedule_hooks(master, sessptr, RUMBLE_HOOK_CLOSE + RUMBLE_HOOK_IMAP);

        comm_addEntry(svc, session.client->brecv + session.client->bsent, session.client->rejected);
        disconnect(session.client->socket);
        IMAP_LOG("Cleaning up\n");

        // Start cleanup
        free(parameters);
        free(cmd);
        rumble_clean_session(sessptr);
        rumble_free_account(pops->account);
        mailman_close_bag(pops->bag);
        pops->bag = 0;
        // End cleanup

        pthread_mutex_lock(&(svc->mutex));
        dforeach((sessionHandle *), s, svc->handles, iter) {
            if (s == sessptr) {
                dvector_delete(&iter);
                break;
            }
        }

        // Check if we were told to go kill ourself :(
        if ((session._tflags & RUMBLE_THREAD_DIE) || svc->enabled != 1 || thread->status == -1) {
            rumbleThread * t;
// #if RUMBLE_DEBUG & RUMBLE_DEBUG_THREADS
            IMAP_TRA("<imap4::threads>I (%#lx) was told to die :(\n", (uintptr_t) pthread_self());
// #endif
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
        myName = rumble_get_dictionary_value(master->_core.conf, "servername");
        myName = myName ? myName : "??";
    }

    pthread_exit(0);
}



ssize_t rumble_server_imap_login(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    char user[256], pass[256], digest[1024];
    accountSession  *imap = (accountSession *) session->_svcHandle;
    mailman_close_bag(imap->bag);
    if (sscanf(parameters, "\"%256[^\" ]\" \"%256[^\" ]\"", user, pass) == 2 ||
        sscanf(parameters, "\"%256[^\" ]\" %255s", user, pass) == 2 ||
        sscanf(parameters, "%255s \"%256[^\" ]\"", user, pass) == 2 ||
        sscanf(parameters, "%255s %255s", user, pass) == 2) {
        sprintf(digest, "<%s>", user);
        address * addr = rumble_parse_mail_address(digest);
        if (addr) {
            IMAP_LOG("%s requested access to %s@%s via LOGIN\n", session->client->addr, addr->user, addr->domain);
            imap->account = rumble_account_data_auth(0, addr->user, addr->domain, pass);
            if (imap->account) {
                IMAP_LOG("%s's request for %s@%s was granted\n", session->client->addr, addr->user, addr->domain);
                rumble_comm_printf(session, "%s OK Welcome!\r\n", extra_data);
                imap->folder = 0;
                imap->bag = mailman_get_bag(imap->account->uid,
                                            strlen(imap->account->domain->path) ? imap->account->domain->path : rumble_get_dictionary_value(master->_core.conf, "storagefolder"));
            } else {
                IMAP_LOG("%s's request for %s@%s was denied (wrong pass?)\n", session->client->addr, addr->user, addr->domain);
                rumble_comm_printf(session, "%s NO Incorrect username or password!\r\n", extra_data);
                session->client->rejected = 1;
            }
        } else {
            rumble_comm_printf(session, "%s NO Incorrect username or password!\r\n", extra_data);
            session->client->rejected = 1;
        }
    } else {
        rumble_comm_printf(session, "%s NO Incorrect username or password!\r\n", extra_data);
        session->client->rejected = 1;
    }

    ssize_t rc = rumble_service_schedule_hooks((rumbleService *) session->_svc, session,
        RUMBLE_HOOK_IMAP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_IMAP_AUTH, (const char*) imap->account);
    if (rc == RUMBLE_RETURN_FAILURE) return rc;
    return (RUMBLE_RETURN_IGNORE);
}

// NOOP

ssize_t rumble_server_imap_noop(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    rumble_comm_printf(session, "%s OK Doin' nothin'...\r\n", extra_data);
    return (RUMBLE_RETURN_IGNORE);
}

// CAPABILITY

ssize_t rumble_server_imap_capability(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    char        capa[1024];
    char        *el;
    c_iterator  iter;

    sprintf(capa, "* CAPABILITY");
    cforeach((char *), el, ((rumbleService *) session->_svc)->capabilities, iter) {
        sprintf(&capa[strlen(capa)], " %s", el);
    }

    sprintf(&capa[strlen(capa)], "\r\n");
    rumble_comm_send(session, capa);
    rumble_comm_printf(session, "%s OK CAPABILITY completed.\r\n", extra_data);
    return (RUMBLE_RETURN_IGNORE);
}

// AUTHENTICATE

ssize_t rumble_server_imap_authenticate(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;
    char cmd[32], tmp[258], user[256], pass[256];

    mailman_close_bag(imap->bag);
    imap->bag = 0;
    if (sscanf(strchr(parameters, '"') ? strchr(parameters, '"') + 1 : parameters, "%32[a-zA-Z]", cmd)) {
        rumble_string_upper(cmd);
        if (!strcmp(cmd, "PLAIN")) {
            rumble_comm_printf(session, "%s OK Method <%s> accepted, input stuffs!\r\n", extra_data, cmd);
            char * line = rumble_comm_read(session);
            int x = 0;
            if (line) {
                char * buffer = rumble_decode_base64(line);
                if (sscanf(buffer + 1, "\"%255[^\"]\"", user)) x = 2;
                else sscanf(buffer + 1, "%255s", user);
                if (!sscanf(buffer + 2 + x + strlen(user), "\"%255[^\"]\"", pass)) sscanf(buffer + 2 + x + strlen(user), "%255s", pass);
                sprintf(tmp, "<%s>", user);
                if (pass[strlen(pass) - 1] == 4) pass[strlen(pass) - 1] = 0; // remove EOT character if present.
                address * addr = rumble_parse_mail_address(tmp);
                if (addr) {
                    IMAP_LOG("%s requested access to %s@%s via AUTHENTICATE", session->client->addr, addr->user, addr->domain);
                    imap->account = rumble_account_data_auth(0, addr->user, addr->domain, pass);
                    if (imap->account) {
                        rumble_comm_printf(session, "%s OK Welcome!\r\n", extra_data);
                        imap->folder = 0;
                        // Check if we have a shared mailbox instance available, if not, make one
                        imap->bag = mailman_get_bag(imap->account->uid, strlen(imap->account->domain->path) ?
                            imap->account->domain->path : rumble_get_dictionary_value(master->_core.conf, "storagefolder"));
                    } else {
                        rumble_comm_printf(session, "%s NO Incorrect username or password!\r\n", extra_data);
                        session->client->rejected = 1;
                    }
                    rumble_free_address(addr);
                } else {
                    rumble_comm_printf(session, "%s NO Incorrect username or password!\r\n", extra_data);
                    session->client->rejected = 1;
                }
                free(buffer);
                free(line);
            }
        }
    }

    ssize_t rc = rumble_service_schedule_hooks((rumbleService *) session->_svc, session,
        RUMBLE_HOOK_IMAP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_IMAP_AUTH, (const char*) imap->account);
    if (rc == RUMBLE_RETURN_FAILURE) return rc;
    return (RUMBLE_RETURN_IGNORE);
}


// SELECT

ssize_t rumble_server_imap_select(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;

    // Are we authed?
    if (imap->account) {
        rumble_args * params = rumble_read_words(parameters);
        char * selector = params->argc ? params->argv[0] : "";

        // Get the folder
        mailman_folder * folder = mailman_get_folder(imap->bag, selector);
        if (folder) {
            mailman_letter  *letter;
            uint32_t        i;
            mailman_update_folder(folder, imap->bag->uid, 0);
            imap->folder = folder;
            rumble_rw_start_read(imap->bag->lock);
            session->flags |= rumble_mailman_HAS_SELECT;
            session->flags |= rumble_mailman_HAS_READWRITE;
            uint32_t exists = 0;
            uint32_t recent = 0;
            uint32_t first = 0;

            // Retrieve the statistics of the folder
            for (i = 0; i < folder->size; i++) {
                letter = &folder->letters[i];
                if (!letter->inuse) continue;
                exists++;
                if (!first && (letter->flags & RUMBLE_LETTER_RECENT)) first = exists;
                if (letter->flags & RUMBLE_LETTER_RECENT) {
                    letter->flags -= RUMBLE_LETTER_RECENT;
                    letter->updated = 1;
                    recent++;
                }
            }

            rumble_rw_stop_read(imap->bag->lock);
            IMAP_LOG("* %u EXISTS", exists);
            rumble_comm_printf(session, "* %u EXISTS\r\n", exists);
            rumble_comm_send(session, "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n");
            if (recent) {
                IMAP_LOG("* %u RECENT\r\n", recent);
                rumble_comm_printf(session, "* %u RECENT\r\n", recent);
            }

            if (first) rumble_comm_printf(session, "* OK [UNSEEN %"PRIu64 "] Message %"PRIu64 " is the first unseen message.\r\n", first, first);
            rumble_comm_printf(session, "* OK [UIDVALIDITY %08u] UIDs valid\r\n", imap->account->uid);
            rumble_comm_printf(session, "%s OK [READ-WRITE] SELECT completed.\r\n", extra_data);
        } else
            rumble_comm_printf(session, "%s NO No such mailbox <%s>!\r\n", extra_data, selector);

        // Shared Object Reader Unlock
        rumble_args_free(params);
    } else rumble_comm_printf(session, "%s NO Not logged in yet!\r\n", extra_data);
    return (RUMBLE_RETURN_IGNORE);
}


// EXAMINE

ssize_t rumble_server_imap_examine(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;
    // Are we authed?
    if (imap->account) {
        rumble_args * params = rumble_read_words(parameters);
        char * selector = params->argc ? params->argv[0] : "";
        mailman_folder * folder = mailman_get_folder(imap->bag, selector);
        if (folder) {
            rumble_rw_start_read(imap->bag->lock);
            session->flags |= rumble_mailman_HAS_SELECT;
            session->flags |= rumble_mailman_HAS_READWRITE;
            uint32_t exists = 0;
            uint32_t recent = 0;
            uint32_t first = 0;
            for (int i = 0; i < folder->size; i++) {
                mailman_letter * letter = &folder->letters[i];
                if (!letter->inuse) continue;
                exists++;
                if (!first && (letter->flags & RUMBLE_LETTER_RECENT)) first = exists;
            }
            rumble_rw_stop_read(imap->bag->lock);
            rumble_comm_printf(session, "* %u EXISTS\r\n", exists);
            rumble_comm_send(session, "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n");
            if (recent) rumble_comm_printf(session, "* %u RECENT.\r\n", recent);
            if (first) rumble_comm_printf(session, "* OK [UNSEEN %u] Message %u is the first unseen message.\r\n", first, first);
            rumble_comm_printf(session, "* OK [UIDVALIDITY %08u] UIDs valid\r\n", imap->account->uid);
            rumble_comm_printf(session, "%s OK [READ-ONLY] EXAMINE completed.\r\n", extra_data);
        } else
            rumble_comm_printf(session, "%s NO No such mailbox <%s>!\r\n", extra_data, selector);
    } else
        rumble_comm_printf(session, "%s NO Not logged in yet!\r\n", extra_data);
    return (RUMBLE_RETURN_IGNORE);
}


// CREATE

ssize_t rumble_server_imap_create(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;
    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    rumble_args * args = rumble_read_words(parameters);
    if (args && args->argc == 1) {
        char * newName = args->argv[0];
        // Shared Object Writer Lock
        mailman_folder * newFolder = mailman_get_folder(imap->bag, newName);
        if (newFolder)
            rumble_comm_printf(session, "%s NO CREATE failed: Duplicate folder name.\r\n", extra_data);
        else {
            rumble_rw_start_write(imap->bag->lock);
            // Add the folder to the SQL DB
            radb_run_inject(master->_core.db, "INSERT INTO folders (uid, name) VALUES (%u, %s)", imap->account->uid, newName);
            // Update the local folder list
            rumble_rw_stop_write(imap->bag->lock);
            mailman_update_folders(imap->bag);
            // Shared Object Writer Unlock
            rumble_comm_printf(session, "%s OK CREATE completed\r\n", extra_data);
        }
    } else rumble_comm_printf(session, "%s BAD Invalid CREATE syntax!\r\n", extra_data);
    if (args) rumble_args_free(args);
    return (RUMBLE_RETURN_IGNORE);
}


// DELETE

ssize_t rumble_server_imap_delete(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;
    mailman_folder  *folder = 0;
    char            *folderName = 0;
    // Are we authed?
    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    rumble_args * args = rumble_read_words(parameters);

    /* Find the folder we're looking for */
    if (args && args->argc >= 1) {
        folderName = args->argv[0];
        folder = mailman_get_folder(imap->bag, folderName);
    }

    if (!folder) {
        rumble_comm_printf(session, "%s NO DELETE failed: No such folder <%s>\r\n", extra_data, folderName);
        return (RUMBLE_RETURN_IGNORE);
    }

    // Obtain write lock on the bag
    rumble_rw_start_write(imap->bag->lock);

    // Delete folder from database and bag struct
    radb_run_inject(master->_core.db, "DELETE FROM folders WHERE id = %u", folder->fid);
    mailman_delete_folder(imap->bag, folder);
    rumble_rw_stop_write(imap->bag->lock);
    rumble_comm_printf(session, "%s OK Deleted <%s>\r\n", extra_data, folderName);
    return (RUMBLE_RETURN_IGNORE);
}


// RENAME

ssize_t rumble_server_imap_rename(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;
    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    rumble_args * args = rumble_read_words(parameters);
    if (args && args->argc == 2) {
        char * oldName = args->argv[0];
        char * newName = args->argv[1];
        // Shared Object Writer Lock
        mailman_folder * oldFolder = mailman_get_folder(imap->bag, oldName);
        mailman_folder * newFolder = mailman_get_folder(imap->bag, newName);
        if (newFolder) rumble_comm_printf(session, "%s NO RENAME failed: Duplicate folder name.\r\n", extra_data);
        else if (!oldFolder)
            rumble_comm_printf(session, "%s NO RENAME failed: No such folder <%s>\r\n", extra_data, oldName);
        else {
            rumble_rw_start_write(imap->bag->lock);
            radb_run_inject(master->_core.db, "UPDATE folders set name = %s WHERE id = %u", newName, oldFolder->fid);
            strncpy(oldFolder->name, newName, 64);
            rumble_comm_printf(session, "%s OK RENAME completed\r\n", extra_data);
            rumble_rw_stop_write(imap->bag->lock);
        }
    } else rumble_comm_printf(session, "%s BAD Invalid RENAME syntax!\r\n", extra_data);
    return (RUMBLE_RETURN_IGNORE);
}


// SUBSCRIBE

ssize_t rumble_server_imap_subscribe(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;
    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    rumble_args * args = rumble_read_words(parameters);
    if (args && args->argc == 1) {
        char * folderName = args->argv[0];
        // Shared Object Writer Lock
        mailman_folder * folder = mailman_get_folder(imap->bag, folderName);
        if (!folder) rumble_comm_printf(session, "%s NO SUBSCRIBE failed: No such folder <%s>\r\n", extra_data, folderName);
        else {
            rumble_rw_start_write(imap->bag->lock);
            radb_run_inject(master->_core.db, "UPDATE folders set subscribed = 1 WHERE id = %l", folder->fid);
            folder->subscribed = 1;
            rumble_rw_stop_write(imap->bag->lock);
            rumble_comm_printf(session, "%s OK SUBSCRIBE completed\r\n", extra_data);
            //  Shared Object Writer Unlock
        }

    } else rumble_comm_printf(session, "%s BAD Invalid SUBSCRIBE syntax!\r\n", extra_data);
    rumble_args_free(args);
    return (RUMBLE_RETURN_IGNORE);
}


// UNSUBSCRIBE

ssize_t rumble_server_imap_unsubscribe(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;
    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    rumble_args * args = rumble_read_words(parameters);
    if (args && args->argc == 1) {
        char * folderName = args->argv[0];
        // Shared Object Writer Lock
        mailman_folder * folder = mailman_get_folder(imap->bag, folderName);
        if (!folder) rumble_comm_printf(session, "%s NO UNSUBSCRIBE failed: No such folder <%s>\r\n", extra_data, folderName);
        else {
            rumble_rw_start_write(imap->bag->lock);
            radb_run_inject(master->_core.db, "UPDATE folders set subscribed = 0 WHERE id = %l", folder->fid);
            folder->subscribed = 0;
            rumble_rw_stop_write(imap->bag->lock); // Shared Object Writer Unlock
            rumble_comm_printf(session, "%s OK UNSUBSCRIBE completed\r\n", extra_data);
        }
    } else rumble_comm_printf(session, "%s BAD Invalid UNSUBSCRIBE syntax!\r\n", extra_data);
    rumble_args_free(args);
    return (RUMBLE_RETURN_IGNORE);
}



// LIST

ssize_t rumble_server_imap_list(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;
    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    rumble_args * args = rumble_read_words(parameters);
    if (args && args->argc == 2) {
        char * pattern = args->argv[1];
        rumble_rw_start_read(imap->bag->lock);
        mailman_folder * folder = imap->folder;
        if (!folder) rumble_comm_send(session, "* LIST (\\Noselect) \".\" \"\"\r\n");
        else rumble_comm_printf(session, "* LIST (\\Noselect) \"\" \"%s\"\r\n", folder->name);
        for (int i = 0; i < imap->bag->size; i++) {
            folder = &imap->bag->folders[i];
            if (folder->inuse) {
                int x = strncmp(pattern, folder->name, strlen(pattern));
                char * xpattern = strchr(pattern, '*');
                if (x && xpattern)
                    if (x) x = strncmp(pattern, folder->name, strlen(pattern) - strlen(xpattern));

                if (!x) {
                    rumble_comm_printf(session, "* LIST () \".\" \"%s\"\r\n", folder->name);
                    IMAP_LOG("* LIST () \".\" \"%s\"\n", folder->name);
                }
            }
        }
        rumble_rw_stop_read(imap->bag->lock);
        rumble_comm_printf(session, "%s OK LIST completed\r\n", extra_data);
    } else rumble_comm_printf(session, "%s BAD Invalid LIST syntax!\r\n", extra_data);
    rumble_args_free(args);
    return (RUMBLE_RETURN_IGNORE);
}

// LSUB

ssize_t rumble_server_imap_lsub(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;
    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    rumble_args * args = rumble_read_words(parameters);
    if (args && args->argc == 2) {
        // Shared Object Reader Lock
        rumble_rw_start_read(imap->bag->lock);
        if (imap->folder) {
            rumble_comm_printf(session, "* LSUB () \".\" \"INBOX\"\r\n");
            for (int i = 0; i < imap->bag->size; i++) {
                mailman_folder * folder = &imap->bag->folders[i];
                if (folder->inuse && folder->subscribed) rumble_comm_printf(session, "* LSUB () \".\" \"%s\"\r\n", folder->name);
            }
        }
        // Shared Object Reader Unlock
        rumble_rw_stop_read(imap->bag->lock);
        rumble_comm_printf(session, "%s OK LSUB completed\r\n", extra_data);
    } else rumble_comm_printf(session, "%s BAD Invalid LSUB syntax!\r\n", extra_data);
    rumble_args_free(args);
    return (RUMBLE_RETURN_IGNORE);
}


// STATUS

ssize_t rumble_server_imap_status(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    int messages = 0, recent = 0, unseen = 0;
    char * folderName = 0;
    mailman_folder * folder = 0;
    accountSession  *imap = (accountSession *) session->_svcHandle;

    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    rumble_args * args = rumble_read_words(parameters);
    if (args && args->argc >= 1) {
        folderName = args->argv[0];
        folder = mailman_get_folder(imap->bag, folderName);
        if (!folder) {
            rumble_comm_printf(session, "%s NO STATUS failed: No such folder <%s>\r\n", extra_data, folderName);
            return (RUMBLE_RETURN_IGNORE);
        }
    }
    mailman_update_folder(folder, imap->bag->uid, 0);

    // Retrieve the status of the folder
    rumble_rw_start_read(imap->bag->lock);
    for (int i = 0; i < folder->size; i++) {
        mailman_letter * letter = &folder->letters[i];
        if (letter) {
            if (!(letter->flags & RUMBLE_LETTER_READ) || (letter->flags == RUMBLE_LETTER_RECENT)) unseen++;
            if (letter->flags & RUMBLE_LETTER_RECENT) recent++;
            messages++;
        }
    }
    rumble_rw_stop_read(imap->bag->lock);
    rumble_comm_printf(session, "%s STATUS %s ", extra_data, folderName);
    for (int x = 1; x < args->argc; x++) {
        if (strstr(args->argv[x], "UNSEEN")) rumble_comm_printf(session, "UNSEEN %u ", unseen);
        if (strstr(args->argv[x], "RECENT")) rumble_comm_printf(session, "RECENT %u ", recent);
        if (strstr(args->argv[x], "MESSAGES")) rumble_comm_printf(session, "MESSAGES %u ", messages);
    }
    rumble_comm_printf(session, "\r\n");
    rumble_args_free(args);
    return (RUMBLE_RETURN_IGNORE);
}


// APPEND

ssize_t rumble_server_imap_append(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    char            *destFolder;
    char            *Flags = 0;
    uint32_t        size = 0;
    accountSession  *imap = (accountSession *) session->_svcHandle;
    mailman_folder  *folder = 0;
    uint32_t        readBytes = 0, flags = 0;

    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    rumble_args * params = rumble_read_words(parameters);
    if (params->argc > 1 && imap->bag) {
        IMAP_LOG("getting size of email");
        sscanf(params->argv[params->argc - 1], "{%d", &size);
        IMAP_LOG("size is %u bytes", size);
        destFolder = params->argv[0];
        Flags = params->argc > 2 ? params->argv[1] : "";
        // Shared Object Reader Lock
        folder = mailman_get_folder(imap->bag, destFolder);
    }

    if (strlen(Flags)) {
        if (strstr(Flags, "\\Seen")) flags |= RUMBLE_LETTER_READ;
        if (strstr(Flags, "\\Recent")) flags |= RUMBLE_LETTER_RECENT;
        if (strstr(Flags, "\\Deleted")) flags |= RUMBLE_LETTER_DELETED;
        if (strstr(Flags, "\\Flagged")) flags |= RUMBLE_LETTER_FLAGGED;
    }

    rumble_args_free(params);
    if (!size || !folder) {
        rumble_comm_printf(session, "%s BAD Invalid APPEND syntax!\r\n", extra_data);
    } else {
        IMAP_LOG("Append required, making up new filename");
        char * fid = rumble_create_filename();
        char * sf = imap->bag->path;
        char * filename = (char*)calloc(1, strlen(sf) + 36);
        if (!filename) merror();
        sprintf(filename, "%s/%s.msg", sf, fid);
        IMAP_LOG("Storing new message of size %u in folder", size);
        FILE * fp = fopen(filename, "wb");
        if (fp) {
            char    OK = 1;
            IMAP_LOG("Writing to file %s", filename);
            rumble_comm_printf(session, "%s OK Appending!\r\n", extra_data); // thunderbird bug?? yes it is!
            while (readBytes < size) {
                char * line = rumble_comm_read_bytes(session, size > 1024 ? 1024 : size);
                if (line) {
                    readBytes += strlen(line);
                    fwrite(line, strlen(line), 1, fp);
                    free(line);
                } else {
                    OK = 0;
                    break;
                }
            }
            fclose(fp);
            if (!OK) {
                IMAP_LOG("An error occured while reading file from client");
                unlink(filename);
            } else {
                IMAP_LOG("File written OK");
                radb_run_inject(master->_core.mail, "INSERT INTO mbox (id,uid, fid, size, flags, folder) VALUES (NULL,%u, %s, %u,%u, %l)",
                                imap->account->uid, fid, size, flags, folder->fid);
                IMAP_LOG("Added message no. #%s to folder %llu of user %u", fid, folder->fid, imap->account->uid);
            }
        }
        free(filename);
        free(fid);
        // TODO: Check if there's room for storing message
    }
    // 003 APPEND saved-messages (\Seen) {310}
    return (RUMBLE_RETURN_IGNORE);
}

// CHECK
ssize_t rumble_server_imap_check(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    return (RUMBLE_RETURN_IGNORE);
}

// CLOSE
ssize_t rumble_server_imap_close(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;
    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    mailman_folder * folder = imap->folder;
    if (folder && imap->account && (session->flags & rumble_mailman_HAS_SELECT)) {
        mailman_commit(imap->bag, folder, 0);
        session->flags -= rumble_mailman_HAS_SELECT; // clear select flag
        imap->folder = 0;
        rumble_comm_printf(session, "%s OK Expunged and closed the mailbox.\r\n", extra_data);
    } else rumble_comm_printf(session, "%s NO CLOSE: No mailbox to close!\r\n", extra_data);
    return (RUMBLE_RETURN_IGNORE);
}


// EXPUNGE

ssize_t rumble_server_imap_expunge(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;
    mailman_folder  *folder = imap->folder;
    if (imap->account && (session->flags & rumble_mailman_HAS_SELECT) && folder) {
        mailman_commit(imap->bag, folder, 0);
        rumble_comm_printf(session, "%s OK Expunged them letters.\r\n", extra_data);
    } else rumble_comm_printf(session, "%s NO EXPUNGE: No mailbox selected for expunging!\r\n", extra_data);
    return (RUMBLE_RETURN_IGNORE);
}


// SEARCH
ssize_t rumble_server_imap_search(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    return (RUMBLE_RETURN_IGNORE);
}


// FETCH
ssize_t rumble_server_imap_fetch(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;
    size_t a, c, d = 0;
    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    mailman_folder * folder = imap->folder;
    if (!folder) {
        rumble_comm_printf(session, "%s NO No mailbox selected for fetching!\r\n", extra_data);
        return (RUMBLE_RETURN_IGNORE);
    }
    mailman_update_folder(folder, imap->account->uid, 0);
    int uid = strstr(parameters, "UID") ? 1 : 0;
    int internaldate = strstr(parameters, "INTERNALDATE") ? 1 : 0;
    //envelope = strstr(parameters, "ENVELOPE") ? 1 : 0;
    int size = strstr(parameters, "RFC822.SIZE") ? 1 : 0;
    //text = strstr(parameters, "RFC822.TEXT") ? 1 : 0;
    //header = strstr(parameters, "RFC822.HEADER") ? 1 : 0;
    int flags = strstr(parameters, "FLAGS") ? 1 : 0;
    int octets = 0;
    char line[1024];
    memset(line, 0, 1024);
    const char * body_peek = strstr(parameters, "BODY.PEEK[");
    const char * body = strstr(parameters, "BODY[");
    rumble_args * parts = 0;
    if (body) sscanf(body, "BODY[%1000[^]]<%u>", line, &octets);
    else if (body_peek)
        sscanf(body_peek, "BODY.PEEK[%1000[^]]<%u>", line, &octets);
    size_t w_uid = session->flags & rumble_mailman_HAS_UID;
    if (body || body_peek) {
        if (strlen(line)) {
            char region[32], buffer[1024];
            memset(region, 0, 32);
            memset(buffer, 0, 1024);
            if (sscanf(line, "%32s (%1000c)", region, buffer) == 2) {
                parts = rumble_read_words(buffer);
                for (int b = 0; b < parts->argc; b++) rumble_string_lower(parts->argv[b]);
            }
        }
    }

    rumble_args * params = rumble_read_words(parameters);
    rangePair       ranges[64];
    rumble_scan_ranges((rangePair *) &ranges, params->argc > 0 ? params->argv[0] : "0");
    for (int x = 0; ranges[x].start != 0; x++) {
        size_t first = ranges[x].start;
        size_t last = ranges[x].end;
        a = 0;
        d = 0;
        IMAP_LOG("Fetching letter %lu through %lu", first, last);
        for (int i = 0; i < folder->size; i++) {
            mailman_letter * letter = &folder->letters[i];
            if (!letter->inuse) continue;
            a++;
            if (w_uid && (letter->id < first || (last > 0 && letter->id > last))) continue;
            if (!w_uid && (a < first || (last > 0 && a > last))) continue;
            d++;
            rumble_comm_printf(session, "* %u FETCH (", a);
            if (flags) {
                rumble_comm_printf(session, "FLAGS (%s%s%s%s) ", (letter->flags == RUMBLE_LETTER_RECENT) ? "\\Recent " : "",
                         (letter->flags & RUMBLE_LETTER_READ) ? "\\Seen " : "", (letter->flags & RUMBLE_LETTER_DELETED) ? "\\Deleted " : "",
                         (letter->flags & RUMBLE_LETTER_FLAGGED) ? "\\Flagged " : "");
            }

            if (uid || w_uid) rumble_comm_printf(session, "UID %llu ", letter->id);
            if (size) rumble_comm_printf(session, "RFC822.SIZE %u ", letter->size);
            if (internaldate) rumble_comm_printf(session, "INTERNALDATE %u ", letter->delivered);
            if (body) letter->flags -= (letter->flags & RUMBLE_LETTER_RECENT); // Remove \Recent flag since we're not peeking
            if (body || body_peek) {
                FILE * fp = mailman_open_letter(imap->bag, folder, letter->id);
                if (!fp) {
                    // TODO Check it
                    IMAP_LOG("meh, couldn't open letter file");
                    letter->flags |= RUMBLE_LETTER_EXPUNGE;
                    mailman_commit(imap->bag, folder, 1);

                } else {
                    if (parts) {
                        char header[10240];
                        memset(header, 0, 10240);
                        while (fgets(line, 1024, fp)) {
                            c = strlen(line);
                            if (line[0] == '\r' || line[0] == '\n') break;
                            char key[64];
                            memset(key, 0, 64);
                            if (sscanf(line, "%63[^:]", key)) {
                                rumble_string_lower(key);
                                if (parts) {
                                    for (int b = 0; b < parts->argc; b++) {
                                        if (!strcmp(key, parts->argv[b])) {
                                            if (line[c - 2] != '\r') {
                                                line[c - 1] = '\r';
                                                line[c] = '\n';
                                                line[c + 1] = 0;
                                            }
                                            strncpy(header + strlen(header), line, strlen(line));
                                        }
                                    }
                                } else {
                                     // if ( line[c-2] != '\r' ) {line[c-1] = '\r';
                                     // line[c] = '\n';
                                     // line[c+1] = 0;
                                    strncpy(header + strlen(header), line, strlen(line));
                                }
                            }
                        }
                        sprintf(header + strlen(header), "\r\n \r\n");
                        rumble_comm_printf(session, "BODY[HEADER.FIELDS (%s)] {%u}\r\n", line, strlen(header));
                        rumble_comm_send(session, header);
                        IMAP_LOG("BODY[HEADER.FIELDS (%s)] {%u}", line, strlen(header));
                        IMAP_LOG("%s", header);
                    } else {
                        rumble_comm_printf(session, "BODY[] {%u}\r\n", letter->size);
                        IMAP_LOG("BODY[] {%u}", letter->size);
                        memset(line, 0, 1024);
                        while (fgets(line, 1024, fp)) {
                            rumble_comm_send(session, line);
                            IMAP_LOG("%s", line);
                        }
                    }
                    fclose(fp);
                }
                rumble_comm_send(session, " ");
            }
            rumble_comm_printf(session, ")\r\n");
        }
    }
    if (parts) rumble_args_free(parts);
    rumble_args_free(params);
    rumble_comm_printf(session, "%s OK FETCH completed\r\n", extra_data);
    if (folder) IMAP_LOG("Fetched %lu letters from <%s>", d, folder->name);
    return (RUMBLE_RETURN_IGNORE);
}


// STORE

ssize_t rumble_server_imap_store(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    accountSession  *imap = (accountSession *) session->_svcHandle;
    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    mailman_folder * folder = imap->folder;
    if (!folder) {
        rumble_comm_printf(session, "%s NO STORE: No mailbox selected for storing!\r\n", extra_data);
        return (RUMBLE_RETURN_IGNORE);
    }

    int useUID = session->flags & rumble_mailman_HAS_UID;

    // Get the store type
    //int silent = strstr(parameters, ".SILENT") ? 1 : 0;
    int  control = strchr(parameters, '+') ? 1 : (strchr(parameters, '-') ? -1 : 0);
    char            args[100];
    memset(args, 0, 100);
    sscanf(parameters, "%*100[^(](%99[^)])", args);

    // Set the master flag
    int flag = 0;
    flag |= strstr(parameters, "\\Deleted") ? RUMBLE_LETTER_DELETED : 0;
    flag |= strstr(parameters, "\\Seen") ? RUMBLE_LETTER_READ : 0;
    flag |= strstr(parameters, "\\Flagged") ? RUMBLE_LETTER_FLAGGED : 0;
    flag |= strstr(parameters, "\\Draft") ? RUMBLE_LETTER_DRAFT : 0;
    flag |= strstr(parameters, "\\Answered") ? RUMBLE_LETTER_ANSWERED : 0;
    flag |= strstr(parameters, "\\Recent") ? RUMBLE_LETTER_RECENT : 0;

    // Process the letters ;
    // For each range, set the message stuf
    rumble_args * parts = rumble_read_words(parameters);
    if (parts->argc > 1) {
        rangePair ranges[64];
        rumble_scan_ranges((rangePair *) &ranges, parts->argv[0]);
        for (int x = 0; ranges[x].start != 0; x++) {
            uint64_t first = ranges[x].start;
            uint64_t last = ranges[x].end;
            IMAP_LOG("Storing flags for letter %lu through %lu", first, last);
            if (control == -1) mailman_remove_flags(folder, flag, useUID, first, last);
            if (control == 0) mailman_set_flags(folder, flag, useUID, first, last);
            if (control == 1) mailman_add_flags(folder, flag, useUID, first, last);
        }
    }
    rumble_args_free(parts);
    rumble_comm_printf(session, "%s OK STORE completed.\r\n", extra_data);
    return (RUMBLE_RETURN_IGNORE);
}



// COPY

ssize_t rumble_server_imap_copy(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    // Check for selected folder
    accountSession  *imap = (accountSession *) session->_svcHandle;
    mailman_folder  *folder = imap->folder;
    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    // Is a folder selected to copy from?
    if (!folder) {
        rumble_comm_printf(session, "%s NO COPY: I don't know where to copy from!\r\n", extra_data);
        return (RUMBLE_RETURN_IGNORE);
    }
    int useUID = session->flags & rumble_mailman_HAS_UID; // Are we using UIDs?
    char folderName[100]; // Get the destination folder
    memset(folderName, 0, 100);
    rumble_args * parts = rumble_read_words(parameters);
    if (parts->argc >= 2) {
        int a = strlen(parts->argv[parts->argc - 1]);
        strncpy(folderName, parts->argv[parts->argc - 1], a < 100 ? a : 99);
    }

    // Check if folder exists
    mailman_folder * destination = mailman_get_folder(imap->bag, folderName);
    if (!destination) {
        rumble_comm_printf(session, "%s NO COPY [TRYCREATE] failed: Destination folder doesn't exist!\r\n", extra_data);
        return (RUMBLE_RETURN_IGNORE);
    }

    // For each range, copy the messages
    rangePair ranges[64];
    rumble_scan_ranges((rangePair *) &ranges, parts->argv[0]);
    rumble_args_free(parts);
    for (int x = 0; ranges[x].start != 0; x++) {
        uint64_t first = ranges[x].start;
        uint64_t last = ranges[x].end;
        mailman_copy_letter(imap->bag, folder, destination, first, last, useUID);
    }
    rumble_comm_printf(session, "%s OK COPY completed\r\n", extra_data);
    return (RUMBLE_RETURN_IGNORE);
}


// IDLE

ssize_t rumble_server_imap_idle(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    int rc = -1, cc = 0, exists = 0, recent = 0, first = 0, oexists = 0, orecent = 0, ofirst = 0;
    mailman_letter  *letter;
    accountSession  *imap = (accountSession *) session->_svcHandle;
    mailman_folder  *folder = imap->folder;
    if (!imap->account) return (RUMBLE_RETURN_IGNORE);
    if (!folder) {
        rumble_comm_printf(session, "%s NO No mailbox selected for fetching!\r\n", extra_data);
        return (RUMBLE_RETURN_IGNORE);
    }

    rumble_comm_printf(session, "%s OK IDLE Starting idle mode.\r\n", extra_data);
    char buffer[5];
    memset(buffer, 0, 5);

    // Retrieve the statistics of the folder before idling
    rumble_rw_start_read(imap->bag->lock);
    for (int i = 0; i < folder->size; i++) {
        letter = &folder->letters[i];
        if (!letter->inuse) continue;
        oexists++;
        if (!ofirst && (!(letter->flags & RUMBLE_LETTER_READ) || (letter->flags == RUMBLE_LETTER_RECENT))) ofirst = oexists;
        if (letter->flags == RUMBLE_LETTER_RECENT) orecent++;
    }

    rumble_rw_stop_read(imap->bag->lock);

    // While idle, check for stuff, otherwise break off
    while (rc < 0)
    {
        rc = recv(session->client->socket, buffer, 1, MSG_PEEK | MSG_DONTWAIT);
        if (rc == 1) break; // got data from client again
        else if (rc == 0) {
            IMAP_LOG("Idle: disconnected");
            return (RUMBLE_RETURN_FAILURE); // disconnected?
        } else if (rc == -1) {
            cc++;
            if (cc == 10) {
                // Check the DB for new messages every 50 seconds
                mailman_update_folder(folder, imap->bag->uid, 0);
                cc = 0;
            }

            rumble_rw_start_read(imap->bag->lock);
            for (int i = 0; i < folder->size; i++) {
                letter = &folder->letters[i];
                if (!letter->inuse) continue;
                exists++;
                if (!first && (!(letter->flags & RUMBLE_LETTER_READ) || (letter->flags == RUMBLE_LETTER_RECENT))) first = exists;
                if (letter->flags == RUMBLE_LETTER_RECENT) recent++;
            }

            rumble_rw_stop_read(imap->bag->lock);
            if (oexists != exists) {
                rc = rumble_comm_printf(session, "* %u EXISTS\r\n", exists);
                if (rc == -1) break;
                oexists = exists;
            }

            if (recent != orecent) {
                rc = rumble_comm_printf(session, "* %u RECENT\r\n", exists);
                if (rc == -1) break;
                orecent = recent;
            }
            exists = 0;
            recent = 0;
            first = 0;
            sleep(5);
        }
    }

    char * line = rumble_comm_read(session);
    if (!line) return (RUMBLE_RETURN_FAILURE);
    else {
        free(line);
        rumble_comm_printf(session, "%s OK IDLE completed.\r\n", extra_data);
        IMAP_LOG("Idle done");
        return (RUMBLE_RETURN_IGNORE);
    }
}


ssize_t rumble_server_imap_logout(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    IMAP_LOG("Logging out");
    return (RUMBLE_RETURN_FAILURE);
}


// TESTING

ssize_t rumble_server_imap_test(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data) {
    int         x = 0;
    rangePair   ranges[64];
    rumble_comm_printf(session, "<%s>\r\n", parameters);
    rumble_scan_ranges((rangePair *) &ranges, parameters);
    while (1) {
        if (!ranges[x].start) break;
        IMAP_LOG("start: %lu, stop: %lu", ranges[x].start, ranges[x].end);
        x++;
    }
    return (RUMBLE_RETURN_IGNORE);
}
