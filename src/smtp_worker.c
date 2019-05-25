#include "rumble.h"
#include "comm.h"
#include "private.h"
#include "mailman.h"
#include <sys/stat.h>
#include <dirent.h>
#   include "servers.h"

#define WAIT_OTHERS 3

mqueue * current = 0;
const char * svcs[] = { "imap4", "pop3", "smtp", "mailman", 0 };
const char * statement = "SELECT time, loops, fid, sender, recipient, flags, id FROM queue WHERE time <= strftime('%%s','now') LIMIT 4";


void rumble_prune_storage(const char *folder) {
    struct stat     fileinfo;
    struct dirent   *dirp;
    char            filename[512];
    time_t now = time(0);
    DIR * dir = opendir(folder);
    if (dir != NULL) {
        while ((dirp = readdir(dir))) {
            if (dirp->d_name[0] == '.' || strstr(dirp->d_name, ".msg")) continue;
            sprintf(filename, "%s/%s", folder, dirp->d_name);
            if (stat(filename, &fileinfo) == -1) continue;
            if ((now - fileinfo.st_atime) > 43200) {
                unlink(filename);
            }
        }
        closedir(dir);
    }
}

// MTA delivery worker
void *rumble_worker_process(void *m) {
    rumbleService   *svc = (rumbleService *) m;
    masterHandle    *master = svc->master;
    sessionHandle   *sess = (sessionHandle *) malloc(sizeof(sessionHandle)), *s;
    clientHandle    c;
    d_iterator      diter;

    int maxAttempts = atoi(rumble_get_dictionary_value(master->_core.conf, "deliveryattempts"));
    maxAttempts = maxAttempts ? maxAttempts : 5; // TODO maxAttempts to #define
    sess->client = &c;
    sess->_svc = svc;
    if (!sess) merror();
    sess->_master = (masterHandle *) svc->master;
    while (1) {
        pthread_mutex_lock(&svc->mutex);
        pthread_cond_wait(&svc->cond, &svc->mutex);
        dvector_add(svc->handles, (void*)sess);
        svc->traffic.sessions++;

        // Move the item struct to a private address and free up the global one
        mqueue * item = current;
        current = 0;
        pthread_mutex_unlock(&svc->mutex);
        if (!item) continue;

        // Check for rampant loops
        item->loops++;
        if (item->loops > maxAttempts) {
            rumble_debug(NULL, "mailman", "Message %s is looping, dumping it!\n", item->fid);
            if (strcmp(item->sender->user, "mailman") || strcmp(item->sender->domain, "localhost")) {
                smtp_deliver_failure(master, item->sender->raw, item->recipient->raw,
                                     "Reason: Message seems to be looping.");
            }
            // cleanup
            if (item->recipient) rumble_free_address(item->recipient);
            if (item->sender)    rumble_free_address(item->sender);
            if (item->fid)       free( (char*)item->fid);
            if (item->flags)     free( (char*)item->flags);
            item->account = 0;
            free(item);
            continue;
        }

        // Local delivery?
        if (rumble_domain_exists(item->recipient->domain)) {
            rumble_debug(NULL, "mailman", "Have mail for %s (local domain), looking for user %s@%s", item->recipient->domain,
                         item->recipient->user, item->recipient->domain);
            rumble_mailbox * user = rumble_account_data(0, item->recipient->user, item->recipient->domain);
            if (user) {
                int knowType = 0;
                item->account = user;
                // pre-delivery parsing (virus, spam, that sort of stuff)
                ssize_t rc = rumble_server_schedule_hooks(master, (sessionHandle*) item, RUMBLE_HOOK_PARSER);
                // hack, hack..
                if (rc == RUMBLE_RETURN_OKAY) {
                    if (user->type & RUMBLE_MTYPE_MBOX)  knowType = smtp_deliver_mbox(user, item, master);
                    if (user->type & RUMBLE_MTYPE_ALIAS) knowType = smtp_deliver_alias(user, item, master);
                    if (user->type & RUMBLE_MTYPE_FEED)  knowType = smtp_deliver_feed(user, item, master);
                    if (user->type & RUMBLE_MTYPE_RELAY) knowType = smtp_deliver_foreign(item, master, user->arg);
                    if (user->type & RUMBLE_MTYPE_MOD)   knowType =
                        rumble_server_schedule_hooks(master, (sessionHandle*)item, RUMBLE_HOOK_FEED);
                }
                if (knowType == 0) {
                    rumble_debug(master, "mailman", "Account <%s@%s> has unknown mailbox type, ignoring mail :(\n", user->user, user->domain->name);
                }
                rumble_free_account(user);
            } else {
                printf("I couldn't find %s :(\n", item->recipient->raw);
            }
        } else smtp_deliver_foreign(item, master, item->recipient->domain); // Foreign delivery...

        // cleanup
        if (item->recipient)    rumble_free_address(item->recipient);
        if (item->sender)       rumble_free_address(item->sender);
        if (item->fid)          free((char *) item->fid);
        if (item->flags)        free((char *) item->flags);
        item->account = 0;
        free(item);

        // Signal we're free for another job
        dforeach((sessionHandle*), s, svc->handles, diter) {
            if (s == sess) {
                dvector_delete(&diter);
                break;
            }
        }
    } // loop
    return NULL;
}

// Trash collector
void *rumble_sanitation_process(void *m) {
    rumbleService   *svc = (rumbleService *) m;
    masterHandle    *master = svc->master;
    d_iterator      iter;
    rumble_domain   *domain;
    const char * mainpath = rumble_config_str(master, "storagefolder");
    const char * localpath = 0;
    while (1) {
        // Check the main storage folder
        rumble_prune_storage(mainpath);
        // Check for invididually set storage folders
        rumble_rw_start_read(master->domains.rrw);

        dforeach((rumble_domain *), domain, master->domains.list, iter) {
            localpath = domain->path;
            if (localpath && strlen(localpath) && strcmp(localpath, mainpath))
                rumble_prune_storage(localpath);
        }

        rumble_rw_stop_read(master->domains.rrw);
        sleep(14400);
    }
    return NULL;
}


void *rumble_worker_init(void *T) {
    rumbleThread    *thread = (rumbleThread *) T;
    rumbleService   *svc = (rumbleService *) thread->svc;
    masterHandle    *master = (masterHandle *) svc->master;

    sleep(WAIT_OTHERS); // TODO wait for the others :>

    pthread_attr_t  attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 128 * 1024);   /* let's see if 512kb is enough
                                                     * ;
                                                     * > */
    // MTA workers
    for (int x = 0; x < 20; x++) {
        thread = (rumbleThread *) malloc(sizeof(rumbleThread));
        cvector_add(svc->threads, thread);
        thread->status = 1;
        pthread_create(&thread->thread, &attr, rumble_worker_process, svc);
    }

    // Trash collector
    thread = (rumbleThread *) malloc(sizeof(rumbleThread));
    cvector_add(svc->threads, thread);
    thread->status = 1;
    pthread_create(&thread->thread, &attr, rumble_sanitation_process, svc);

    radbObject * dbo = radb_prepare(master->_core.mail, statement);
    if (!dbo) printf("Something went wrong with this: %s\n", statement);

    while (1) {
        radbResult * result = radb_fetch_row(dbo);
        if (result) {
            mqueue * item = (mqueue*)calloc(1, sizeof(mqueue));
            if (item) {
                item->mType     = 0;
                item->date      = result->column[0].data.uint32; // delivery time
                item->loops     = result->column[1].data.uint32; // loops
                item->fid       = strclone(result->column[2].data.string); // fid
                item->sender    = rumble_parse_mail_address(result->column[3].data.string); // sender
                item->recipient = rumble_parse_mail_address(result->column[4].data.string); // recipient
                item->flags =   strclone(result->column[5].data.string); // flags

                radb_run_inject(master->_core.mail, "DELETE FROM queue WHERE id = %u", result->column[6].data.uint32);
                fflush(stdout);

                if (!item->sender || !item->recipient) {
                    printf("BAD: Sender or Recipient is invalid, discarding mail.\n");
                    if (item->recipient)    rumble_free_address(item->recipient);
                    if (item->sender)       rumble_free_address(item->recipient);
                    if (item->fid)          free( (char*)item->fid );
                    if (item->flags)        free( (char*)item->flags );
                    item->account = 0;
                    free(item);

                } else {
                    pthread_mutex_lock(&svc->mutex);
                    current = item;
                    pthread_cond_signal(&svc->cond);
                    pthread_mutex_unlock(&svc->mutex);
                }
            }
        } else { // no result
            // Update traffic stats while we're doing nothing
            for (int K = 0; K < 4; K++) {
                rumbleService * xsvc = comm_serviceHandle(svcs[K]);
                if (xsvc) comm_addEntry(xsvc, 0, 100);
            }

            radb_cleanup(dbo);
            // sleep for 3 seconds if there's nothing to do right now.
            sleep(WAIT_OTHERS);
            dbo = radb_prepare(master->_core.mail, statement);
        }
    }

    radb_cleanup(dbo);
    return NULL;
}
