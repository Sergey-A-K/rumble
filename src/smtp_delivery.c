#include <stdlib.h>

#include "rumble.h"
#include "sqlite3.h"
#include "servers.h"
#include "private.h"
#include "database.h"
#include "comm.h"
#include "mailman.h"
#include <sys/stat.h>
#include <errno.h>


const char tmp_mask[] = "%s/smtp_deliver-XXXXXX"; // TODO move this to setting file

const char * smtp_df_sql = "INSERT INTO queue (id,loops, fid, sender, recipient, flags) VALUES (NULL,%u,%s,%s,%s,%s)";
const char * smtp_da_sql = "INSERT INTO queue (id,loops, fid, sender, recipient, flags) VALUES (NULL,%s,%s,%s,%s,%s)";
const char * smtp_dm_sql = "INSERT INTO mbox (id,uid, fid, size, flags) VALUES (NULL,%u, %s, %u,0)";
const char * smtp_do_sql = "INSERT INTO queue (id,time, loops, fid, sender, recipient, flags) VALUES (NULL,strftime('%%%%s', 'now', '+%u seconds'),%%u,%%s,%%s,%%s,%%s)";
const char * smtp_df_mmlh = "Mailer Daemon <mailman@localhost>";

int smtp_deliver_feed(rumble_mailbox *user, mqueue *item, masterHandle *master) {
    rumble_debug(master, "mailman", "Feeding email to program <%s>", user->arg);

    const char * path = rumble_config_str(master, "storagefolder");
    char * filename = (char*)calloc(1, strlen(path) + 24); // TODO max char ulong 20
    sprintf(filename, "%s/%s", path, item->fid);


    char * tempfile = (char*)calloc(1, strlen(path) + strlen(tmp_mask) + 1);
    sprintf(tempfile, tmp_mask, path);

    int fd = mkstemp(tempfile);
    if(fd == -1){
        rumble_debug(master, "mailman", "ERR mkstemp(%s):%s", tempfile, strerror(errno));
    } else {
        rumble_debug(master, "mailman", "Temporary file [%s] created\n", tempfile);
        close (fd);
    }

    char buffer[2001]; // TODO Alloc
    sprintf(buffer, "%s < %s > %s", user->arg, filename, tempfile);
    printf("Executing: %s\n", buffer);
    system(buffer);

    FILE * fp = fopen(tempfile, "rb");
    if (fp) {

        if (!fgets(buffer, 2000, fp))
            memset(buffer, 0, 2000);

        while (strlen(buffer) > 2) {
            size_t i = strlen(buffer);
            char xarg[2001];
            char xuser[129];
            char xdomain[129];
            memset(xarg, 0, 2001);
            memset(xuser, 0, 129);
            memset(xdomain, 0, 129);
            if (buffer[i - 1] == '\n') buffer[i - 1] = 0;
            if (buffer[i - 2] == '\r') buffer[i - 2] = 0;

            if (sscanf(buffer, "R-FORWARD %256c", xarg)) {
                rumble_debug(master, "mailman", "Forwarding letter to %s\n", xarg);
                radb_run_inject(master->_core.mail, smtp_df_sql, 1, item->fid, item->sender->raw, xarg, item->flags);
            }

            if (sscanf(buffer, "R-REPLY %256c", xarg)) {
                char * fid = 0;
                rumble_debug(master, "mailman", "Replying with message file <%s>\n", xarg);
                if (rumble_mail_from_file(master, xarg, &fid)) { // if length
                    radb_run_inject(master->_core.mail, smtp_df_sql, 1, fid, item->recipient->raw, item->sender->raw, item->flags);
                }
            }

            if (sscanf(buffer, "R-SEND <%128[^@ ]@%128[^>]> %256c", xuser, xdomain, xarg) == 3) {
                char * fid = 0;
                char recipient[260];
                rumble_debug(master, "mailman", "Sending message <%s> to <%s@%s>\n", xarg, xuser, xdomain);
                sprintf(recipient, "<%s@%s>", xuser, xdomain);
                if (rumble_mail_from_file(master, xarg, &fid)) { // if length
                    radb_run_inject(master->_core.mail, smtp_df_sql, 1, fid, item->recipient->raw, recipient, item->flags);
                }
            }

            if (sscanf(buffer, "R-DELETE %256c", xarg)) {
                rumble_debug(master, "mailman", "Deleting file <%s>\n", xarg);
                unlink(xarg);
            }

            if (!fgets(buffer, 2000, fp)) break;
        }
        fclose(fp);
    }
    unlink(tempfile);
    unlink(filename);
    free(tempfile);
    free(filename);
    return RUMBLE_RETURN_OKAY;
}





int smtp_deliver_alias(rumble_mailbox *user, mqueue *item, masterHandle *master) {
    rumble_debug(master, "mailman", "%s@%s is an alias, looking up arguments", user->user, user->domain->name);
    if (strlen(user->arg)) {
        char * pch = strtok(user->arg, " ,;");
        char * email = (char*)calloc(1, 256);
        while (pch != NULL) {
            memset(email, 0, 128);
            if (strlen(pch) >= 3) {
                char * loops = (char*)calloc(1, 4);
                sprintf(loops, "%u", item->loops);
                if (sscanf(pch, "%256c", email)) {
                    rumble_string_lower(email);
                    char xemail[256];
                    memset(xemail, 0, 256);
                    snprintf(xemail, 255, "<%s>", email);
                    rumble_debug(master, "mailman", "Delivering message %s to alias %s...", item->fid, xemail);
                    radb_run_inject(master->_core.mail, smtp_da_sql, loops, item->fid, item->sender->raw, xemail, item->flags);
                }
            }
            pch = strtok(NULL, " ,;");
        }
        free(email);
    } else {
        rumble_debug(master, "mailman", "No arguments supplied for alias account!");
    }
    return RUMBLE_RETURN_OKAY;
    // done here!
}




int smtp_deliver_mbox(rumble_mailbox *user, mqueue *item, masterHandle *master) {
    rumble_debug(master, "mailman", "Delivering message %s to mailbox %s @ %s...", item->fid, user->user, user->domain->name);

    // Start by making a copy of the letter
    size_t fsize = rumble_copy_mail(master, item->fid, user->user, user->domain->name, (char **) &item->fid);
    if (!item->fid || !fsize) {
        if (item->fid) free((void *) item->fid);
        rumble_debug(master, "mailman", "message %s could not be read, aborting", item->fid);
        return 1;
    }
    // move file to user's inbox
    const char  *defaultPath = rumble_config_str(master, "storagefolder");
    const char  *domainStoragePath = strlen(user->domain->path) ? user->domain->path : defaultPath;
    char * ofilename = (char*)calloc(1, strlen(defaultPath) + 26);
    char * nfilename = (char*)calloc(1, strlen(domainStoragePath) + 26);
    sprintf(ofilename, "%s/%s", defaultPath, item->fid);
    sprintf(nfilename, "%s/%s.msg", domainStoragePath, item->fid);
#ifdef RUMBLE_DEBUG_STORAGE
    rumble_debug(master, "mailman", "Moving %s to %s", ofilename, nfilename);
#endif
    if (rename(ofilename, nfilename)) {
        perror("Couldn't move file");
    }
    free(ofilename);
    free(nfilename);
    radb_run_inject(master->_core.mail, smtp_dm_sql, item->account->uid, item->fid, fsize);
    // done here!
    return RUMBLE_RETURN_OKAY;
}


int smtp_deliver_foreign(mqueue *item, masterHandle *master, const char *host) {
    char                        serverReply[2048];
    uint32_t                    delivered = 500;
    d_iterator                  iter;

    int maxAttempts = atoi(rumble_get_dictionary_value(master->_core.conf, "deliveryattempts"));
    maxAttempts = maxAttempts ? maxAttempts : 5; // TODO move to define

    int retryInterval = atoi(rumble_get_dictionary_value(master->_core.conf, "retryinterval"));
    retryInterval = retryInterval ? retryInterval : 360; // TODO move to define

    const char * ignmx = rumble_get_dictionary_value(master->_core.conf, "ignoremx");
    dvector * badmx = dvector_init();
    if (strlen(ignmx)) rumble_scan_words(badmx, ignmx);

    rumble_debug(master, "mailman", "mail %s: %s@%s is a foreign user, finding host <%s>.", item->fid, item->recipient->user,
                 item->recipient->domain, host);
    dvector * mx = comm_mxLookup(host);
    if (!mx || !mx->size) {
        rumble_debug(master, "mailman", "Couldn't look up domain %s, faking a SMTP 450 error.", host);
        delivered = 450;
        sprintf(serverReply, "Reason: Unable to resolve hostname '%s'", host);
    } else if (mx->size) {
        char * filename = (char*)calloc(1, 256);
        if (!filename) merror();
        sprintf(filename, "%s/%s", rumble_get_dictionary_value(master->_core.conf, "storagefolder"), item->fid);
        mxRecord * mxr;
        dforeach((mxRecord *), mxr, mx, iter) {
            if (rumble_has_dictionary_value(badmx, mxr->host)) continue; // ignore bogus MX records
            rumble_debug(master, "mailman", "Trying %s (%u)...\n", mxr->host, mxr->preference);
            // Anything below 300 would be good here :>
            rumble_sendmail_response * res = rumble_send_email(master, mxr->host, filename, item->sender, item->recipient);
            // get the best result from all servers we've tried
            delivered = (res->replyCode < delivered) ? res->replyCode : delivered;
            rumble_debug(master, "mailman", "MTA <%s> returned code %d (%s)", res->replyServer, delivered, res->replyMessage);
            sprintf(serverReply, "<%s> said: [%d] %s", res->replyServer, res->replyCode, res->replyMessage);
            rumble_flush_dictionary(res->flags);
            free(res->flags);
            free(res->replyMessage);
            free(res->replyServer);
            free(res);
            if (delivered <= 299) break; // yay!
        }
        free(filename);
    }
    if (delivered >= 500)
        smtp_deliver_failure(master, item->sender->raw, item->recipient->raw, serverReply);
    else
        if (delivered >= 400) {
        // If we have tried 5 times without succeess, it's time to end this.
        if (item->loops >= maxAttempts)
            smtp_deliver_failure(master, item->sender->raw, item->recipient->raw, serverReply);
        else {
            // temp failure, push mail back into queue (schedule next try in 6 minutes).
            rumble_debug(master, "mailman", "MTA reported temporary error(%u), queuing mail for later (+%u secs)",
                delivered, retryInterval);
            char statement[1024];
            sprintf(statement, smtp_do_sql, retryInterval);
            radb_run_inject(master->_core.mail, statement,
                item->loops, item->fid, item->sender->raw, item->recipient->raw, item->flags);
            rumble_debug(master, "mailman", "Mail %s queued", item->fid);
        }
    } else {
        rumble_debug(master, "mailman", "Mail %s delivered.", item->fid);
    }
    // Clean up DNS records
    if (mx) comm_mxFree(mx);
    rumble_flush_dictionary(badmx);
    dvector_destroy(badmx);
    return RUMBLE_RETURN_OKAY; // All done!
}


int smtp_deliver_failure(masterHandle *master, const char *sender, const char *recipient, const char *reason) {
    rumble_debug(master, "mailman", "Critical failure, letting sender know");
    const char  * sf = rumble_config_str(master, "storagefolder");
    char * newfilename = (char*)calloc(1, strlen(sf) + 26);
    char * fid = rumble_create_filename();
    sprintf(newfilename, "%s/%s", sf, fid);
    FILE * fp = fopen(newfilename, "wb");
    if (fp) {
        fprintf(fp, "To: %s\r\nFrom: %s\r\n\
Subject: Delivery failed\r\n\r\n\
The email you sent to %s failed to be delivered.\r\n\
%s\r\n\r\n", sender, smtp_df_mmlh, recipient, reason);
        radb_run_inject(master->_core.mail, smtp_df_sql, 1, fid, smtp_df_mmlh, sender, "");
        fclose(fp);
    }
    free(newfilename);
    free(fid);
    return 1;
}


// Private handling function for rumble_send_email()
void get_smtp_response(sessionHandle *session, rumble_sendmail_response *res) {
    unsigned char   b = '-';
    res->replyCode = 500;
    char * flag = (char*)calloc(1, 200);
    if (!flag) merror();
    if (res) {
        while (b == '-') {
            char * line = rumble_comm_read(session);
            if (!line) break;
            res->replyCode = 500;
            // printf("MTA: %s\n", line);
            memset(res->replyMessage, 0, 1000);
            if (sscanf(line, "%3u%c%200c", &res->replyCode, &b, res->replyMessage) < 2) {
                res->replyCode = 500;
                break;
            }
            memset(flag, 0, 200);
            if (sscanf(line, "%*3u%*1[ %-]%20[A-Z0-9]", flag)) {
                if (strlen(flag) > 2) {
                    rumble_add_dictionary_value(res->flags, flag, flag);
                }
            }
            free(line);
        }
    }
    free(flag);
    if (res->replyCode == 500) ((rumbleService *) session->_svc)->traffic.rejections++;
}



rumble_sendmail_response    *rumble_send_email
                            (
                                masterHandle    *master,
                                const char      *mailserver,
                                const char      *filename,
                                address         *sender,
                                address         *recipient
                            ) {
    clientHandle                c;
    sessionHandle               s;
    s.client = &c;
    s._tflags = 0;
    s._svc = comm_serviceHandleExtern(master, "mailman");
    rumble_sendmail_response * res = (rumble_sendmail_response *) malloc(sizeof(rumble_sendmail_response));
    if (!res) merror();
    res->flags = dvector_init();
    res->replyCode = 500;
    res->replyMessage = (char*)calloc(1, 1024);
    res->replyServer  = (char*)calloc(1, strlen(mailserver) + 1);
    if (!res->replyServer || !res->replyMessage || !res->flags) merror();
    res->replyServer = strclone(mailserver);
    sprintf(res->replyMessage, "Server could not be reached.");
    FILE * fp = fopen(filename, "rb");
    if (!fp) {
        perror("Couldn't open file!");
        return (res);
    }
    fseek(fp, 0, SEEK_END);
    size_t fsize = ftell(fp);
    rewind(fp);
    res->replyCode = 250;
    rumble_debug(master, "mailman", "connecting to %s...", mailserver);


    c.tls_session = 0;
    c.socket = comm_open(master, mailserver, 25);
    c.recv = 0;
    c.send = 0;
    c.brecv = 0;
    c.bsent = 0;
    const char * me = rumble_get_dictionary_value(master->_core.conf, "servername");
    FD_ZERO(&c.fd);
    FD_SET(c.socket, &c.fd);

    // Append BATV (unless we already have BATV or VERP)
    if (!strlen(sender->tag)) {
        char                *batv = rumble_create_filename();
        sprintf(sender->tag, "prvs=%s", batv);
        rumbleKeyValuePair * el = (rumbleKeyValuePair *) malloc(sizeof(rumbleKeyValuePair));
        if (!el) merror();
        el->key = batv;
        el->value = (char *) time(0);
        dvector_add(master->_core.batv, el);
    }

    while (c.socket) {
        get_smtp_response(&s, res);
        if (res->replyCode >= 300) break;

        rumble_comm_printf(&s, "EHLO %s\r\n", me); // Try EHLO first
        get_smtp_response(&s, res);
        if (res->replyCode >= 300) {
            rumble_comm_printf(&s, "HELO %s\r\n", me); // Or...try HELO
            get_smtp_response(&s, res);
            if (res->replyCode >= 300) break;
        }

        if (rumble_has_dictionary_value(res->flags, "SIZE")) { // Do a MAIL FROM
            rumble_comm_printf(&s, "MAIL FROM: <%s=%s@%s> SIZE=%u\r\n", sender->tag, sender->user, sender->domain, fsize);
        } else {
            rumble_comm_printf(&s, "MAIL FROM: <%s=%s@%s>\r\n", sender->tag, sender->user, sender->domain);
        }

        get_smtp_response(&s, res);
        if (res->replyCode >= 300) break;

        // Do an RCPT TO
        rumble_comm_printf(&s, "RCPT TO: <%s@%s>\r\n", recipient->user, recipient->domain);
        get_smtp_response(&s, res);
        if (res->replyCode >= 300) break;

        // Do a DATA
        rumble_comm_printf(&s, "DATA\r\n", sender);
        get_smtp_response(&s, res);
        if (res->replyCode >= 400) break;
        while (!feof(fp)) {
            char buffer[2048];
            memset(buffer, 0, 2000);
            size_t chunk = fread(buffer, 1, 2000, fp);
            send(c.socket, buffer, chunk, 0);
            if (s._svc) ((rumbleService *) s._svc)->traffic.sent += chunk;
            else rumble_debug(master, "mailman", "..");
        }

        rumble_comm_send(&s, ".\r\n");
        get_smtp_response(&s, res);
        break;
    }

    fclose(fp);
    rumble_comm_printf(&s, "QUIT\r\n", sender);
    comm_addEntry(s._svc, c.brecv + c.bsent, 0);
    if (c.socket) close(c.socket);
    return (res);
}
