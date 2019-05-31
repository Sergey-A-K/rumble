#include "rumble.h"
#include "private.h"
#include "database.h"
#include <stdarg.h>
#include <fcntl.h>
#include "mailman.h"
#include "comm.h"
#include "servers.h"
#include <sys/stat.h>

#define MM_LOG(x ...) rumble_debug(NULL, "mailman", x);
#define MM_TRA(x ...) rumble_debug(NULL, "mailman", x);

void rumble_master_init_mailman(masterHandle *master) {
    (void) master;
    MM_LOG("Launching mailman service");
    rumbleService * svc = comm_registerService(master, "mailman", rumble_worker_init, 0, 1);
    svc->settings.stackSize = 128 * 1024; // Set stack size for service to 128kb (should be enough)
    int rc = comm_startService(svc);
    if (!rc) {
        MM_LOG("ABORT: Couldn't launching mailman service!");
        exit(EXIT_SUCCESS);
    } else {
            svc->cue_hooks  = cvector_init();
            svc->init_hooks = cvector_init();
            svc->exit_hooks = cvector_init();
    }
}




mailman_bag *mailman_new_bag(uint32_t uid, const char *path) {
    mailman_bag *bag = (mailman_bag *) malloc(sizeof(mailman_bag));
    if (!bag) merror();
    bag->uid = uid;
    bag->lock = rumble_rw_init();
    bag->sessions = 1;
    bag->closed = 0;
    bag->size = 32;
    bag->firstFree = 0;
    bag->folders = (mailman_folder *) calloc(33, sizeof(mailman_folder));
    mailman_folder * inbox = mailman_new_folder(bag);
    inbox->fid = 0;
    strcpy(inbox->name, "INBOX");
    memset(bag->path, 0, 256);
    strncpy(bag->path, path, 256);
    mailman_update_folders(bag);
    return (bag);
}


mailman_folder *mailman_new_folder(mailman_bag *bag) {
    if (!bag) return (NULL);
    int f = 0, x = 0;
    for (int i = bag->firstFree; i < bag->size; i++) {
        if (bag->folders[i].inuse == 0) { // Look for an empty slot to add the folder
            f = i;
            x++;
            break;
        }
    }
    if (!x) {
        bag->folders = (mailman_folder*) realloc((void *) bag->folders, (bag->size + 8) * sizeof(mailman_folder));
        if (!bag->folders) MM_LOG("WTF?!");
        for (int i = bag->size - 1; i < (bag->size + 8); i++) {
            bag->folders[i].inuse = 0;
        }
        f = bag->size;
        bag->size += 8;
    }
    bag->firstFree = f + 1;
    bag->folders[f].letters = (mailman_letter *) calloc(257, sizeof(mailman_letter));
    bag->folders[f].firstFree = 0;
    bag->folders[f].size = 256;
    bag->folders[f].lock = bag->lock;
    bag->folders[f].subscribed = 0;
    bag->folders[f].inuse = 1;
    return (&bag->folders[f]);
}

mailman_letter *mailman_new_letter(mailman_folder *folder) {
    if (!folder) return (NULL);
    int f = 0, x = 0;
    for (int i = folder->firstFree; i < folder->size; i++) {
        if (folder->letters[i].inuse == 0) { // Look for an empty spot first
            f = i;
            x++;
            folder->letters[i].inuse = 1;
            break;
        }
    }

    if (!x) {
        folder->letters = (mailman_letter *) realloc(folder->letters,
            (sizeof(mailman_letter)) * (folder->size + 33));
        for (int i = folder->size - 1; i < folder->size + 32; i++)
            folder->letters[i].inuse = 0;
        f = folder->size;
        folder->firstFree = f + 1;
        folder->size += 32;
    }
    return (&folder->letters[f]);
}


void mailman_free_folder(mailman_folder *folder) {
    if (!folder || !folder->inuse) return;
    if (!folder) return;
    if (folder->letters) free(folder->letters);
    folder->size = 0;
    folder->letters = 0;
    folder->inuse = 0;
    folder->fid = 0;
    folder->firstFree = 0;
}


void mailman_free_bag(mailman_bag *bag) {
    if (!bag) return;
    mailman_bag *rbag = 0;
    c_iterator  iter;
    for (int i = 0; i < bag->size; i++) mailman_free_folder(&bag->folders[i]);
    free(bag->folders);
    rumble_rw_destroy(bag->lock);
    cforeach((mailman_bag *), rbag, Master_Handle->mailboxes.bags, iter) {
        if (rbag == bag) {
            cvector_delete(&iter);
            break;
        }
    }
    free(bag);
}

void mailman_close_bag(mailman_bag *bag) {
    if (!bag) return;
    rumble_rw_start_write(bag->lock);
    bag->sessions--;
    if (bag->sessions == 0) bag->closed = 1;
    rumble_rw_stop_write(bag->lock);
    if (bag->sessions == 0) mailman_free_bag(bag);
}


void mailman_add_flags(mailman_folder *folder, uint32_t flags, uint32_t UID, uint64_t start, uint64_t stop) {
    if (!folder) return;
    if (stop == 0) stop = start;
    rumble_rw_start_write(folder->lock);
    for (int i = 0; i < folder->size; i++) {
        mailman_letter * letter = &folder->letters[i];
        if (letter->inuse) {
            if (UID) {
                if (letter->id >= start && letter->id <= stop) {
                    letter->flags |= flags;
                    letter->updated = 1;
                    MM_LOG("Updated flags for msg %lu: %08X\n", letter->id, letter->flags);
                }
            } else {
                if (i + 1 >= start && i < stop) {
                    letter->flags |= flags;
                    letter->updated = 1;
                }
            }
        }
    }
    rumble_rw_stop_write(folder->lock);
}

void mailman_remove_flags(mailman_folder *folder, uint32_t flags, uint32_t UID, uint64_t start, uint64_t stop) {
    if (!folder) return;
    if (stop == 0) stop = start;
    rumble_rw_start_write(folder->lock);
    for (int i = 0; i < folder->size; i++) {
        mailman_letter * letter = &folder->letters[i];
        if (letter->inuse) {
            if (UID) {
                if (letter->id >= start && letter->id <= stop) {
                    letter->flags -= (letter->flags & flags);
                    letter->updated = 1;
                    MM_LOG("Set flags for %lu to %08X\n", letter->id, letter->flags);
                }
            } else {
                if (i + 1 >= start && i < stop) {
                    letter->flags -= (letter->flags & flags);
                    letter->updated = 1;
                }
            }
        }
    }
    rumble_rw_stop_write(folder->lock);
}


void mailman_set_flags(mailman_folder *folder, uint32_t flags, uint32_t UID, uint64_t start, uint64_t stop) {
    if (!folder) return;
    if (stop == 0) stop = start;
    rumble_rw_start_write(folder->lock);
    for (int i = 0; i < folder->size; i++) {
        mailman_letter * letter = &folder->letters[i];
        if (letter->inuse) {
            if (UID) {
                if (letter->id >= start && letter->id <= stop) {
                    letter->flags = flags;
                    letter->updated = 1;
                    MM_LOG("Set flags for %lu to %08X\n", letter->id, letter->flags);
                }
            } else {
                if (i + 1 >= start && i < stop) {
                    letter->flags = flags;
                    letter->updated = 1;
                }
            }
        }
    }
    rumble_rw_stop_write(folder->lock);
}


void mailman_update_folders(mailman_bag *bag) {
    radbObject *dbo = radb_prepare(Master_Handle->_core.db, "SELECT id, name, subscribed FROM folders WHERE uid = %u", bag->uid);
    if (dbo) {
        radbResult *dbr;
        while ((dbr = radb_step(dbo))) {
            mailman_folder * folder = 0;
            for (int i = 0; i < bag->size; i++) {
                if (bag->folders[i].inuse && bag->folders[i].fid == dbr->column[0].data.uint64) {
                    folder = &bag->folders[i];
                    break;
                }
            }
            if (!folder) {
                folder = mailman_new_folder(bag);
                folder->fid = dbr->column[0].data.uint64;
                folder->subscribed = dbr->column[2].data.int32;
                memset(folder->name, 0, 64);
                strncpy(folder->name, dbr->column[1].data.string, 64);
            }
        }
        radb_cleanup(dbo);
    } else MM_LOG("!update_folders, dbo == NULL!")
}

void mailman_update_folder(mailman_folder *folder, uint32_t uid, uint64_t lastID) {
    int f = 0;
    radbObject *dbo = radb_prepare(Master_Handle->_core.mail,
        "SELECT id, fid, size, delivered, flags, folder FROM mbox WHERE uid = %u AND folder = %l",
        uid, folder->fid);
    if (dbo) {
        radbResult *dbr;
        while ((dbr = radb_step(dbo))) {
            f = 0;
            int lid = dbr->column[0].data.int64;
            for (unsigned i = 0; i < folder->size; i++) {
                if (folder->letters[i].inuse) {
                    if (lid == folder->letters[i].id) {
                        f++;
                        break;
                    }
                }
            }

            if (!f) {
                mailman_letter *letter = mailman_new_letter(folder);
                letter->flags = dbr->column[4].data.uint32;
                letter->id = dbr->column[0].data.uint64;
                letter->size = dbr->column[2].data.int32;
                letter->delivered = dbr->column[3].data.int32;
                letter->updated = 0;
                letter->inuse = 1;
                memset(letter->filename, 0, 32);
                strcpy(letter->filename, dbr->column[1].data.string);
                f = 0;
            }
        }
        radb_cleanup(dbo);
    } else MM_LOG("!update_folder, dbo == NULL!")
}


mailman_folder *mailman_get_folder(mailman_bag *bag, const char *name) {
    if (!bag || !name) {
        MM_TRA("mailman_get_folder: !bag || !name");
        return (NULL);
    }
    mailman_folder *folder = NULL;
    rumble_rw_start_read(bag->lock);
    for (unsigned i = 0; i < bag->size; i++) {
        if (bag->folders[i].inuse && !strcmp(bag->folders[i].name, name)) {
            folder = &bag->folders[i];
            break;
        }
    }
    rumble_rw_stop_read(bag->lock);
    return (folder);
}

void mailman_rename_folder(mailman_folder *folder, const char *name) {
    if (!folder || !name) return;
    memset( folder->name, 0, 64);
    strncpy(folder->name, name, 64);
}


void mailman_delete_folder(mailman_bag *bag, mailman_folder *folder) {
    if (!bag || !folder) return;
    MM_LOG("Deleting account #%u's folder <%s>", bag->uid, folder->name);
    rumble_rw_start_write(folder->lock); // lock
    radb_run_inject(Master_Handle->_core.db,   "DELETE FROM folders WHERE id = %l", folder->fid);
    radb_run_inject(Master_Handle->_core.mail, "DELETE FROM mbox WHERE uid = %u AND folder = %l", bag->uid, folder->fid);
    unsigned int f = 0;
    for (unsigned int i = 0; i < folder->size; i++) {
        mailman_letter *letter = &folder->letters[i];
        if (letter->inuse) {
            f++;
            char *filename = (char*)calloc(1, strlen(bag->path) + strlen(letter->filename) + 6);
            sprintf(filename, "%s/%s.msg", bag->path, letter->filename);
            MM_LOG("unlink %s", filename);
            unlink(filename);
            free(filename);
            letter->inuse = 0;
        }
    }
    mailman_free_folder(folder);
    rumble_rw_stop_write(bag->lock); // unlock
    MM_LOG("Deleted %u letters.", f);
}


void mailman_commit(mailman_bag *bag, mailman_folder *folder, char expungeOnly) {
    if (!bag || !folder) {
        MM_TRA("mailman_commit with !bag || !folder");
        return;
    }
    MM_LOG("mailman_commit() Updating #%u's folder <%s>", bag->uid, folder->name);
    rumble_rw_start_write(folder->lock); // lock
    unsigned int f = 0;
    for (unsigned int i = 0; i < folder->size; i++) {
        mailman_letter *letter = &folder->letters[i];
        if (letter->inuse) {
            MM_LOG("Letter %lu has flags <%08X>, looking for <%08X>\n", letter->id, letter->flags, RUMBLE_LETTER_DELETED);
            if ((expungeOnly && (letter->flags & RUMBLE_LETTER_EXPUNGE)) || (!expungeOnly && (letter->flags & RUMBLE_LETTER_DELETED))) {
                MM_LOG("Deleting letter no. %lu\n", letter->id);
                radb_run_inject(Master_Handle->_core.mail, "DELETE FROM mbox WHERE id = %l", letter->id);
                char *filename = (char*)calloc(1, strlen(bag->path) + strlen(letter->filename) + 6);
                sprintf(filename, "%s/%s.msg", bag->path, letter->filename);
                MM_LOG("unlink %s", filename);
                unlink(filename);
                free(filename);
                folder->letters[i].inuse = 0;
                if (i < folder->firstFree) folder->firstFree = i;
                f++;
            } else if (letter->updated) {
                radb_run_inject(Master_Handle->_core.mail, "UPDATE mbox SET flags = %u WHERE uid = %u AND id = %l",
                    letter->flags, bag->uid, letter->id);
                letter->updated = 0;
            }
        }
    }
    rumble_rw_stop_write(folder->lock);  // unlock
    MM_LOG("Deleted %u letters.", f);
}



FILE *mailman_open_letter(mailman_bag *bag, mailman_folder *folder, uint64_t id) {
    mailman_letter  *letter = NULL;
    for (unsigned int i = 0; i < folder->size; i++) {
        if (folder->letters[i].inuse && folder->letters[i].id == id) {
            letter = &folder->letters[i];
            break;
        }
    }
    if (!letter) {
        MM_LOG("letters id=%d not found", id)
        return (NULL);
    }

    char *filename = (char*)calloc(1, strlen(bag->path) + strlen(letter->filename) + 6);
    sprintf(filename, "%s/%s.msg", bag->path, letter->filename);
    if (chdir(bag->path) == -1) {
        MM_LOG("Couldn't chdir to: %s", bag->path);
        int bad = mkdir(bag->path, S_IRWXU | S_IRGRP | S_IWGRP);
        if (bad) { MM_LOG("Couldn't mkdir: %s, code: %d", bag->path, bad); }
        else     { MM_LOG("Created new domain path: %s", bag->path); }
    }
    MM_LOG("Opening: %s", filename);
    FILE * fp = fopen(filename, "r");
    free(filename);
    if (!fp) MM_LOG("Couldn't open file :(");
    return (fp);
}

void mailman_copy_letter( mailman_bag *bag,
                          mailman_folder *sourceFolder,
                          mailman_folder *destFolder,
                          uint64_t start,
                          uint64_t stop,
                          uint32_t UID) {
    MM_LOG("mailman_copy_letter()");
    if (!bag || !sourceFolder || !destFolder) {
        MM_LOG("mailman_copy_letter: !bag || !sourceFolder || !destFolder");
        return;
    }
    if (stop == 0) stop = start;
    rumble_rw_start_write(bag->lock); // lock
    for (unsigned int i = 0; i < sourceFolder->size; i++) {
        mailman_letter *letter = &sourceFolder->letters[i];
        if (letter->inuse) {
            // TODO potential bugs
            if ((UID && (letter->id >= start && letter->id <= stop)) || (!UID && (i + 1 >= start && 1 < i))) {
                MM_LOG("Copying letter %lu to folder %lu", letter->id, destFolder->fid);
                char *fid = rumble_create_filename();
                char *filename = (char*)calloc(1, strlen(bag->path) + strlen(fid) + 6);
                sprintf(filename, "%s/%s.msg", bag->path, fid);
                FILE *in, *out;
                in = mailman_open_letter(bag, sourceFolder, letter->id);
                if (in) {
                    out = fopen(filename, "wb");
                    if (!out) fclose(in);
                    else {
                        char * buffer = (char*)calloc(1, 2048);
                        while (!feof(in)) {
                            size_t len = fread(buffer, 1, 2048, in);
                            fwrite(buffer, 1, len, out);
                        }
                        free(buffer);
                        fclose(out);
                        radb_run_inject(Master_Handle->_core.mail,
                            "INSERT INTO mbox (id, uid, fid, folder, size, flags) VALUES (NULL, %u, %s, %l, %u, %u)",
                            bag->uid, fid, destFolder->fid, letter->size, letter->flags | RUMBLE_LETTER_RECENT);
                    }
                } else {
                    MM_LOG("Couldn't create copy of letter at %s, aborting.", filename);
                }
                free(fid);
                free(filename);
            } else MM_LOG("potential bugs???");
        }
    }
    rumble_rw_stop_write(bag->lock); // unlock
}


mailman_bag *mailman_get_bag(uint32_t uid, const char *path) {
    mailman_bag *bag = NULL;
    mailman_bag *rbag = NULL;
    c_iterator  iter;
    cforeach((mailman_bag *), bag, Master_Handle->mailboxes.bags, iter) {
        if (bag->uid == uid) {
            rumble_rw_start_write(bag->lock);
            if (bag->closed == 0) rbag = bag;
            bag->sessions++;
            rumble_rw_stop_write(bag->lock);
            break;
        }
    }
    if (rbag) MM_LOG("Using already opened bag")
    else {
        MM_LOG("Making new bag struct with %s as path", path);
        rbag = mailman_new_bag(uid, path);
        cvector_add(Master_Handle->mailboxes.bags, rbag);
    }
    return (rbag);
}

void rumble_mailman_free_parsed_letter(rumble_parsed_letter *letter) {
    c_iterator iter;
    rumbleKeyValuePair *pair;
    if (letter->body) free(letter->body);
    if (letter->headers) {
        cforeach((rumbleKeyValuePair *), pair, letter->headers, iter) {
            free((char*)pair->key);
            free((char*)pair->value);
        }
        cvector_destroy(letter->headers);
    }
    rumble_parsed_letter *chunk;
    if (letter->multipart_chunks) {
        cforeach((rumble_parsed_letter *), chunk, letter->multipart_chunks, iter) {
            rumble_mailman_free_parsed_letter(chunk);
        }
        cvector_destroy(letter->multipart_chunks);
    }
    free(letter);
}


rumble_parsed_letter *rumble_mailman_readmail(const char *filename) {
    rumble_parsed_letter    *letter = 0;
    MM_LOG("Mailman.readMail: Opening <%s>", filename);
    FILE * fp = fopen(filename, "rb");
    if (fp) {
        letter = rumble_mailman_readmail_private(fp, 0);
        fclose(fp);
    }
    MM_LOG("Closing <%s>", filename);
    return (letter);
}



rumble_parsed_letter *rumble_mailman_readmail_private(FILE *fp, const char *boundary) {
    if (!fp) return (0);
    int headers = 1;
    size_t blen = 0, pos = 0, llen = 0;
    unsigned long previous = 0;

    MM_LOG("Parsing file pointer with boundary set to <%s>", boundary ? boundary : "(null)");
    rumble_parsed_letter * letter = (rumble_parsed_letter *) malloc(sizeof(rumble_parsed_letter));
    if (!letter) merror();
    letter->body = 0;
    letter->is_multipart = 0;
    letter->is_last_part = 0;
    letter->headers = cvector_init();
    letter->multipart_chunks = cvector_init();
    char starting_boundary[128], finishing_boundary[128], child_boundary[128], line[1024];
    memset(starting_boundary, 0, 128);
    memset(finishing_boundary, 0, 128);
    memset(child_boundary, 0, 128);
    memset(line, 0, 1024);
    if (boundary) {
        sprintf(starting_boundary, "--%s", boundary);
        sprintf(finishing_boundary, "--%s--", boundary);
        blen = strlen(starting_boundary);
    }
    rumbleKeyValuePair      *header = 0;
    while (!feof(fp)) {
        if (fgets(line, 1024, fp)) {

            llen = strlen(line);

            // Check if we hit a boundary line
            if (boundary && !strncmp(line, starting_boundary, blen)) {
                if (!strncmp(line, finishing_boundary, blen + 2)) letter->is_last_part = 1; // Did we hit the last boundary?
                break; // Finish up and return.
            }

            if (headers == 1) {
                if (!llen || line[0] == '\r' || line[0] == '\n') {
                    headers = 0;
                    // pdepth(depth, "</headers>");
                    continue;
                } // End of headers

                char key[256], value[1024];
                memset(key, 0, 256);
                memset(value, 0, 1024);

                // Are we continuing the previous header line?
                if (header && (line[0] == ' ' || line[0] == '\t')) {
                    if (sscanf(line, "%1024[^\r\n]", value) == 1) {
                        size_t  old_len = strlen(header->value), new_len = strlen(value);
                        value[new_len] = 0;
                        MM_LOG("Reallocating value to hold %lu bytes", old_len+new_len+1);
                        header->value = realloc((char *) header->value, old_len + new_len + 1);
                        strncpy((char *) header->value + old_len, line, new_len + 1);
                        MM_LOG("+%s: %s", header->key, line);

                    }
                }

                // Or did we start on a new header pair?
                if (sscanf(line, "%256[^:]: %1024[^\r\n]", key, value) == 2) {
                    size_t klen = strlen(key);
                    size_t vlen = strlen(value);
                    header = (rumbleKeyValuePair *) malloc(sizeof(rumbleKeyValuePair));
                    header->key = calloc(1, klen + 1);
                    rumble_string_lower(key);
                    strncpy((char *) header->key, key, klen);
                    header->value = calloc(1, vlen + 1);
                    strncpy((char *) header->value, value, vlen);
                    cvector_add(letter->headers, header);
                    MM_LOG("%s: %s\n", key, value);
                    // pdepth(depth+1, "<header>");
                    // pdepth(depth+1, line);

                }
            // Done with headers, browse through them and look for a boundary if any
            } else if (headers == 0) {
                // pdepth(depth, "<header check>");
                c_iterator iter;
                cforeach((rumbleKeyValuePair *), header, letter->headers, iter) {
                    if (!strcmp(header->key, "content-type")) {
                        MM_LOG("Found a content-type: %s", header->value);
                        const char  *at = strstr(header->value, "boundary=");
                        if (at && sscanf(at, "boundary=\"%255[^\"]", child_boundary)) {
                            // MM_LOG("This message has boundary issues! ;D (%s)",child_boundary);
                            letter->is_multipart = 1;
                        }
                    }
                }
                headers = -1;
                // if (!letter->is_multipart) MM_LOG("Mail is single-part\n");
                // pdepth(depth, "</header check>");
                // pdepth(depth, "<body>");
            // Read body of message
            } else if (headers == -1) {
                // No multipart, just add the body
                if (!letter->is_multipart) {
                    // MM_LOG(".");
                    // New body, malloc
                    if (!letter->body) {
                        letter->body = (char *) calloc(1, llen + 1);
                        strncpy(letter->body, line, llen);
                        pos = llen;
                    } else { // Old body, append to it.
                        letter->body = (char *) realloc((char *) letter->body, pos + llen + 1);
                        strncpy((char *) letter->body + pos, line, llen);
                        pos += llen;
                        letter->body[pos] = 0;
                    }
                } else {
                    rumble_parsed_letter * child = 0;
                    fseek(fp, previous, SEEK_SET);
                    // MM_LOG("This line was: %s\n", line);
                    while (1) {
                        child = rumble_mailman_readmail_private(fp, child_boundary);
                        if (!child) break;
                        cvector_add(letter->multipart_chunks, child);
                        if (child->is_last_part) break;
                    }
                    if (child && child->is_last_part) break;
                }
            }
            previous = ftell(fp);
        }
    }
    fclose(fp);
    // MM_LOG("\n");
    // if (letter->is_last_part) pdepth(--depth, "<last chunk>");
    if (letter->body || letter->is_multipart) {
        return (letter);
    } else {
        rumble_mailman_free_parsed_letter(letter);
        return (NULL);
    }
}
