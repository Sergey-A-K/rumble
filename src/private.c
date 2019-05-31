#include "rumble.h"
#include "private.h"

#define LOG(x ...) rumble_debug(NULL, "mailman", x);

// THREADS TRACE
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_THREADS)
#define RRW(x ...) rumble_debug(NULL, "rrw", x);
#else
#define RRW(x ...)
#endif


size_t rumble_copy_mail(masterHandle *m, const char *fid, const char *usr, const char *dmn, char **pfid) {
    size_t fsize = 0;
    const char *storagefolder = rumble_config_str(m, "storagefolder");
    const char *servername    = rumble_config_str(m, "servername");
    char * nfid = rumble_create_filename();
    char * filename  = (char*)calloc(1, strlen(storagefolder) + strlen(nfid) + 2);
    char * ofilename = (char*)calloc(1, strlen(storagefolder) + strlen(nfid) + 2);
    if (!filename || !ofilename) merror();
    sprintf(filename,  "%s/%s", storagefolder, nfid);
    sprintf(ofilename, "%s/%s", storagefolder, fid);
    FILE * ofp = fopen(ofilename, "r");
    FILE * fp  = fopen(filename, "wb");
    LOG("Copying %s to file %s...", ofilename, filename);
    free(filename);
    free(ofilename);
    if (!ofp) {
        LOG("Couldn't open file <%s>", ofilename);
        if (fp) fclose(fp);
        free(nfid);
        *pfid = 0;
        return (0);
    }
    if (!fp) {
        LOG("Couldn't write file <%s>", filename);
        if (ofp) fclose(ofp);
        free(nfid);
        *pfid = 0;
        return (0);
    }
    char * now = rumble_mtime();
    char * buffer = (char*)calloc(1, 2048);
    if (!now || !buffer) merror();
    // fprintf(fp, "Received: from localhost by %s (rumble) for %s@%s with ESMTPA id <%s>; %s\r\n",
    fprintf(fp, "Received: from localhost by %s for <%s@%s> with ESMTPA id <%s>; %s\r\n",
        servername,     usr,dmn,    nfid, now);
    free(now);

    while (!feof(ofp)) {
        size_t  rc = fread(buffer, 1, 2048, ofp);
        if (rc < 0) break;
        if (!fwrite(buffer, rc, 1, fp)) break;
        fsize += rc;
    }
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    rewind(fp);
    fclose(fp);
    fclose(ofp);
    free(buffer);
    *pfid = nfid;
    return (fsize);
}



size_t rumble_mail_from_file(masterHandle *master, const char *oldfile, char **fid) {
    size_t length = 0;
    *fid = rumble_create_filename();
    const char  * storagefolder = rumble_config_str(master, "storagefolder");
    char *newfile = calloc(1, strlen(storagefolder) + strlen(*fid) + 2);
    sprintf(newfile, "%s/%s", storagefolder, *fid);
    FILE * in  = fopen(oldfile, "r");
    FILE * out = fopen(newfile, "wb");
    LOG("Copying %s to file %s...", oldfile, newfile);
    free(newfile);
    if (!in) {
        LOG("Couldn't open file <%s>", oldfile);
        if (out) fclose(out);
        *fid = 0;
        return (0);
    }
    if (!out) {
        LOG("Couldn't write file <%s>", newfile);
        if (in) fclose(in);
        *fid = 0;
        return (0);
    }
    char * buffer = (char*)calloc(1, 2048);
    if (!buffer) merror();
    while (!feof(in)) {
        size_t  rc = fread(buffer, 1, 2048, in);
        if (rc < 0) break;
        if (!fwrite(buffer, rc, 1, out)) break;
    }
    fseek(out, 0, SEEK_END);
    length = ftell(out);
    rewind(out);
    fclose(out);
    fclose(in);
    free(buffer);
    return (length);
}






// rumble_readerwriter: A simple reader/writer mechanism that allows multiple readers to access the same memory, but
// grants exclusive access whenever a writer requests write access.
rumble_readerwriter *rumble_rw_init(void) {
    rumble_readerwriter *rrw = (rumble_readerwriter *) malloc(sizeof(rumble_readerwriter));
    if (!rrw) merror();
    rrw->readers = 0;
    rrw->writers = 0;
    pthread_mutex_init(&rrw->mutex, 0);
    pthread_cond_init(&rrw->reading, 0);
    pthread_cond_init(&rrw->writing, 0);
    RRW("rw_init [ok]");
    return (rrw);
}

void rumble_rw_destroy(rumble_readerwriter *rrw) {
    pthread_mutex_destroy(&rrw->mutex);
    pthread_cond_destroy(&rrw->reading);
    pthread_cond_destroy(&rrw->writing);
    free(rrw);
}

void rumble_rw_start_read(rumble_readerwriter *rrw) {
    RRW("rw_start_read...");
    pthread_mutex_lock(&rrw->mutex);
    // Wait for any writers working (or queued for work) to do their stuff.
    while (rrw->writers) pthread_cond_wait(&rrw->writing, &rrw->mutex);
    // Announce that we're reading now.
    RRW("++ Add read hook");
    rrw->readers++;
    pthread_mutex_unlock(&rrw->mutex);
    RRW("...rw_start_read end");
}


void rumble_rw_stop_read(rumble_readerwriter *rrw) {
    RRW("rw_stop_read...");
    pthread_mutex_lock(&rrw->mutex);
    rrw->readers--;
    // If a writer is waiting;
    // Signal that we've stopped reading
    if (rrw->writers) pthread_cond_broadcast(&rrw->reading);
    pthread_mutex_unlock(&rrw->mutex);
    RRW("...rw_stop_read end");
}

void rumble_rw_start_write(rumble_readerwriter *rrw) {
    RRW("rw_start_write...");
    pthread_mutex_lock(&rrw->mutex);
    RRW("Wait for any previous writer to finish");
    while (rrw->writers) {
        RRW("waiting for writer to finish...");
        pthread_cond_wait(&rrw->writing, &rrw->mutex);
    }
    // Let readers know that we want to write ;
    RRW("++ Add write hook");
    rrw->writers++;
    // Wait for all readers to quit
    while (rrw->readers) {
        RRW("waiting for reader to finish...");
        pthread_cond_wait(&rrw->reading, &rrw->mutex);
    }
    pthread_mutex_unlock(&rrw->mutex);
    RRW("...rw_start_write end");
}


void rumble_rw_stop_write(rumble_readerwriter *rrw)
{
    RRW("rw_stop_write...");
    pthread_mutex_lock(&rrw->mutex);
    if (rrw->writers) rrw->writers--;
    RRW("Remove write hook");
    pthread_cond_broadcast(&rrw->writing);
    pthread_mutex_unlock(&rrw->mutex);
    RRW("...rw_stop_write end");
}



void rumble_clean_session(sessionHandle *session) {
    if (!session) return;
    if (session->sender) {
        rumble_free_address(session->sender);
        session->sender = 0;
    }
    address *el;
    d_iterator iter;
    dforeach((address *), el, session->recipients, iter) if (el) rumble_free_address(el);
    dvector_flush(session->recipients);
}
