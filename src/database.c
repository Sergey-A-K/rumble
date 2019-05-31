#include "rumble.h"

#include "private.h"
#include "database.h"
#include <stdarg.h>


#define DB_LOG(x ...) rumble_debug(NULL, "db", x);


// Database constructors and wrappers
void rumble_database_load_sqlite(masterHandle *master, FILE *runlog) {
    (void)runlog;

    char          dbpath[1024];
    char        mailpath[1024];
    memset(dbpath,   0, 1024);
    memset(mailpath, 0, 1024);

    DB_LOG("Checking for thread-safe environment: %s", sqlite3_threadsafe() == 0 ? "No" : "Yes");

    const char * datafolder = rumble_config_str(master, "datafolder");
    const char * execpath = rumble_get_dictionary_value(master->_core.conf, "execpath");

    sprintf(dbpath, "%s/rumble.sqlite", datafolder);
    sprintf(mailpath, "%s/mail.sqlite", datafolder);

    FILE * ftmp = fopen(dbpath, "a+");
    if (ftmp) {
        fclose(ftmp);
    } else {
        sprintf(dbpath, "%s/%s/rumble.sqlite", execpath, datafolder);
        sprintf(mailpath, "%s/%s/mail.sqlite", execpath, datafolder);
    }

    DB_LOG("Loading database %s", dbpath);
    master->_core.db = radb_init_sqlite(dbpath); // Domains and accounts
    if (!master->_core.db) {
        DB_LOG("ERROR: Can't open database <%s>", dbpath);
        exit(EXIT_FAILURE);
    }

    DB_LOG("Loading letters %s", mailpath);
    master->_core.mail = radb_init_sqlite(mailpath); // Letters
    if (!master->_core.mail) {
        DB_LOG("ERROR: Can't open database <%s>", mailpath);
        exit(EXIT_FAILURE);
    }


    radb_run(master->_core.db,   "PRAGMA synchronous = 2");
    radb_run(master->_core.mail, "PRAGMA synchronous = 1");
    radb_run(master->_core.mail, "PRAGMA cache_size = 5000");

    // Check if the tables exists or not

    int rc = radb_run(master->_core.db, "PRAGMA table_info (accounts)");
    if (!rc) {
        DB_LOG("New installation, creating DB");
        rc = radb_run(master->_core.db,
                     "CREATE TABLE \"domains\" (\"id\" INTEGER PRIMARY KEY  AUTOINCREMENT  NOT NULL  UNIQUE , \"domain\" VARCHAR NOT NULL , \"storagepath\" VARCHAR, \"flags\" INTEGER NOT NULL  DEFAULT 0);");
        if (rc) DB_LOG("Couldn't create [domains] table in rumble DB!");
        rc = radb_run(master->_core.db,
                     "CREATE TABLE \"accounts\" (\"id\" INTEGER PRIMARY KEY  AUTOINCREMENT  NOT NULL  UNIQUE , \"domain\" VARCHAR NOT NULL , \"user\" VARCHAR, \"password\" CHAR(64), \"type\" CHAR(5) NOT NULL  DEFAULT mbox, \"arg\" VARCHAR);");
        if (rc) DB_LOG("Couldn't create [accounts] table in rumble DB!");
        rc = radb_run(master->_core.db,
                     "CREATE TABLE \"folders\" (\"uid\" INTEGER NOT NULL  DEFAULT 0, \"id\" INTEGER PRIMARY KEY  AUTOINCREMENT  NOT NULL  UNIQUE , \"name\" VARCHAR NOT NULL , \"subscribed\" BOOL NOT NULL  DEFAULT false);");
        if (rc) DB_LOG("Couldn't create [folders] table in rumble DB!");


    }

    rc = radb_run(master->_core.mail, "PRAGMA table_info (queue)");
    if (!rc) {
        DB_LOG("New installation, creating mail letters DB");
        rc = radb_run(master->_core.mail,
            "CREATE TABLE \"mbox\" (\"id\" INTEGER PRIMARY KEY  AUTOINCREMENT  NOT NULL  UNIQUE , \"uid\" INTEGER NOT NULL , \"fid\" VARCHAR NOT NULL , \"size\" INTEGER NOT NULL , \"delivered\" INTEGER DEFAULT (strftime('%s', 'now')), \"folder\" INTEGER NOT NULL DEFAULT 0, \"flags\" INTEGER NOT NULL DEFAULT 1 );");
        if (rc) DB_LOG("Couldn't create [mbox] table in mail letters DB!");
        rc = radb_run(master->_core.mail,
            "CREATE TABLE \"queue\" (\"id\" INTEGER PRIMARY KEY  NOT NULL ,\"time\" INTEGER NOT NULL  DEFAULT (STRFTIME('%s','now')) ,\"loops\" INTEGER NOT NULL  DEFAULT (0) ,\"fid\" VARCHAR NOT NULL ,\"sender\" VARCHAR NOT NULL ,\"recipient\" VARCHAR NOT NULL ,\"flags\" INTEGER NOT NULL  DEFAULT (0) );");
        if (rc) DB_LOG("Couldn't create [queue] table in mail letters DB!");
        rc = radb_run(master->_core.mail,
            "CREATE TABLE \"trash\" (\"id\" INTEGER PRIMARY KEY  NOT NULL ,\"fid\" VARCHAR NOT NULL);");
        if (rc) DB_LOG("Couldn't create [trash] table in mail letters DB!");
    }

//     // Check for the 'flags' column in the domain db
//     DB_LOG("Checking for 0.35+ db structure");
//     rc = 0;
//     radbResult * dbr;
//     radbObject * dbo = radb_prepare(master->_core.db, "PRAGMA table_info (domains)");
//     while ((dbr = radb_step(dbo))) {
//         if (!strcmp(dbr->column[1].data.string, "flags")) {
//             rc = 1;
//             break;
//         }
//     }
//
//     if (!rc) {
//         rumble_debug(NULL, "core", "db structure is deprecated, updating");
//         rc = radb_run(master->_core.db, "ALTER TABLE \"domains\" ADD COLUMN \"flags\" INTEGER NOT NULL  DEFAULT 0");
//     } else rumble_debug(NULL, "core", "db structure is up to date!");
//     radb_cleanup(dbo);

    DB_LOG("Database successfully initialized");

}


void rumble_database_load(masterHandle *master, FILE *runlog) {
    rumble_database_load_sqlite(master, runlog);
}

void rumble_free_account(rumble_mailbox *user) {
    if (!user) return;
    if (user->arg) free(user->arg);
    if (user->user) free(user->user);
    if (user->hash) free(user->hash);
    if (user->domain) {
        if (user->domain->name) free(user->domain->name);
        if (user->domain->path) free(user->domain->path);
        free(user->domain);
    }
    user->arg = 0;
    user->domain = 0;
    user->user = 0;
}

uint32_t rumble_account_exists(sessionHandle *session, const char *user, const char *domain) {
    (void)session;
    int rc = radb_run_inject(Master_Handle->_core.db,
        "SELECT user FROM accounts WHERE domain = %s AND %s GLOB user ORDER BY LENGTH(user) DESC LIMIT 1", domain, user);
    return (rc);
}


uint32_t rumble_account_exists_raw(const char *user, const char *domain) {
    int rc = radb_run_inject(Master_Handle->_core.db,
        "SELECT * FROM accounts WHERE domain = %s AND user = %s ORDER BY LENGTH(user) DESC", domain, user);
    return (rc);
}


rumble_mailbox *rumble_account_data(uint32_t uid, const char *user, const char *domain) {
    char stmt[256];
    memset(stmt, 0, 256);
    radbObject * dbo;
    if (uid) {
        sprintf(stmt, "SELECT id, domain, user, password, type, arg FROM accounts WHERE id = %u LIMIT 1", uid);
        dbo = radb_prepare(Master_Handle->_core.db, stmt);
    } else {
        if (!domain || !user) return (NULL);
        char * xusr = strclone(user);
        char * xdmn = strclone(domain);
        rumble_string_lower(xusr);
        rumble_string_lower(xdmn);
        dbo = radb_prepare(Master_Handle->_core.db,
            "SELECT id, domain, user, password, type, arg FROM accounts WHERE domain = %s AND %s GLOB user ORDER BY LENGTH(user) DESC LIMIT 1", xdmn, xusr);
        free(xusr);
        free(xdmn);
    }
    radbResult * dbr = radb_step(dbo);
    rumble_mailbox * acc = NULL;
    if (dbr) {
        acc = (rumble_mailbox*)malloc(sizeof(rumble_mailbox));
        if (!acc) merror();
        acc->uid =                       dbr->column[0].data.int32;   // Account UID
        acc->domain = rumble_domain_copy(dbr->column[1].data.string); // Account Domain struct
        acc->user =             strclone(dbr->column[2].data.string); // Account Username
        acc->hash =             strclone(dbr->column[3].data.string); // Password (hashed)
        char * tmp =            strclone(dbr->column[4].data.string); // Account type
        rumble_string_lower(tmp);

        DB_LOG("Mbox %s@%s is of type %s", acc->user, acc->domain->name, tmp);

        acc->type = RUMBLE_MTYPE_MBOX;
        if      (!strcmp(tmp, "alias")) acc->type = RUMBLE_MTYPE_ALIAS;
        else if (!strcmp(tmp, "mod"))   acc->type = RUMBLE_MTYPE_MOD;
        else if (!strcmp(tmp, "feed"))  acc->type = RUMBLE_MTYPE_FEED;
        else if (!strcmp(tmp, "relay")) acc->type = RUMBLE_MTYPE_FEED;
        free(tmp);
        acc->arg = strclone(dbr->column[5].data.string); // Account args
    }
    radb_cleanup(dbo);
    return (acc);
}


rumble_mailbox *rumble_account_data_auth(uint32_t uid, const char *user, const char *domain, const char *pass) {
    rumble_mailbox * acc = rumble_account_data(0, user, domain);
    if (acc) {
        char * hash = rumble_sha256((const char*)pass);
        if (!strcmp(hash, acc->hash)) {
            rumble_debug(NULL, "core", "Account %s successfully logged in.", user);
            free(hash);
            return (acc);
        }
        free(hash);
        rumble_free_account(acc);
        free(acc);
        acc = 0;
    }
    rumble_debug(NULL, "core", "Account %s failed to log in (wrong pass?).", user);
    return (acc);
}

// rumble_domain_exists: Checks if a domain exists in the database. Returns 1 if true, 0 if false. ;
// Check if domain exists as a local domain @param domain The domain to be checked. @return 1 if domain exists, 0
// otherwise.
uint32_t rumble_domain_exists(const char *domain) {
    uint32_t rc = 0;
    rumble_domain * dmn;
    d_iterator iter;
    char * dmncpy = strclone(domain);
    rumble_string_lower(dmncpy);
    rumble_rw_start_read(Master_Handle->domains.rrw);
    dforeach((rumble_domain *), dmn, Master_Handle->domains.list, iter) {
        if (!strcmp(dmn->name, dmncpy)) {
            rc = 1;
            break;
        }
    }
    free(dmncpy);
    rumble_rw_stop_read(Master_Handle->domains.rrw);
    return (rc);
}


// rumble_domain_copy: Returns a copy of the domain info
rumble_domain *rumble_domain_copy(const char *domain) {
    rumble_domain *dmn, *rc = 0;
    d_iterator      iter;
    char * dmncpy = strclone(domain);
    rumble_string_lower(dmncpy);
    rumble_rw_start_read(Master_Handle->domains.rrw);
    dforeach((rumble_domain *), dmn, Master_Handle->domains.list, iter) {
        if (!strcmp(dmn->name, dmncpy)) {
            rc = (rumble_domain *) malloc(sizeof(rumble_domain));
            if (!rc) merror();
            rc->name = (char *) calloc(1, strlen(dmn->name) + 1);
            rc->path = (char *) calloc(1, strlen(dmn->path) + 1);
            strcpy(rc->name, dmn->name);
            strcpy(rc->path, dmn->path);
            rc->flags = dmn->flags;
            rc->id = dmn->id;
            break;
        }
    }
    rumble_rw_stop_read(Master_Handle->domains.rrw);
    free(dmncpy);
    return (rc);
}




cvector *rumble_domains_list(void) {
    rumble_domain * dmn, * rc;
    d_iterator iter;
    cvector * cvec = cvector_init();
    rumble_rw_start_read(Master_Handle->domains.rrw);
    dforeach((rumble_domain *), dmn, Master_Handle->domains.list, iter) {
        rc = (rumble_domain *) malloc(sizeof(rumble_domain));
        if (!rc) merror();
        rc->id = 0;
        rc->name = (char*) calloc(1, strlen(dmn->name) + 1);
        rc->path = (char*) calloc(1, strlen(dmn->path) + 1);
        strcpy(rc->name, dmn->name);
        strcpy(rc->path, dmn->path);
        rc->id = dmn->id;
        rc->flags = dmn->flags;
        cvector_add(cvec, rc);
    }
    rumble_rw_stop_read(Master_Handle->domains.rrw);
    return (cvec);
}




cvector *rumble_database_accounts_list(const char *domain) {
    cvector * cvec = cvector_init();
    if (rumble_domain_exists(domain)) {
        radbObject * dbo = radb_prepare(Master_Handle->_core.db,
            "SELECT id, user, password, type, arg FROM accounts WHERE domain = %s", domain);
        rumble_mailbox * acc = NULL;
        radbResult * dbr;
        while ((dbr = radb_step(dbo))) {
            acc = (rumble_mailbox *) malloc(sizeof(rumble_mailbox));
            if (!acc) merror();
            acc->uid   =          dbr->column[0].data.int32;   // Account UID
            acc->user  = strclone(dbr->column[1].data.string); // Account Username
            acc->hash  = strclone(dbr->column[2].data.string); // Password (hashed)
            char * tmp = strclone(dbr->column[3].data.string); // Account type
            rumble_string_lower(tmp);
            acc->type = RUMBLE_MTYPE_MBOX;
            if      (!strcmp(tmp, "alias")) acc->type = RUMBLE_MTYPE_ALIAS;
            else if (!strcmp(tmp, "mod"))   acc->type = RUMBLE_MTYPE_MOD;
            else if (!strcmp(tmp, "feed"))  acc->type = RUMBLE_MTYPE_FEED;
            else if (!strcmp(tmp, "relay")) acc->type = RUMBLE_MTYPE_FEED;
            free(tmp);
            acc->arg = strclone(dbr->column[4].data.string); // Account args
            acc->domain = 0;
            cvector_add(cvec, acc);
        }
        radb_cleanup(dbo);
    }
    return (cvec);
}



void rumble_database_accounts_free(cvector *accounts) {
    c_iterator      citer;
    rumble_mailbox  *acc;
    cforeach((rumble_mailbox *), acc, accounts, citer) {
        if (acc->hash) free(acc->hash);
        if (acc->user) free(acc->user);
        if (acc->arg)  free(acc->arg);
        free(acc);
    }
    cvector_destroy(accounts);
}




void rumble_domain_free(rumble_domain *domain) {
    if (!domain) return;
    if (domain->name) free(domain->name);
    if (domain->path) free(domain->path);
    free(domain);
}



// Internal database functions (not for use by modules) ;
// rumble_database_update_domains: Updates the list of domains from the db
void rumble_database_update_domains(void) {
    rumble_domain   *domain;
    d_iterator      iter;

    rumble_rw_start_write(Master_Handle->domains.rrw); // lock
    // Clean up the old list
    dforeach((rumble_domain *), domain, Master_Handle->domains.list, iter) rumble_domain_free(domain);
    dvector_flush(Master_Handle->domains.list);
    radbObject *dbo = radb_prepare(Master_Handle->_core.db, "SELECT id, domain, storagepath, flags FROM domains WHERE 1");
    radbResult * dbr;
    while ((dbr = radb_step(dbo))) {
        domain = (rumble_domain *) malloc(sizeof(rumble_domain));
        if (!domain) merror();
        domain->id =            dbr->column[0].data.int32;   // Domain ID
        domain->flags =         dbr->column[3].data.int32;   // Domain flags
        domain->name = strclone(dbr->column[1].data.string); // Domain name
        domain->path = strclone(dbr->column[2].data.string); // Optional domain specific storage path
        dvector_add(Master_Handle->domains.list, domain);
        DB_LOG("Found domain: %s (%d)", domain->name, domain->id);
    }
    rumble_rw_stop_write(Master_Handle->domains.rrw); // unlock
    radb_cleanup(dbo);
}
