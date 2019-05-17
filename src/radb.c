// #define RADB_DEBUG 1

#include "radb.h"


radbObject *radb_init_object(radbMaster *dbm) {
    radbObject  *dbo;
    if (!dbm) { printf("radb_init_object: Received a null-pointer as radbm!\n"); return (0); }
    dbo = (radbObject *) calloc(1, sizeof(radbObject));
    dbo->master = dbm;
    dbo->result = 0;
    dbo->inputBindings = 0;
    dbo->lastError = 0;
    memset(dbo->inputs, 0, 64);
    dbo->status = RADB_EMPTY;
    dbo->db = dbm->handle;
    return (dbo);
}


void radb_cleanup(radbObject *dbo) {
#ifdef RADB_DEBUG
    if (!dbo) { printf("radb_cleanup: Received a null-pointer as radbo!\n"); return; }
    printf("Cleaning up\n");
#endif
    if (!dbo) return;
    if (dbo->state) sqlite3_finalize((sqlite3_stmt *) dbo->state);
#ifdef RADB_DEBUG
    printf("Calling radb_free_result\n");
#endif
    if (dbo->result) radb_free_result(dbo->result);
    if (dbo->inputBindings) free(dbo->inputBindings);
    free(dbo);
}


void radb_close(radbMaster *dbm) {
    if (!dbm) return;
    sqlite3_close((sqlite3 *) dbm->handle);
    free(dbm);
    return;
}


const char *radb_last_error(radbObject *dbo) {
    if (!dbo) return ("(null)");
    return (dbo->lastError ? dbo->lastError : "No error");
}

// TODO - Kill this
radbObject *radb_prepare_vl(radbMaster *dbm, const char *statement, va_list vl) {
    char        *sql, b;
    const char  *p, *op;
    size_t      len = 0, strl = 0;
    int         at = 0,  rc = 0;
    radbObject  *dbo;

    dbo = radb_init_object(dbm);
    if (!dbo) return (0);
    dbo->status = 0;
    sql = (char *) calloc(1, 2048);
    op = statement;
    for (p = strchr(statement, '%'); p != NULL; p = strchr(op, '%')) {
        strl = strlen(op) - strlen(p);
        strncpy((char *) (sql + len), op, strl);
        len += strl;
        if (sscanf((const char *) p, "%%%c", &b)) {
            if (b == '%') {
                strncpy((char *) (sql + len), "%", 1);
                len += 1;
            } else {
                strncpy((char *) (sql + len), "?", 1);
                len += 1;
                dbo->inputs[at++] = b;
            }

            op = (char *) p + 2;
        }
    }

    //strl = strlen(op);
    strncpy((char *) (sql + len), op, strlen(op));
    strl = strlen(sql);
    if (sql[strl - 1] != ';') sql[strl++] = ';';
    dbo->status = RADB_PARSED;
    rc = sqlite3_prepare_v2((sqlite3 *) dbo->db, sql, -1, (sqlite3_stmt **) &dbo->state, NULL);
    // printf("Prepared: %s\n", sql);
    free(sql);
    if (rc) {
        radb_cleanup(dbo);
        return (0);
    }

    radb_inject_vl(dbo, vl);
    return (dbo);
}



/////////////////////////////////////////////////////////////////////////////////////////

radbObject *radb_prepare(radbMaster *radbm, const char *statement, ...) {
    radbObject  *dbo;
    va_list     vl;

#ifdef RADB_DEBUG
    printf("radb_prepare: %s\n", statement);
#endif
    va_start(vl, statement);
    dbo = radb_prepare_vl(radbm, statement, vl);
    va_end(vl);
    return (dbo);
}

int radb_inject(radbObject *dbo, ...) {

    int     rc;
    va_list vl;

    if (!dbo) return (0);
    va_start(vl, dbo);
    rc = radb_inject_vl(dbo, vl);
    va_end(vl);
    return (rc);
}

int radb_inject_vl(radbObject *dbo, va_list args) {
    int                     rc = 0,at;
    const char              *x = 0;
    if (!dbo) return (0);


    for (at = 0; dbo->inputs[at]; at++) {
        switch (dbo->inputs[at])
        {
            case 's':
                x = va_arg(args, const char *);
                rc = sqlite3_bind_text((sqlite3_stmt *) dbo->state, at + 1, x ? x : "", -1, SQLITE_TRANSIENT);
                break;

            case 'u':
                rc = sqlite3_bind_int((sqlite3_stmt *) dbo->state, at + 1, va_arg(args, unsigned int));
                break;

            case 'i':
                rc = sqlite3_bind_int((sqlite3_stmt *) dbo->state, at + 1, va_arg(args, signed int));
                break;

            case 'l':
                rc = sqlite3_bind_int64((sqlite3_stmt *) dbo->state, at + 1, va_arg(args, signed long long int));
                break;

            case 'f':
                rc = sqlite3_bind_double((sqlite3_stmt *) dbo->state, at + 1, va_arg(args, double));
                break;

            default:
                break;
        }

        if (rc) {
            fprintf(stderr, "[RADB] SQLite aborted with code %d at item %u!\n", rc, at + 1);
            dbo->state = 0;
        }
    }



    dbo->status = RADB_BOUND;
    return (rc);
}



signed int radb_query(radbObject *dbo) {

    signed int  rc = 0;

    if (!dbo) return (0);

    rc = (sqlite3_step((sqlite3_stmt *) dbo->state) == SQLITE_ROW) ? 1 : 0;
    dbo->status = RADB_EXECUTED;
    return (rc);
}


void radb_prepare_result(radbObject *dbo) {
    if (!dbo) return;
    dbo->result = 0;
    int count;

    count = sqlite3_column_count((sqlite3_stmt *) dbo->state);
    if (!count) return;
    dbo->result = malloc(sizeof(radbResult));
    dbo->result->column = calloc(sizeof(radbItem), count);
    dbo->result->items = count;
    dbo->result->bindings = 0;

    dbo->status = RADB_FETCH;
}


void radb_free_result(radbResult *result) {
    if (!result) return;
#ifdef RADB_DEBUG
    printf("freeing up result data\n");
#endif
    if (result->column) free(result->column);
    if (result->bindings) free(result->bindings);
    free(result);
#ifdef RADB_DEBUG
    printf("done!!\n");
#endif
}


signed int radb_run(radbMaster *radbm, const char *statement) {


    radbObject  *dbo = 0;
    signed int  rc = 0;

#ifdef RADB_DEBUG
    printf("radb_run: %s\n", statement);
    if (!radbm) printf("Error: dbm is (null)\n");
#endif
    if (!radbm) return (-1);
    dbo = radb_init_object(radbm);



    rc = sqlite3_prepare_v2((sqlite3 *) dbo->db, statement, -1, (sqlite3_stmt **) &dbo->state, NULL);

    rc = radb_query(dbo);
    radb_cleanup(dbo);
    return (rc);
}


int radb_run_inject(radbMaster *radbm, const char *statement, ...) {


    va_list     vl;
    radbObject  *dbo = 0;
    int         rc = 0;

    if (!radbm) return (-1);
#ifdef RADB_DEBUG
    printf("radb_run_inject: %s\n", statement);
#endif
    va_start(vl, statement);
    dbo = radb_prepare_vl(radbm, statement, vl);
    va_end(vl);
    rc = radb_query(dbo);
    radb_cleanup(dbo);
    return (rc);
}




radbMaster *radb_init_sqlite(const char *file) {
    radbMaster  *radbm = malloc(sizeof(radbMaster));


    radbm->pool.count = 0;
    if (sqlite3_open(file, (sqlite3 **) &radbm->handle)) {
        fprintf(stderr, "[RADB] Couldn't open %s: %s\n", file, sqlite3_errmsg((sqlite3 *) radbm->handle));
        return (0);
    }

    return (radbm);
}



radbResult *radb_step(radbObject *dbo) {
    if (!dbo) return (0);
    if (dbo->state == 0) {
        fprintf(stderr, "[RADB] Can't step: Statement wasn't prepared properly!\n");
        return (0);
    }

    int             rc = -1, l;
    unsigned int    i = 0;
    radbResult      *res;

    if (dbo->status == RADB_FETCH) rc = sqlite3_step((sqlite3_stmt *) dbo->state);
    if (dbo->status <= RADB_BOUND) rc = (radb_query(dbo) == 1) ? SQLITE_ROW : 0;
    if (dbo->status <= RADB_EXECUTED) radb_prepare_result(dbo);
    res = dbo->result;
    if (rc != SQLITE_ROW) {
        return (0);

    }
    for (i = 0; i < res->items; i++) {
        l = sqlite3_column_bytes((sqlite3_stmt *) dbo->state, i);
        memset(res->column[i].data.string, 0, l + 1);
        res->column[i].type = 2;
        switch (sqlite3_column_type((sqlite3_stmt *) dbo->state, i))
        {
        case SQLITE_TEXT:
            res->column[i].type = 1;
            memcpy(res->column[i].data.string, sqlite3_column_text((sqlite3_stmt *) dbo->state, i), l);
            break;

        case SQLITE_INTEGER:
            res->column[i].data.int64 = sqlite3_column_int64((sqlite3_stmt *) dbo->state, i);
            break;

        case SQLITE_FLOAT:
            res->column[i].data._double = sqlite3_column_double((sqlite3_stmt *) dbo->state, i);
            break;

        default:
            break;
        }
    }

    return (res);
}



