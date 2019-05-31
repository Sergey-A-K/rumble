#include "rumble.h"

#include "radb.h"


#define RADB_TRACE(x ...)
/*
#define RADB_TRACE(x ...) { \
    fprintf(stderr, __FILE__); \
    fprintf(stderr, " "); \
    fprintf(stderr, x); \
    fprintf(stderr, "\n"); \
}
*/

radbObject *radb_init_object(radbMaster *dbm) {
    if (!dbm) {
        RADB_TRACE("%d:%s(): Received a null-pointer as dbm", __LINE__, __func__);
        return (NULL);
    }

    radbObject * dbo = (radbObject *) calloc(1, sizeof(radbObject));
    if (dbo) {
        dbo->master = dbm;
        dbo->result = 0;
        dbo->inputBindings = 0;
        dbo->lastError = 0;
        memset(dbo->inputs, 0, 64);
        dbo->status = RADB_EMPTY;
        dbo->db = dbm->handle;
        RADB_TRACE("%d:%s(): Normal init dbo", __LINE__, __func__);
        return (dbo);
    }
    RADB_TRACE("%d:%s(): !calloc for dbo", __LINE__, __func__);
    return(NULL);
}


void radb_cleanup(radbObject *dbo) {
    if (!dbo) {
        RADB_TRACE("%d:%s(): Received a null-pointer as dbo", __LINE__, __func__);
        return;
    }
    RADB_TRACE("%d:%s(): Cleaning up", __LINE__, __func__);
    if (dbo->state) sqlite3_finalize((sqlite3_stmt *) dbo->state);
    RADB_TRACE("%d:%s(): Calling radb_free_result", __LINE__, __func__);
    if (dbo->result) radb_free_result(dbo->result);
    if (dbo->inputBindings) free(dbo->inputBindings);
    free(dbo);
}

void radb_close(radbMaster *dbm) {
    if (!dbm) {
        RADB_TRACE("%d:%s(): Received a null-pointer as dbm", __LINE__, __func__);
        return;
    }
    RADB_TRACE("%d:%s(): Calling sqlite3_close", __LINE__, __func__);
    sqlite3_close((sqlite3 *) dbm->handle);
    free(dbm);
    return;
}


const char *radb_last_error(radbObject *dbo) {
    if (!dbo) return ("(null)");
    return (dbo->lastError ? dbo->lastError : "No error");
}


radbObject *radb_prepare_vl(radbMaster *dbm, const char *statement, va_list vl) {
    radbObject * dbo = radb_init_object(dbm);
    if (!dbo) return (NULL);
    char * sql = (char *) calloc(1, 2048);
    if (!sql) {
        RADB_TRACE("%d:%s(): !calloc for sql", __LINE__, __func__);
        return (NULL);
    }
    dbo->status = 0;
    char b = 0;
    size_t len = 0, strl = 0;
    int at = 0;
    const char * op = statement;
    const char * p;
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
    strncpy((char *) (sql + len), op, strlen(op));
    strl = strlen(sql);
    if (sql[strl - 1] != ';') sql[strl++] = ';';
    dbo->status = RADB_PARSED;
    int rc = sqlite3_prepare_v2((sqlite3 *) dbo->db, sql, -1, (sqlite3_stmt **) &dbo->state, NULL);
    RADB_TRACE("%d:%s(): Prepared: %s", __LINE__, __func__, sql);
    free(sql);
    if (rc) {
        RADB_TRACE("%d:%s(): Prepared result !=0, exit", __LINE__, __func__);
        radb_cleanup(dbo);
        return (0);
    }
    radb_inject_vl(dbo, vl);
    RADB_TRACE("%d:%s(): Done! Return dbo", __LINE__, __func__);
    return (dbo);
}



radbObject *radb_prepare(radbMaster *radbm, const char *statement, ...) {
    va_list vl;
    va_start(vl, statement);
    radbObject * dbo = radb_prepare_vl(radbm, statement, vl);
    va_end(vl);
    return (dbo);
}

int radb_inject(radbObject *dbo, ...) {
    if (!dbo) {
        RADB_TRACE("%d:%s(): Received a null-pointer as dbo", __LINE__, __func__);
        return (0);
    }
    va_list vl;
    va_start(vl, dbo);
    int rc = radb_inject_vl(dbo, vl);
    va_end(vl);
    RADB_TRACE("%d:%s(): Return %d", __LINE__, __func__, rc);
    return (rc);
}

int radb_inject_vl(radbObject *dbo, va_list args) {
    if (!dbo) {
        RADB_TRACE("%d:%s(): Received a null-pointer as dbo", __LINE__, __func__);
        return (0);
    }
    int rc = 0;
    const char *x;
    for (int at = 0; dbo->inputs[at]; at++) {
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
            RADB_TRACE("%d:%s(): SQLite aborted with code %d at item %u!", __LINE__, __func__, rc, at + 1);
            dbo->state = 0;
        }
    }
    dbo->status = RADB_BOUND;
    RADB_TRACE("%d:%s(): Return %d", __LINE__, __func__, rc);
    return (rc);
}



int radb_query(radbObject *dbo) {
    if (!dbo) {
        RADB_TRACE("%d:%s(): Received a null-pointer as dbo", __LINE__, __func__);
        return (0);
    }
    int rc = (sqlite3_step((sqlite3_stmt *) dbo->state) == SQLITE_ROW) ? 1 : 0;
    dbo->status = RADB_EXECUTED;
    RADB_TRACE("%d:%s(): Return %d", __LINE__, __func__, rc);
    return (rc);
}


void radb_prepare_result(radbObject *dbo) {
    if (!dbo) {
        RADB_TRACE("%d:%s(): Received a null-pointer as dbo", __LINE__, __func__);
        return;
    }
    dbo->result = 0;
    int count = sqlite3_column_count((sqlite3_stmt *) dbo->state);
    if (!count) {
        RADB_TRACE("%d:%s(): count zero, return", __LINE__, __func__);
        return;
    }
    dbo->result = malloc(sizeof(radbResult));
    if (!dbo->result) {
        RADB_TRACE("%d:%s(): !malloc(radbResult), BAD", __LINE__, __func__);
    }
    dbo->result->column = calloc(sizeof(radbItem), count);
    if (!dbo->result->column) {
        RADB_TRACE("%d:%s(): !calloc(radbItem, %d), BAD", __LINE__, __func__, count);
    }
    dbo->result->items = count;
    dbo->result->bindings = 0;
    dbo->status = RADB_FETCH;
    RADB_TRACE("%d:%s(): Prepared result", __LINE__, __func__);
}


void radb_free_result(radbResult *result) {
    if (!result) {
        RADB_TRACE("%d:%s(): Received a null-pointer as result", __LINE__, __func__);
        return;
    }
    RADB_TRACE("%d:%s(): freeing up result data", __LINE__, __func__);
    if (result->column) free(result->column);
    if (result->bindings) free(result->bindings);
    free(result);
    RADB_TRACE("%d:%s(): freeing completed", __LINE__, __func__);
}


int radb_run(radbMaster *radbm, const char *statement) {
    if (!radbm) {
        RADB_TRACE("%d:%s(): Received a null-pointer as radbm", __LINE__, __func__);
        return (-1);
    }
    RADB_TRACE("%d:%s(): %s", __LINE__, __func__, statement);
    radbObject * dbo = radb_init_object(radbm);
    int rc = sqlite3_prepare_v2((sqlite3 *) dbo->db, statement, -1, (sqlite3_stmt **) &dbo->state, NULL);
    rc = radb_query(dbo);
    radb_cleanup(dbo);
    return (rc);
}


int radb_run_inject(radbMaster *radbm, const char *statement, ...) {
    if (!radbm) {
        RADB_TRACE("%d:%s(): Received a null-pointer as radbm", __LINE__, __func__);
        return (-1);
    }
    va_list     vl;
    va_start(vl, statement);
    radbObject * dbo = radb_prepare_vl(radbm, statement, vl);
    va_end(vl);
    int rc = radb_query(dbo);
    radb_cleanup(dbo);
    return (rc);
}


radbMaster *radb_init_sqlite(const char *file) {
    if (!file) {
        RADB_TRACE("%d:%s(): Received a null-pointer as file", __LINE__, __func__);
    }
    radbMaster  *radbm = malloc(sizeof(radbMaster));
    if (radbm) {
        radbm->pool.count = 0;
        if (sqlite3_open(file, (sqlite3 **) &radbm->handle)) {
            RADB_TRACE("%d:%s(): Couldn't open %s: %s", __LINE__, __func__, file, sqlite3_errmsg((sqlite3*) radbm->handle););
            free(radbm);
            return (NULL);
        }
        return (radbm);
    }
    return (NULL);
}



radbResult *radb_step(radbObject *dbo) {
    if (!dbo) {
        RADB_TRACE("%d:%s(): Received a null-pointer as dbo", __LINE__, __func__);
        return (NULL);
    }
    if (dbo->state == NULL) {
        RADB_TRACE("%d:%s(): Can't step: Statement wasn't prepared properly!", __LINE__, __func__);
        return (NULL);
    }

    int rc = -1;
    if (dbo->status == RADB_FETCH) rc = sqlite3_step((sqlite3_stmt *) dbo->state);
    if (dbo->status <= RADB_BOUND) rc = (radb_query(dbo) == 1) ? SQLITE_ROW : 0;
    if (dbo->status <= RADB_EXECUTED) radb_prepare_result(dbo);

    if (rc != SQLITE_ROW) {
        RADB_TRACE("%d:%s(): rc != SQLITE_ROW, return NULL", __LINE__, __func__);
        return (NULL);
    }

    radbResult * res = dbo->result;
    for (int i = 0; i < res->items; i++) {
        int l = sqlite3_column_bytes((sqlite3_stmt *) dbo->state, i);
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
    RADB_TRACE("%d:%s(): return result", __LINE__, __func__);
    return (res);
}



