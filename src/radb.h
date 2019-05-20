#ifndef _RADB_H_
#define _RADB_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <stdint.h>
#include <sqlite3.h>


#define RADB_EMPTY      0
#define RADB_PARSED     1
#define RADB_PREPARED   2
#define RADB_BOUND      3
#define RADB_EXECUTED   4
#define RADB_FETCH      5


typedef struct {
    unsigned    inUse;
    void        *handle;
} radbChild;

typedef struct {
    radbChild   *children;
    unsigned    count;
} radbPool;

typedef struct {
    //unsigned    dbType;
    radbPool    pool;
    void        *handle;
} radbMaster;

typedef struct {
    enum { STRING = 1, NUMBER = 2 } types;
    unsigned    type;
    unsigned    size;
    union
    {
        char        string[256];
        uint32_t    uint32;
        int32_t     int32;
        int64_t     int64;
        uint64_t    uint64;
        double      _double;
        float       _float;
    } data;
} radbItem;

//     radbResult: A result object holding the currently fetched row of data

typedef struct {
    radbItem    *column;
    unsigned    items;
    void        *bindings;
} radbResult;

//     radbObject: An object holding the current SQL statement and its status

typedef struct {
    void        *state;
    void        *db;
    unsigned    status;
    char        buffer[1024];
    radbResult  *result;
    radbMaster  *master;
    void        *inputBindings;
    char        inputs[64];
    const char  *lastError;
} radbObject;

// Fixed prototypes

// radb_run: Run a plain SQL command and retrieve the number of rows affected or returned, nothing else. This function
// is a wrapper for opening, querying and closing a database handle.
signed int  radb_run(radbMaster *radbm, const char *statement);

// radb_run_inject: Same as radb_run, but with a formatted statement with injected values.
int radb_run_inject(radbMaster *radbm, const char *statement, ...);

// radb_prepare: Initiates a prepared statement with (or without) injected values. If you have injected values (or none are needed),
// you can call radb_query to retrieve the number of rows affected or returned, depending on your statement.
radbObject  *radb_prepare(radbMaster *radbm, const char *statement, ...);
radbObject  *radb_prepare_vl(radbMaster *dbm, const char *statement, va_list vl);

// radb_inject: Injects new values into the prepared statement referenced by dbo.
int radb_inject(radbObject *dbo, ...);

// radb_inject_vl: Same as radb_inject but with a va_list instead.
int radb_inject_vl(radbObject *dbo, va_list args);

//  radb_query: Runs the prepared statement and returns the number of rows affected of returned (depending on your SQL operation)
signed int  radb_query(radbObject *dbo);

// radb_step (aka radb_fetch_row): Fetches a result from the active query. If the query hasn't been executed yet.
// radb_step takes care of that as well.
radbResult  *radb_step(radbObject *dbo);

// radb_free_result: Frees up a result struct. You shouldn't use this unless you know what you're doing - instead,
// use radb_cleanup at the end of your query.
void    radb_free_result(radbResult *result);

// radb_cleanup: Cleans up after a statement has been executed and the results, bindings etc are no longer needed.
void    radb_cleanup(radbObject *dbo);

// radb_prepare_result: Internal function for preparing the result structure based on the SQL operation
void        radb_prepare_result(radbObject *dbo);
const char  *radb_last_error(radbObject *dbo);


// radb_close: Shuts down the database connection and frees up the handles etc etc.
void    radb_close(radbMaster *dbm);

// Model-specific definitions
radbMaster  *radb_init_sqlite(const char *file);

#   define radb_free       radb_free_result
#   define radb_fetch_row  radb_step
#   define radb_do         radb_run

#endif
