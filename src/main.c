/* File: main.c Author: Administrator Created on January 2, 2011, 8:22 AM */


#include "rumble.h"
#include "database.h"
#include "comm.h"
#include "private.h"
// #include "rumble_version.h"
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "servers.h"




extern masterHandle *Master_Handle;

#ifdef RUMBLE_LUA
#include <lua.h>
extern int (*lua_callback) (lua_State *, void *, void *);
#endif

FILE            *sysLog;
extern dvector  *debugLog;
extern char     shutUp;
static dvector  *s_args;

const char * couldn_Create_Sock = "ABORT: Couldn't create socket for service!";

int rumbleStart(void) {
    srand(time(NULL));
    masterHandle * master = (masterHandle*)malloc(sizeof(masterHandle));
    if (!master) merror();


    Master_Handle = master;

    rumble_debug(NULL, "startup", "Starting Rumble Mail Server (v/%u.%02u.%04u)", RUMBLE_MAJOR, RUMBLE_MINOR, RUMBLE_REV);
    master->_core.uptime = time(0);
    master->_core.modules = dvector_init();
    master->_core.batv = dvector_init();
    master->_core.parser_hooks = cvector_init();
    master->_core.feed_hooks = cvector_init();
    master->domains.list = dvector_init();
    master->domains.rrw = rumble_rw_init();
    master->mailboxes.rrw = rumble_rw_init();
    master->mailboxes.list = dvector_init();
    master->mailboxes.bags = cvector_init();
    master->services = cvector_init();
    master->debug.logfile = sysLog;
    master->debug.logvector = debugLog;

#ifdef RUMBLE_LUA
    lua_callback = rumble_lua_callback;
    pthread_mutex_init(&master->lua.mutex, 0);
    for (int x = 0; x < RUMBLE_LSTATES; x++) {
        master->lua.states[x].state = 0;
        master->lua.states[x].working = 0;
    }
#endif

    srand(time(0));
    rumble_config_load(master, s_args);
    if (rumble_has_dictionary_value(s_args, "execpath"))
        rumble_add_dictionary_value(master->_core.conf, "execpath", rumble_get_dictionary_value(s_args, "execpath"));
    rumble_database_load(master, 0);
    rumble_database_update_domains();

    rumble_debug(NULL, "startup", "Launching mailman service");
    rumbleService * svc = comm_registerService(master, "mailman", rumble_worker_init, 0, 1); // TODO wait for the others :>
    svc->settings.stackSize = 128 * 1024; // Set stack size for service to 128kb (should be enough)
    int rc = comm_startService(svc);
    if (!rc) {
        rumble_debug(NULL, "core", "ABORT: Couldn't launching mailman service!");
        exit(EXIT_SUCCESS);
    }

    svc = comm_registerService(master, "smtp", rumble_smtp_init, rumble_config_str(master, "smtpport"), RUMBLE_INITIAL_THREADS);
    // Set stack size for service to 128kb (should be enough)
    svc->settings.stackSize = 128 * 1024;
    if (rumble_config_int(master, "enablesmtp")) {
        rumble_debug(NULL, "core", "Launching SMTP service");
        rc = comm_startService(svc);
        if (!rc) {
            rumble_debug(NULL, "core", couldn_Create_Sock);
            exit(EXIT_SUCCESS);
        }
    }

    svc = comm_registerService(master, "pop3", rumble_pop3_init, rumble_config_str(master, "pop3port"), RUMBLE_INITIAL_THREADS);
    // Set stack size for service to 256kb (should be enough)
    svc->settings.stackSize = 256 * 1024;
    if (rumble_config_int(master, "enablepop3")) {
        rumble_debug(NULL, "core", "Launching POP3 service...");
        rc = comm_startService(svc);
        if (!rc) {
            rumble_debug(NULL, "core", couldn_Create_Sock);
            exit(EXIT_SUCCESS);
        }
    }

    svc = comm_registerService(master, "imap4", rumble_imap_init, rumble_config_str(master, "imap4port"), RUMBLE_INITIAL_THREADS);
    // Set stack size for service to 512kb (should be enough)
    svc->settings.stackSize = 512 * 1024;
    if (rumble_config_int(master, "enableimap4")) {
        rumble_debug(NULL, "core", "Launching IMAP4 service...");
        rc = comm_startService(svc);
        if (!rc) {
            rumble_debug(NULL, "startup", couldn_Create_Sock);
            exit(EXIT_SUCCESS);
        }
    }

    rumble_master_init(master);
    rumble_modules_load(master);

    //     Change into running as RunAs user after creating sockets and setting up the server
    rumble_setup_runas(master);

   // End RunAs directive
    if (rumble_has_dictionary_value(s_args, "--service")) {
        rumble_debug(NULL, "startup", "--service enabled, going stealth.");
        shutUp = 1;
    }

    rumble_debug(NULL, "startup", "Rumble is up and running, listening for incoming calls!");
    while (1) {
        cleanup();
        sleep(60);
    }

    return (EXIT_SUCCESS);
}

// char *executable;

int main(int argc, char **argv) {
//     executable = *(argv);
    shutUp = 0;
    fflush(stdout);
    s_args = dvector_init();

    char r_path[512];
    memset(r_path, 0, 512);
    char tmpfile[1024]; // TODO Size...

    if (argc) {
        char *m = argv[0], *n;

        while (m != NULL) {
            n = strchr(m + 1, '/');
            if (n) {
                m = n;
            } else {
                break;
            }
        }


        strncpy(r_path, argv[0], strlen(argv[0]) - strlen(m));
        if (chdir(r_path) == -1) { };
    }

    for (int x = 0; x < argc; x++) {
        rumble_scan_flags(s_args, argv[x]);
        rumble_add_dictionary_value(s_args, argv[x], "true");
    }

    debugLog = dvector_init();
    for (int x = 0; x < 500; x++) {
        char * dstring = (char*)calloc(1, 512);
        dvector_add(debugLog, dstring);
    }

    if (strlen(r_path)) {

        sprintf(tmpfile, "%s/rumble_status.log", r_path);
        sysLog = fopen(tmpfile, "w");
    } else sysLog = fopen("rumble_status.log", "w");
    if (!sysLog) {
        printf("Error: Couldn't open rumble_status.log for writing.\nEither rumble is already running, or I don't have access to write to this folder.\n");
        exit(0);
    }
    if (strlen(r_path)) {
        rumble_debug(NULL, "startup", "Entering directory: %s", r_path);
        rumble_add_dictionary_value(s_args, "execpath", r_path);
    }

    attach_debug();
    if (rumble_has_dictionary_value(s_args, "--service")) {
        shutUp = 1;
        int pid = fork();
        if (pid != 0) exit(EXIT_SUCCESS);
        setsid();
        printf("Starting rumble v/%u.%u.%u as daemon\n", RUMBLE_MAJOR, RUMBLE_MINOR, RUMBLE_REV);
        fclose(stdout);
        rumbleStart();
        return (0);
    } else {
        rumbleStart();
        return (0);
    }
}


void cleanup(void) {
    if (sysLog) {
        rewind(sysLog);
        dvector_element * obj = debugLog->last;
        while (obj) {
            const char * entry = (char*)obj->object;
            if (entry && strlen(entry)) fprintf(sysLog, "%s", entry);
            obj = obj->prev;
        }
        fflush(sysLog);
    }
}
