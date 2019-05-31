// File: main.c Author: Administrator Created on January 2, 2011, 8:22 AM
#include "rumble.h"
#include "database.h"
#include "comm.h"
#include "private.h"
#include <sys/types.h>
#include <dlfcn.h>
#include "servers.h"

#ifdef RUMBLE_LUA
#include <lua.h>
int (*lua_callback) (lua_State *, void *, void *);
#endif


FILE *sysLog = NULL;
dvector *debugLog = NULL;
const char *log_f_name = "rumble_status.log";
static dvector *s_args;
masterHandle *Master_Handle = NULL;

#define LOG(x ...) rumble_debug(NULL, "core", x);

typedef int (*rumbleModInit) (void *master, rumble_module_info *modinfo);
typedef uint32_t (*rumbleVerCheck) (void);
typedef rumblemodule_config_struct * (*rumbleModConfig) (const char *key, const char *value);



int rumbleStart(void) {
    srand(time(NULL));
    masterHandle * master = (masterHandle*)malloc(sizeof(masterHandle));
    if (!master) merror();

    Master_Handle = master;

    LOG("Starting Rumble Mail Server (v/%u.%02u.%04u)", RUMBLE_MAJOR, RUMBLE_MINOR, RUMBLE_REV);
    master->_core.uptime        = time(0);
    master->_core.modules       = dvector_init();
    master->_core.batv          = dvector_init();
    master->_core.parser_hooks  = cvector_init();
    master->_core.feed_hooks    = cvector_init();
    master->domains.list        = dvector_init();
    master->domains.rrw         = rumble_rw_init();
    master->mailboxes.rrw       = rumble_rw_init();
    master->mailboxes.list      = dvector_init();
    master->mailboxes.bags      = cvector_init();
    master->services            = cvector_init();
    master->debug.logfile       = sysLog;
    master->debug.logvector     = debugLog;

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
    if (rumble_has_dictionary_value(s_args, "execpath")) // for database
        rumble_add_dictionary_value(master->_core.conf, "execpath", rumble_get_dictionary_value(s_args, "execpath"));
    rumble_database_load(master, 0);
    rumble_database_update_domains();

    rumble_master_init_smtp(master);
    rumble_master_init_pop3(master);
    rumble_master_init_imap4(master);
    rumble_master_init_mailman(master);


    LOG("Loading modules...");
    dvector_element     *line;
    for (line = master->_core.conf->first; line != NULL; line = line->next) {
        rumbleKeyValuePair * el = (rumbleKeyValuePair *) line->object;

        if (!strcmp(el->key, "loadmodule")) {
            LOG("Loading %s...", el->value);
            void * handle = dlopen(el->value, RTLD_LAZY | RTLD_NODELETE);
            char * error  = dlerror();
            if (!handle) {
                error = error ? error : "(no such file?)";
                fprintf(stderr, "\nError loading %s: %s\n", el->value, error);
                LOG("Error loading %s: %s", el->value, error);
                exit(1);
            }

            if (error) LOG("Loadmodule warning: %s", error);
            rumble_module_info * modinfo = (rumble_module_info *) calloc(1, sizeof(rumble_module_info));
            if (!modinfo) merror();
            modinfo->author      = NULL;
            modinfo->description = NULL;
            modinfo->title       = NULL;
            rumbleModInit  init   = (rumbleModInit)   dlsym(handle, "rumble_module_init");
            rumbleVerCheck mcheck = (rumbleVerCheck)  dlsym(handle, "rumble_module_check");
            modinfo->config       = (rumbleModConfig) dlsym(handle, "rumble_module_config");
            error = (init == 0 || mcheck == 0) ? "no errors" : 0;
            if (error != NULL) {
                LOG("Warning: %s does not contain required module functions.", el->value);
            }

            if (init && mcheck) {
                master->_core.currentSO = el->value;
                dvector_add(master->_core.modules, modinfo);
                uint32_t ver = (*mcheck) ();
                ver = (ver & 0xFFFFFF00) + (RUMBLE_VERSION & 0x000000FF);
                int x = EXIT_SUCCESS;

                if (ver > RUMBLE_VERSION || ver < RUMBLE_VERSION_REQUIRED) {
                    LOG("ERROR: %s was compiled with librumble version (v%#X), server executable (v%#X)", el->value, ver, RUMBLE_VERSION);
                } else { // version OK
                    modinfo->file = el->value;
                    x = init(master, modinfo);
                }

                if (x == EXIT_SUCCESS) {
                    if (modinfo->title) LOG("Loaded extension: %-30s", modinfo->title)
                    else LOG("Loaded %48s", el->value);
                } else {
                    LOG("Error: %s failed to load!", el->value);
                    dlclose(handle);
                }
            } //else dlclose(handle);
        }

    }

    LOG("Loading scripts...");

#ifdef RUMBLE_LUA
    for (line = master->_core.conf->first; line != NULL; line = line->next) {
        rumbleKeyValuePair * el = (rumbleKeyValuePair *) line->object;
        if (!strcmp(el->key, "loadscript")) { rumble_loadscript(el->value); }
    }
#endif

    // Change into running as RunAs user after creating sockets and setting up the server
    rumble_setup_runas(master);
    // End RunAs directive

    if (rumble_has_dictionary_value(s_args, "--SERVICE")) {
        LOG("--service enabled, going stealth.");

    }

    LOG("Rumble is up and running, listening for incoming calls!");
    while (1) {
        cleanup();
        sleep(60);
    }

    return (EXIT_SUCCESS);
}

// ================================================================= //
//                          MAIN
// ================================================================= //
int main(int argc, char **argv) {
    fflush(stdout);
    char r_path[512];
    memset(r_path, 0, 512);

    if (argc) {
        char *m = argv[0];
        while (m != NULL) {
            char * n = strchr(m + 1, '/');
            if (n) m = n; else break;
        }

        strncpy(r_path, argv[0], strlen(argv[0]) - strlen(m));

        if (chdir(r_path) == -1) {
            printf("Cannot chdir(%s)\n", r_path);
        };
    }

    s_args = dvector_init();
    for (int x = 0; x < argc; x++) {
        if (!strcmp(argv[x], "--help")) {

            printf("\
Usage: rumble [parameters]\n\
Available parameters:\n\
--service          : Starting rumble as daemon\n\
--config-dir=<dir> : Set <dir> for rumble.conf\n\
--help             : Print this help\nv/%u.%u.%u\n", RUMBLE_MAJOR, RUMBLE_MINOR, RUMBLE_REV);
            return (EXIT_SUCCESS);
        }

        rumble_scan_flags(s_args, argv[x]); // key UPPER!
        rumble_add_dictionary_value(s_args, argv[x], "true"); //
    }


    debugLog = dvector_init();
    for (int x = 0; x < 500; x++) {
        char * dstring = (char*)calloc(1, 512);
        dvector_add(debugLog, dstring);
    }

    char * tmpfile = (char*)calloc(1, strlen(r_path) + strlen(log_f_name) + 1);
    if (strlen(r_path)) {
        rumble_add_dictionary_value(s_args, "execpath", r_path);
        sprintf(tmpfile, "%s/%s", r_path, log_f_name);
    } else
        tmpfile = strclone(log_f_name);

    sysLog = fopen(tmpfile, "w");
    if (!sysLog)
        printf("Couldn't open <%s> for writing.\n", tmpfile);

    attach_debug();

    if (rumble_has_dictionary_value(s_args, "--service")) {
        if (!sysLog) { // sysLog need for daemon
            printf("\n\nWork in daemon mode is not possible.\nRedirect <%s> to stdout.\n\n", log_f_name);
            sysLog = stdout;
        } else { // sysLog accessible
            __pid_t pid = fork();
            if (pid != 0) return(EXIT_SUCCESS);
            __pid_t PID = setsid();
            printf("Rumble in daemon mode, PID=%d\n", PID);
            fclose(stdout);
        }
    }
    rumbleStart();
    return (EXIT_SUCCESS);
}


void cleanup(void) {
    if (sysLog) {
        rewind(sysLog);
        dvector_element * obj = debugLog->last;
        while (obj) {
            const char * entry = obj->object;
            if (entry && strlen(entry)) fprintf(sysLog, "%s", entry);
            obj = obj->prev;
        }
        fflush(sysLog);
    }
}
