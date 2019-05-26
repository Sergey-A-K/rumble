#include "../../rumble.h"
#include "../../private.h"
#include <string.h>

dvector *configuration;
cvector *gatekeeper_login_list, *gatekeeper_connection_list;
rumble_readerwriter* Gatekeeper_lock = 0;
masterHandle *myMaster = 0;

typedef struct {
    char    ip[66];
    int     connections;
} gatekeeper_connection;

typedef struct {
    char    ip[66];
    int     tries;
    time_t  lastAttempt;
    char    quarantined;
} gatekeeper_login_attempt;

int Gatekeeper_enabled                       = 1;
int Gatekeeper_max_login_attempts            = 3;
int Gatekeeper_max_concurrent_threads_per_ip = 25;
int Gatekeeper_quarantine_period             = 300;

const char * _gk_label = "GateKeeper";
const char * _gk_conf  = "gatekeeper.conf";

rumblemodule_config_struct  myConfig[] = {
    { "Enabled",       1, "Enable gatekeeper?",                                         RCS_BOOLEAN, &Gatekeeper_enabled },
    { "LoginAttempts", 2, "Maximum of concurrent login attempts per IP",                RCS_NUMBER,  &Gatekeeper_max_login_attempts },
    { "ThreadsPerIP",  3, "Maximum of concurrent threads per IP",                       RCS_NUMBER,  &Gatekeeper_max_concurrent_threads_per_ip },
    { "Quarantine",    3, "Number of seconds to quarantine an IP for too many attempts",RCS_NUMBER,  &Gatekeeper_quarantine_period },
    { 0, 0, 0, 0 }
};


const char * c_gk_blob = "\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n";


void gk_write_config(void) {
    const char * cfgpath = rumble_config_str(myMaster, "config-dir");
    char filename[1024];
    sprintf(filename, "%s/%s", cfgpath, _gk_conf);
    FILE *cfgfile = fopen(filename, "w");
    if (cfgfile) {
        fprintf(cfgfile, c_gk_blob, myConfig[0].description, myConfig[0].key, Gatekeeper_enabled,
                                    myConfig[1].description, myConfig[1].key, Gatekeeper_max_login_attempts,
                                    myConfig[2].description, myConfig[2].key, Gatekeeper_max_concurrent_threads_per_ip,
                                    myConfig[3].description, myConfig[3].key, Gatekeeper_quarantine_period );
        fclose(cfgfile);
    } else rumble_debug(myMaster, _gk_label, "Error: Couldn't open <%s> for writing", filename);
}

// rumble_module_config: Sets a config value or retrieves a list of config values
rumbleconfig rumble_module_config(const char *key, const char *value) {

    if (!key) { return (myConfig); }
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
            rumble_debug(myMaster, _gk_label, "Module config key|value <%s>|<%s>", key, value);
#endif
    if (!strcmp(key, myConfig[0].key) && value) Gatekeeper_enabled                       = atoi(value);
    if (!strcmp(key, myConfig[1].key) && value) Gatekeeper_max_login_attempts            = atoi(value);
    if (!strcmp(key, myConfig[2].key) && value) Gatekeeper_max_concurrent_threads_per_ip = atoi(value);
    if (!strcmp(key, myConfig[3].key) && value) Gatekeeper_quarantine_period             = atoi(value);
    gk_write_config();
    return (0);

}



ssize_t rumble_gatekeeper_accept(sessionHandle *session, const char *junk) {
    gatekeeper_login_attempt* lentry;
    gatekeeper_connection* centry;
    time_t          now;
    c_iterator      iter;
    int found = 0;

    if (!Gatekeeper_enabled) return (RUMBLE_RETURN_OKAY);

    // First, check the guys quarantined through bad login attempts
    cforeach((gatekeeper_login_attempt*), lentry, gatekeeper_login_list, iter) {
        if (!strcmp(lentry->ip, session->client->addr)) {
            if (lentry->quarantined == 1) {
                now = time(0);
                if ((now - lentry->lastAttempt) > Gatekeeper_quarantine_period) {
                    lentry->quarantined = 0;
                    lentry->tries = 0;
                    break;
                }
                else {
                    rumble_comm_printf(session, "Too many bad logins! Quarantined for %u seconds.\r\n", Gatekeeper_quarantine_period);
                    return RUMBLE_RETURN_FAILURE;
                }
            }
        }
    }
    // Then check the number of connections
    // Then, let's check if the IP is using too many threads
    rumble_rw_start_write(Gatekeeper_lock);
    cforeach((gatekeeper_connection*), centry, gatekeeper_connection_list, iter) {
        if (!memcmp(centry->ip, session->client->addr, 46)) {
            centry->connections++;
            found = 1;
            break;
        }
    }
    if (!found) {
        centry = (gatekeeper_connection*) calloc(1, sizeof(gatekeeper_connection));
        strcpy(centry->ip, session->client->addr);
        centry->connections = 1;
        cvector_add(gatekeeper_connection_list, centry);
    }
    rumble_rw_stop_write(Gatekeeper_lock);

    if (centry->connections > Gatekeeper_max_concurrent_threads_per_ip) {
        rumble_comm_printf(session, "Too many connections (%u) open to this IP!\r\n", centry->connections);
        rumble_debug(myMaster, "gatekeeper", "Client <%s> exceeded the maximum number of open connections (%u)", centry->ip, centry->connections);
        return RUMBLE_RETURN_FAILURE;
    }
    return (RUMBLE_RETURN_OKAY);
}


ssize_t rumble_gatekeeper_close(sessionHandle *session, const char *junk) {
    gatekeeper_connection* centry;
    c_iterator      iter;
    if (!Gatekeeper_enabled) return (RUMBLE_RETURN_OKAY);
    rumble_rw_start_write(Gatekeeper_lock);
    cforeach((gatekeeper_connection*), centry, gatekeeper_connection_list, iter) {
        if (!memcmp(centry->ip, session->client->addr, 46)) {
            centry->connections--;
            if (centry->connections == 0) {
                cvector_delete(&iter);
                free(centry);
            }
        }
    }
    rumble_rw_stop_write(Gatekeeper_lock);
    return RUMBLE_RETURN_OKAY;
}


ssize_t rumble_gatekeeper_auth(sessionHandle *session, const char *OK) {
    gatekeeper_login_attempt* entry;
    c_iterator      iter;
    if (!Gatekeeper_enabled) return (RUMBLE_RETURN_OKAY);
    // Was the login OK? If so, let's delete any counters we have
    if (OK) {
        cforeach((gatekeeper_login_attempt*), entry, gatekeeper_login_list, iter) {
            if (!strcmp(entry->ip, session->client->addr)) {
                cvector_delete(&iter);
                free(entry);
                break;
            }
        }
    }
    // Login went bad, let's write that down!
    else {
        int found = 0;

        cforeach((gatekeeper_login_attempt*), entry, gatekeeper_login_list, iter) {
            if (!strcmp(entry->ip, session->client->addr)) {
                entry->tries++;
                entry->lastAttempt = time(0);
                if (entry->tries >= Gatekeeper_max_login_attempts) {
                    entry->quarantined = 1;
                    rumble_comm_printf(session, "Too many login attempts (>%u) detected, quarantined for %u seconds!\r\n", Gatekeeper_max_login_attempts, Gatekeeper_quarantine_period);
                    rumble_debug(myMaster, "module", "Too many failed login attempts from %s, quarantining.", session->client->addr);
                    return RUMBLE_RETURN_FAILURE;
                }
                found = 1;
            }
        }
        if (!found) {
            entry = (gatekeeper_login_attempt*) malloc(sizeof(gatekeeper_login_attempt));
            entry->tries = 1;
            entry->lastAttempt = time(0);
            entry->quarantined = 0;
            strcpy(entry->ip, session->client->addr);
            cvector_add(gatekeeper_login_list, entry);
        }
    }

    return (RUMBLE_RETURN_OKAY);
}

// ----------------------------------------------------------------------------------------- //
rumblemodule rumble_module_init(void *master, rumble_module_info *modinfo) {
    myMaster = (masterHandle *) master;
    modinfo->title        = "Gatekeeper module";
    modinfo->description  = "This module controls how many login attempts and concurrent connections each client is allowed.";
    modinfo->author       = "Humbedooh [humbedooh@users.sf.net]";
    configuration = rumble_readconfig(_gk_conf);
    if (!configuration) {
        gk_write_config();
    } else {
        Gatekeeper_enabled                       = atoi(rumble_get_dictionary_value(configuration, myConfig[0].key));
        Gatekeeper_max_login_attempts            = atoi(rumble_get_dictionary_value(configuration, myConfig[1].key));
        Gatekeeper_max_concurrent_threads_per_ip = atoi(rumble_get_dictionary_value(configuration, myConfig[2].key));
        Gatekeeper_quarantine_period             = atoi(rumble_get_dictionary_value(configuration, myConfig[3].key));
    }
    if (Gatekeeper_enabled) {
        gatekeeper_login_list      = cvector_init();
        gatekeeper_connection_list = cvector_init();
        Gatekeeper_lock            = rumble_rw_init();

        if (!gatekeeper_login_list || !gatekeeper_connection_list || !Gatekeeper_lock) {
            rumble_debug(myMaster, _gk_label, "Can't init vectors!" );
            return (EXIT_FAILURE);
        }
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
        rumble_debug(myMaster, _gk_label, "Vectors init. %s=%d, %s=%d, %s=%d", myConfig[1].key, Gatekeeper_max_login_attempts,
            myConfig[2].key, Gatekeeper_max_concurrent_threads_per_ip, myConfig[3].key, Gatekeeper_quarantine_period );
#endif

        // Hook onto any new incoming connections on SMTP, IMAP and POP3
        rumble_hook_function(master, RUMBLE_HOOK_SMTP + RUMBLE_HOOK_ACCEPT, rumble_gatekeeper_accept);
        rumble_hook_function(master, RUMBLE_HOOK_IMAP + RUMBLE_HOOK_ACCEPT, rumble_gatekeeper_accept);
        rumble_hook_function(master, RUMBLE_HOOK_POP3 + RUMBLE_HOOK_ACCEPT, rumble_gatekeeper_accept);

        // Hook onto any new closing connections on SMTP, IMAP and POP3
        rumble_hook_function(master, RUMBLE_HOOK_SMTP + RUMBLE_HOOK_CLOSE, rumble_gatekeeper_close);
        rumble_hook_function(master, RUMBLE_HOOK_IMAP + RUMBLE_HOOK_CLOSE, rumble_gatekeeper_close);
        rumble_hook_function(master, RUMBLE_HOOK_POP3 + RUMBLE_HOOK_CLOSE, rumble_gatekeeper_close);

        // Hook the module to the LOGIN command on the SMTP, POP3 and IMAP server.
        rumble_hook_function(master, RUMBLE_HOOK_SMTP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_SMTP_AUTH, rumble_gatekeeper_auth);
        rumble_hook_function(master, RUMBLE_HOOK_IMAP + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_IMAP_AUTH, rumble_gatekeeper_auth);
        rumble_hook_function(master, RUMBLE_HOOK_POP3 + RUMBLE_HOOK_COMMAND + RUMBLE_HOOK_AFTER + RUMBLE_CUE_POP3_PASS, rumble_gatekeeper_auth);

        rumble_debug(myMaster, _gk_label, "Added hooks. Init [OK]");
    } else {
        rumble_debug(myMaster, _gk_label, "This module is currently disabled via <%s>!", _gk_conf);
        return (EXIT_FAILURE);
    }

    return (EXIT_SUCCESS); // Tell rumble that the module loaded okay.


}

