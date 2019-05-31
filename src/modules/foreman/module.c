// File: module.c Author: Humbedooh A simple (but efficient) load balancing module for rumble.
// Created on January 3, 2011, 8:08

#include "../../rumble.h"

masterHandle * FM_MASTER = NULL;
dvector      * FM_CONFIG = NULL;

const char * FM_LBL = "Foreman";
const char * FM_CFG = "foreman.conf";

const char * FM_CFG_BLOB = "\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n\n\
# %s\n%s  %u\n";

int FOREMAN_ENABLED         = 1;
int FOREMAN_THREAD_BUFFER   = 5;
int FOREMAN_FALLBACK        = 10;
int FOREMAN_MAX_JOBS        = 250;
int FOREMAN_MAX_THREADS     = 750;


rumblemodule_config_struct  myConfig[] = {
    { "Enabled",      1, "Enable simple (but efficient) balancing module \"Foreman\" for rumble (def yes=1, no=0)", RCS_BOOLEAN, &FOREMAN_ENABLED },
    { "ThreadBuffer", 6, "Create new workers whenever there's a shortage (default 5)",                              RCS_NUMBER,  &FOREMAN_THREAD_BUFFER },
    { "Fallback",     6, "Fall back to a minimum workers per service when idling (default 10)",                     RCS_NUMBER,  &FOREMAN_FALLBACK },
    { "MaxJobs",      6, "Maximum amount of \"jobs\" each worker is allowed before it's destroyed? (default 250)",  RCS_NUMBER,  &FOREMAN_MAX_JOBS },
    { "MaxThreads",   6, "Max number of threads each service is allowed to run at once. (default 750)",             RCS_NUMBER,  &FOREMAN_MAX_THREADS },
    { 0, 0, 0, 0 }
};


ssize_t accept_hook(sessionHandle *session, const char *junk) {
    if (!FOREMAN_ENABLED) {
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
        rumble_debug(FM_MASTER, FM_LBL, "!FOREMAN_ENABLED return RUMBLE_RETURN_OKAY");
#endif
        return (RUMBLE_RETURN_OKAY);
    }
    // If this thread is getting old, tell it to die once it's idling.
    uint32_t workload = (session->_tflags & 0xFFF00000) >> 20;   // 0xABC00000 >> 0x00000ABC
    if (workload > FOREMAN_MAX_JOBS) session->_tflags |= RUMBLE_THREAD_DIE;
    // Find out what service we're dealing with here.
    rumbleService * svc = (rumbleService *) session->_svc;
    if (svc) {
        if (svc->enabled != 1) return (RUMBLE_RETURN_IGNORE); // Return immediately if svc isn't running

        // Check if there's a shortage of workers. If there is, make some more, if not, just retur
        pthread_mutex_lock(&(svc->mutex));
        int workers = svc->threads->size;   // Number of threads alive
        int busy = svc->handles->size;      // Number of threads busy
        int idle = workers - busy;          // Number of threads idling
        if ((idle <= 1 || workers < FOREMAN_FALLBACK) && workers < FOREMAN_MAX_THREADS) {
            pthread_attr_t  attr;
            pthread_attr_init(&attr);
            pthread_attr_setstacksize(&attr, svc->settings.stackSize);
            int New = (workers + FOREMAN_THREAD_BUFFER) >= FOREMAN_FALLBACK ? FOREMAN_THREAD_BUFFER : FOREMAN_FALLBACK - workers;
            for (int x = 0; x < New; x++) {
                rumbleThread * thread = (rumbleThread *) malloc(sizeof(rumbleThread));
                if (thread) {
                    thread->status = 0;
                    thread->svc = svc;
                    cvector_add(svc->threads, thread);
                    pthread_create(&thread->thread, &attr, svc->init, (void*) thread);
                } else rumble_debug(FM_MASTER, FM_LBL, "WARNING! !malloc new thread");
            }
        }
        pthread_mutex_unlock(&(svc->mutex));
    }
    return (RUMBLE_RETURN_OKAY); // Tell the thread to continue.
}

void fm_write_config(void) {
    const char * cfgpath = rumble_config_str(FM_MASTER, "config-dir");
    char filename[1024];
    sprintf(filename, "%s/%s", cfgpath, FM_CFG);
    FILE *cfgfile = fopen(filename, "w");
    if (cfgfile) { fprintf(cfgfile, FM_CFG_BLOB
            , myConfig[0].description, myConfig[0].key, FOREMAN_ENABLED
            , myConfig[1].description, myConfig[1].key, FOREMAN_THREAD_BUFFER
            , myConfig[2].description, myConfig[2].key, FOREMAN_FALLBACK
            , myConfig[3].description, myConfig[3].key, FOREMAN_MAX_JOBS
            , myConfig[4].description, myConfig[4].key, FOREMAN_MAX_THREADS
        );
        fclose(cfgfile);
    } else rumble_debug(FM_MASTER, FM_LBL, "Error: Couldn't open <%s> for writing", filename);
}

// Standard module initialization function
rumblemodule rumble_module_init(void *master, rumble_module_info *modinfo) {
    FM_MASTER = (masterHandle *) master;
    modinfo->title       = "Foreman module";
    modinfo->description = "Standard module for dynamically managing worker pools.";
    modinfo->author      = "Humbedooh [humbedooh@users.sf.net]";
    FM_CONFIG = rumble_readconfig(FM_CFG);
    if (!FM_CONFIG) {
        rumble_debug(FM_MASTER, FM_LBL, "Configuration not set, write defaults...");
        fm_write_config();
    } else {
        FOREMAN_ENABLED         = atoi(rumble_get_dictionary_value(FM_CONFIG, myConfig[0].key));
        FOREMAN_THREAD_BUFFER   = atoi(rumble_get_dictionary_value(FM_CONFIG, myConfig[1].key));
        FOREMAN_FALLBACK        = atoi(rumble_get_dictionary_value(FM_CONFIG, myConfig[2].key));
        FOREMAN_MAX_JOBS        = atoi(rumble_get_dictionary_value(FM_CONFIG, myConfig[3].key));
        FOREMAN_MAX_THREADS     = atoi(rumble_get_dictionary_value(FM_CONFIG, myConfig[4].key));
    }
    // Hook the module to incoming connections on any service.
    rumble_hook_function(master, RUMBLE_HOOK_SMTP + RUMBLE_HOOK_ACCEPT, accept_hook);
    rumble_hook_function(master, RUMBLE_HOOK_POP3 + RUMBLE_HOOK_ACCEPT, accept_hook);
    rumble_hook_function(master, RUMBLE_HOOK_IMAP + RUMBLE_HOOK_ACCEPT, accept_hook);
    return (EXIT_SUCCESS);  // Tell rumble that the module loaded okay.
}

// rumble_module_config: Sets a config value or retrieves a list of config values.
rumbleconfig rumble_module_config(const char *key, const char *value) {
    if (!key) return (myConfig);
#if (RUMBLE_DEBUG & RUMBLE_DEBUG_MODULES)
    rumble_debug(FM_MASTER, FM_LBL, "Module config key|value <%s>|<%s>", key, value);
#endif
    value = value ? value : "0";
    if (!strcmp(key, myConfig[0].key) && value) FOREMAN_ENABLED       = atoi(value);
    if (!strcmp(key, myConfig[1].key) && value) FOREMAN_THREAD_BUFFER = atoi(value);
    if (!strcmp(key, myConfig[2].key) && value) FOREMAN_FALLBACK      = atoi(value);
    if (!strcmp(key, myConfig[3].key) && value) FOREMAN_MAX_JOBS      = atoi(value);
    if (!strcmp(key, myConfig[4].key) && value) FOREMAN_MAX_THREADS   = atoi(value);
    fm_write_config();
    return (NULL);
}
