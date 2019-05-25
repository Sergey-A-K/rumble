#include <string.h>
#include "../../rumble.h"

ssize_t sample_hook(sessionHandle *session, const char *filename) {
    (void)session;
    (void)filename;
    return (RUMBLE_RETURN_OKAY);
}

rumblemodule rumble_module_init(void *master, rumble_module_info *modinfo) {
    (void)modinfo;
    // Do stuff here... ;
    // Hook the module to new SMTP connections
    rumble_hook_function(master, RUMBLE_HOOK_SMTP + RUMBLE_HOOK_ACCEPT, sample_hook);
    return (EXIT_SUCCESS); // Tell rumble that the module loaded okay.
}
