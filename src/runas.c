#include "rumble.h"
#include "private.h"
#include <pwd.h>
#include <grp.h>
#include <unistd.h>

#define DEFID 999999

void rumble_setup_runas(masterHandle* master) {

    const char *runAsUser = rumble_has_dictionary_value(master->_core.conf, "runas") ? rumble_get_dictionary_value(master->_core.conf, "runas") : "";
    const char *runAsGroup = rumble_has_dictionary_value(master->_core.conf, "runasgroup") ? rumble_get_dictionary_value(master->_core.conf, "runasgroup") : "";

    // Group credentials
    __gid_t         runAsGUID = DEFID;
    if (strlen(runAsGroup)) {

        if (!strcmp(runAsGroup, "root")) runAsGUID = 0;
        else {
            struct group    *runAsGroupEntry = getgrnam(runAsGroup);
            if (runAsGroupEntry && runAsGroupEntry->gr_gid) {
                runAsGUID = runAsGroupEntry->gr_gid;
            }
        }

        if (runAsGUID != DEFID) {
            rumble_debug(NULL, "core", "Running as group: %s", runAsGroup);

            if (setregid(runAsGUID, runAsGUID)) {
                rumble_debug(NULL, "core", "Error: Could not set process GID!");
                exit(EXIT_FAILURE);
            }
        } else {
            rumble_debug(NULL, "core", "I couldn't find the group to run as: %s", runAsGroup);
            exit(EXIT_FAILURE);
        }
    }

    // User credentials
    __uid_t         runAsUID = DEFID;
    if (strlen(runAsUser)) {

        if (!strcmp(runAsUser, "root")) runAsUID = 0;
        else {
            struct passwd   *runAsUserEntry = getpwnam(runAsUser);
            if (runAsUserEntry && runAsUserEntry->pw_uid) {
                runAsUID = runAsUserEntry->pw_uid;
            }
        }

        if (runAsUID != DEFID) {
            rumble_debug(NULL, "core", "Running as user: %s", runAsUser);

            if (setreuid(runAsUID,runAsUID)) {
                rumble_debug(NULL, "core", "Error: Could not set process UID!");
                exit(EXIT_FAILURE);
            }
        } else {
            rumble_debug(NULL, "core", "I couldn't find the user to run as: %s", runAsUser);
            exit(EXIT_FAILURE);
        }

    } else rumble_debug(NULL, "core", "no run-as directive set, running as root(?)");

}
