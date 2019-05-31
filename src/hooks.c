
#include "rumble.h"
#include "servers.h"
#include <string.h>
#include "rumble_version.h"
#include "comm.h"

#define HOOKLOG(x ...)

#ifdef RUMBLE_LUA
#include <lua.h>
int (*lua_callback) (lua_State *, void *, void *);
#endif


rumblemodule rumble_module_check(void) {
    return (RUMBLE_VERSION);
}


void rumble_hook_function(void *handle, uint32_t flags, ssize_t (*func) (sessionHandle *, const char *)) {
    hookHandle *hook = (hookHandle *) malloc(sizeof(hookHandle));
    if (!hook) merror();
    rumble_module_check();

#ifdef RUMBLE_LUA
    hook->lua_callback = 0;
#endif

    hook->func = func;
    hook->flags = flags;
    hook->module = ((masterHandle *) handle)->_core.currentSO;
    hook->modinfo = (rumble_module_info *) ((masterHandle *) handle)->_core.modules->last;

    HOOKLOG("Adding hook of type %#x from %s", hook->flags, hook->module);

    rumbleService * svc;
    switch (flags & RUMBLE_HOOK_STATE_MASK) {
        case RUMBLE_HOOK_ACCEPT:
            switch (flags & RUMBLE_HOOK_SVC_MASK) {
                case RUMBLE_HOOK_SMTP:
                    svc = comm_serviceHandleExtern((masterHandle *) handle, "smtp");
                    if (svc) cvector_add(svc->init_hooks, hook);
                    break;

                case RUMBLE_HOOK_POP3:
                    svc = comm_serviceHandleExtern((masterHandle *) handle, "pop3");
                    if (svc) cvector_add(svc->init_hooks, hook);
                    break;

                case RUMBLE_HOOK_IMAP:
                    svc = comm_serviceHandleExtern((masterHandle *) handle, "imap4");
                    if (svc) cvector_add(svc->init_hooks, hook);
                    break;

                default:
                    break;
            }
            break;

        case RUMBLE_HOOK_COMMAND:
            switch (flags & RUMBLE_HOOK_SVC_MASK) {
                case RUMBLE_HOOK_SMTP:
                    svc = comm_serviceHandleExtern((masterHandle *) handle, "smtp");
                    if (svc) cvector_add(svc->cue_hooks, hook);
                    break;

                case RUMBLE_HOOK_POP3:
                    svc = comm_serviceHandleExtern((masterHandle *) handle, "pop3");
                    if (svc) cvector_add(svc->cue_hooks, hook);
                    break;

                case RUMBLE_HOOK_IMAP:
                    svc = comm_serviceHandleExtern((masterHandle *) handle, "imap4");
                    if (svc) cvector_add(svc->cue_hooks, hook);
                    break;

                default:
                    break;
            }
            break;

        case RUMBLE_HOOK_CLOSE:
            switch (flags & RUMBLE_HOOK_SVC_MASK) {
                case RUMBLE_HOOK_SMTP:
                    svc = comm_serviceHandleExtern((masterHandle *) handle, "smtp");
                    if (svc) cvector_add(svc->exit_hooks, hook);
                    break;

                case RUMBLE_HOOK_POP3:
                    svc = comm_serviceHandleExtern((masterHandle *) handle, "pop3");
                    if (svc) cvector_add(svc->exit_hooks, hook);
                    break;

                case RUMBLE_HOOK_IMAP:
                    svc = comm_serviceHandleExtern((masterHandle *) handle, "imap4");
                    if (svc) cvector_add(svc->exit_hooks, hook);
                    break;

                default:
                    break;
            }
            break;

        case RUMBLE_HOOK_FEED:
            cvector_add(((masterHandle *) handle)->_core.feed_hooks, hook);
            break;

        case RUMBLE_HOOK_PARSER:
            cvector_add(((masterHandle *) handle)->_core.parser_hooks, hook);

        default:
            break;
    }
}

typedef ssize_t (*hookFunc) (sessionHandle *, const char *cmd);

ssize_t rumble_server_execute_hooks(sessionHandle *session, cvector *hooks, uint32_t flags) {
    ssize_t     rc = RUMBLE_RETURN_OKAY;
    hookFunc    mFunc = NULL;
    hookHandle  *hook;
    c_iterator  iter;

    if (!hooks) return (RUMBLE_RETURN_IGNORE);

    HOOKLOG("Running hooks of type %#x", flags);

    cforeach((hookHandle *), hook, hooks, iter) {
        if (!hook) continue;
        if (hook->flags == flags) {
            if (hook->flags & RUMBLE_HOOK_FEED) {
                // ignore wrong feeds
                mqueue * item = (mqueue*)session;
                if (!item->account->arg || strcmp(hook->module, item->account->arg)) {
                    continue;
                }
            }

            mFunc = hook->func;
            HOOKLOG("Executing hook %p from %s\n", (void *) mFunc, hook->module);
            if (mFunc) rc = (mFunc) (session, 0);

#ifdef RUMBLE_LUA
            else if (hook->lua_callback) {
                lua_State   *L = rumble_acquire_state();
                HOOKLOG("Running Lua hook %d", hook->lua_callback);
                rc = lua_callback(L, (void *) hook, session);
                rumble_release_state(L);
            }
#endif

            if (rc == RUMBLE_RETURN_FAILURE) {
                HOOKLOG("Hook %p claimed failure, aborting connection!", (void *) mFunc);
                HOOKLOG("module %s aborted the session with %s!", hook->module, session->client->addr);
                return (RUMBLE_RETURN_FAILURE);
            }

            if (rc == RUMBLE_RETURN_IGNORE) {
                HOOKLOG("Hook %p took over, skipping to next command.", (void *) mFunc);
                HOOKLOG("module %s denied a request from %s", hook->module, session->client->addr);
                return (RUMBLE_RETURN_IGNORE);
            }
        }
    }

    return (rc);
}

ssize_t rumble_server_schedule_hooks(masterHandle *handle, sessionHandle *session, uint32_t flags) {
    rumbleService * svc;
    switch (flags & RUMBLE_HOOK_STATE_MASK) {
    case RUMBLE_HOOK_ACCEPT:
        switch (flags & RUMBLE_HOOK_SVC_MASK) {
            case RUMBLE_HOOK_SMTP:
                svc = comm_serviceHandleExtern(handle, "smtp");
                return (rumble_server_execute_hooks(session, svc->init_hooks, flags));

            case RUMBLE_HOOK_POP3:
                svc = comm_serviceHandleExtern(handle, "pop3");
                return (rumble_server_execute_hooks(session, svc->init_hooks, flags));

            case RUMBLE_HOOK_IMAP:
                svc = comm_serviceHandleExtern(handle, "imap4");
                return (rumble_server_execute_hooks(session, svc->init_hooks, flags));

            default:
                break;
        }
        break;

    case RUMBLE_HOOK_COMMAND:
        switch (flags & RUMBLE_HOOK_SVC_MASK) {
            case RUMBLE_HOOK_SMTP:  svc = comm_serviceHandle("smtp"); return (rumble_server_execute_hooks(session, svc->cue_hooks, flags));
            case RUMBLE_HOOK_POP3:  svc = comm_serviceHandle("pop3"); return (rumble_server_execute_hooks(session, svc->cue_hooks, flags));
            case RUMBLE_HOOK_IMAP:  svc = comm_serviceHandle("imap4"); return (rumble_server_execute_hooks(session, svc->cue_hooks, flags));
            default:                break;
        }
        break;

    case RUMBLE_HOOK_CLOSE:
        switch (flags & RUMBLE_HOOK_SVC_MASK) {
            case RUMBLE_HOOK_SMTP:
                svc = comm_serviceHandle("smtp");
                return (rumble_server_execute_hooks(session, svc->exit_hooks, flags));

            case RUMBLE_HOOK_POP3:
                svc = comm_serviceHandle("pop3");
                return (rumble_server_execute_hooks(session, svc->exit_hooks, flags));

            case RUMBLE_HOOK_IMAP:
                svc = comm_serviceHandle("imap4");
                return (rumble_server_execute_hooks(session, svc->exit_hooks, flags));

            default:
                break;
        }
        break;

    case RUMBLE_HOOK_FEED:
        return (rumble_server_execute_hooks(session, handle->_core.feed_hooks, flags));
        break;

    case RUMBLE_HOOK_PARSER:
        return (rumble_server_execute_hooks(session, handle->_core.parser_hooks, flags));
        break;

    default:
        break;
    }

    return (RUMBLE_RETURN_OKAY);
}


ssize_t rumble_service_execute_hooks(cvector *hooks, sessionHandle *session, uint32_t flags, const char *line) {
    ssize_t     rc = RUMBLE_RETURN_OKAY;
    hookFunc    mFunc = NULL;
    hookHandle  *hook;
    c_iterator  iter;

    HOOKLOG("Running hooks of type %#x", flags);

    cforeach((hookHandle *), hook, hooks, iter) {
        if (!hook) continue;
        if (hook->flags == flags) {
            if (hook->flags & RUMBLE_HOOK_FEED) {
                // ignore wrong feeds
                mqueue  *item = (mqueue *) session;
                if (!item->account->arg || strcmp(hook->module, item->account->arg)) {
                    continue;
                }
            }

            mFunc = hook->func;
            if (mFunc)
                rc = (mFunc) (session, line);
#ifdef RUMBLE_LUA
            else if (hook->lua_callback) {
                lua_State   *L = rumble_acquire_state();
                rc = lua_callback(L, (void *) hook, session);
                rumble_release_state(L);
            }
#endif
            if (rc == RUMBLE_RETURN_FAILURE) {
                HOOKLOG("module %s returned failure on \"%s\"", hook->module, line ? line : "(null)");
                return (RUMBLE_RETURN_FAILURE);
            }

            if (rc == RUMBLE_RETURN_IGNORE) {
                HOOKLOG("module %s returned ignore on \"%s\"", hook->module, line ? line : "(null)");
                return (RUMBLE_RETURN_IGNORE);
            }
        }
    }

    return (rc);
}


ssize_t rumble_service_schedule_hooks(rumbleService *svc, sessionHandle *session, uint32_t flags, const char *line) {
    cvector *hook = 0;
    switch (flags & RUMBLE_HOOK_STATE_MASK) {
        case RUMBLE_HOOK_ACCEPT:    hook = svc->init_hooks; break;
        case RUMBLE_HOOK_COMMAND:   hook = svc->cue_hooks; break;
        case RUMBLE_HOOK_CLOSE:     hook = svc->exit_hooks; break;
        case RUMBLE_HOOK_FEED:      hook = svc->master->_core.feed_hooks; break;
        case RUMBLE_HOOK_PARSER:    hook = svc->master->_core.parser_hooks; break;
        default:                    break;
    }
    return (rumble_service_execute_hooks(hook, session, flags, line));
}


void rumble_service_add_command(rumbleService *svc, const char *command, svcCommand func) {
    svcCommandHook  *hook = (svcCommandHook *) malloc(sizeof(svcCommandHook));
    hook->cmd = command;
    hook->func = func;
    cvector_add(svc->commands, hook);
}

void rumble_service_add_capability(rumbleService *svc, const char *capa) {
    // char *cpy = (char *) calloc(1, strlen(capa) + 1);
    char    *cpy = strclone(capa);
    //strncpy(cpy, capa, strlen(capa));
    cvector_add(svc->capabilities, cpy);
}
