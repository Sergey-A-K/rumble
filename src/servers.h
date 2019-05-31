/* File: servers.h Author: Administrator Created on January 6, 2011, 3:39 PM */
#ifndef SERVERS_H
#define SERVERS_H
#include "rumble.h"

void    rumble_clean_session(sessionHandle *session);

// SMTP handlers
ssize_t rumble_server_smtp_mail(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_smtp_rcpt(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_smtp_helo(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_smtp_ehlo(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_smtp_data(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_smtp_rset(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_smtp_vrfy(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_smtp_noop(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_smtp_auth(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_smtp_tls(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);


//  IMAP4 handlers
ssize_t rumble_server_imap_login(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_noop(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_capability(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_authenticate(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_starttls(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_select(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_examine(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_create(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_delete(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_rename(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_subscribe(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_unsubscribe(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_list(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_lsub(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_status(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_append(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_check(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_close(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_expunge(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_search(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_fetch(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_store(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_copy(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_idle(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_test(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_imap_logout(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);


// POP3 handlers
ssize_t rumble_server_pop3_capa(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_pop3_user(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_pop3_pass(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_pop3_starttls(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_pop3_list(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_pop3_stat(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_pop3_dele(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_pop3_top(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_pop3_retr(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);
ssize_t rumble_server_pop3_uidl(masterHandle *master, sessionHandle *session, const char *parameters, const char *extra_data);


// Hook handlers
ssize_t rumble_server_execute_hooks(sessionHandle *session, cvector *hooks, uint32_t flags);
ssize_t rumble_server_schedule_hooks(masterHandle *handle, sessionHandle *session, uint32_t flags);
ssize_t rumble_service_schedule_hooks(rumbleService *svc, sessionHandle *session, uint32_t flags, const char *line);
void    *rumble_smtp_init(void *m);
void    *rumble_pop3_init(void *m);
void    *rumble_imap_init(void *m);
void    *rumble_worker_init(void *m);
void    rumble_prune_storage(const char *folder);
void    *rumble_sanitation_process(void *m);
void    *rumble_worker_process(void *m);

// void *rumble_worker_initZ(void *T);


#endif /* SERVERS_H */
