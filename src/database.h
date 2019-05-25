/* File: database.h Author: Administrator Created on January 2, 2011, 5:59 PM */
#ifndef DATABASE_H
#define DATABASE_H
#include "rumble.h"
void    rumble_pop3_populate(sessionHandle *session, accountSession *pops);
void    rumble_database_update_domains(void);
#endif /* DATABASE_H */
