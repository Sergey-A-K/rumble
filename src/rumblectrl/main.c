/*
 * File:   main.cpp
 * Author: vaps
 * Created on 4. januar 2012, 17:30
 *
 * Modifyed on 8 may 2019, Sergey. K
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#include "../radb.c"
#include "../crypt.c"

#define A_ADD   1
#define A_DEL   2
#define A_LIST  3
#define A_LISTU 4
#define A_USER  5
#define A_UADD  6
#define A_UDEL  7
#define A_UEDIT 8

const char * dbpath = "db/rumble.sqlite";

char *domain = 0, email = 0, password = 0, uName[512], uDomain[256], uPass[256], uType[256], uArgs[256], uPath[512];
int needHelp = 0;
/*
 *
 */
int main(int argc, char** argv) {
	int i;
	int action = 0;
	radbMaster *db;
	radbObject *dbo;
	radbResult* result;
	if (argc <= 1) needHelp = 1;
	memset(uName, 0, 512);
	memset(uDomain, 0, 256);
	memset(uPass, 0, 256);
	memset(uType, 0, 256);
	memset(uArgs, 0, 256);
	memset(uPath, 0, 512);

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--help")) needHelp = 1;
		if (!strcmp(argv[i], "-h")) needHelp = 1;
		if (!strcmp(argv[i], "--add")) action = A_ADD;
		if (!strcmp(argv[i], "--delete")) action = A_DEL;
		if (!strcmp(argv[i], "--list")) action = A_LIST;
		if (!strcmp(argv[i], "--listusers")) action = A_LISTU;
		if (!strcmp(argv[i], "--userinfo")) action = A_USER;
		if (!strcmp(argv[i], "--adduser")) action = A_UADD;
		if (!strcmp(argv[i], "--deleteuser")) action = A_UDEL;
		if (!strcmp(argv[i], "--edituser")) action = A_UEDIT;
		if (strstr(argv[i], "--email=")) sscanf(argv[i], "--email=%250[^@ ]@%250c", uName, uDomain);
		if (strstr(argv[i], "--domain=")) sscanf(argv[i], "--domain=%250c", uDomain);
		if (strstr(argv[i], "--pass=")) sscanf(argv[i], "--pass=%250c", uPass);
		if (strstr(argv[i], "--type=")) sscanf(argv[i], "--type=%250c", uType);
		if (strstr(argv[i], "--args=")) sscanf(argv[i], "--args=%250c", uArgs);
		if (strstr(argv[i], "--path=")) sscanf(argv[i], "--path=%250c", uPath);
	}

	if (!needHelp) {

		db = radb_init_sqlite(dbpath);
		if (!db) { printf("ERROR: Can't open database <%s>", dbpath); exit(EXIT_FAILURE); }

		switch(action) {
			case A_ADD:
				if (!strlen(uDomain)) { printf("Error: Invalid domain name specified!\n"); needHelp = 1; break;}
				else {
						dbo = radb_prepare(db, "SELECT `id` FROM `domains` WHERE domain = %s LIMIT 1", uDomain);
						if (radb_fetch_row(dbo)) {
						printf("Error: Domain %s already exists\n", uDomain);
						exit(EXIT_FAILURE);
						}
					radb_run_inject(db, "INSERT INTO `domains` (id, domain, storagepath, flags) VALUES (NULL, %s, %s, 0)", uDomain, uPath);
					if (strlen(uPath)) {
                        mkdir(uPath, S_IRWXU | S_IRGRP | S_IWGRP);
					}
				}

				break;
			case A_DEL:
				if (!strlen(uDomain)) { printf("Invalid domain name specified!\n"); needHelp = 1; break; }
				radb_run_inject(db, "DELETE FROM `domains` WHERE domain = %s", uDomain);
				break;
			case A_LIST:
				dbo = radb_prepare(db, "SELECT `id`, `domain` FROM `domains` WHERE 1");
				while ((result = radb_fetch_row(dbo))) {
					printf("%02u: %s\n", result->column[0].data.int32, result->column[1].data.string);
				}
				break;
			case A_LISTU:
				if (!strlen(uDomain)) { printf("Error: Invalid domain name specified!\n"); needHelp = 1; break; }
				dbo = radb_prepare(db, "SELECT `id`, `user`, `type` FROM `accounts` WHERE domain = %s", uDomain);
				while ((result = radb_fetch_row(dbo))) {
					sprintf(uName, "%s@%s",result->column[1].data.string, uDomain);
					printf("%02u: %-32s  %s\n", result->column[0].data.int32, uName, result->column[2].data.string);
				}
				break;
			case A_USER:
				if (!strlen(uDomain)) { printf("Error: Invalid domain name specified!\n"); needHelp = 1; break; }
				if (!strlen(uName)) { printf("Error: Invalid user name specified!\n"); needHelp = 1; break;}
				dbo = radb_prepare(db, "SELECT `id`, `user`, `type` FROM `accounts` WHERE domain = %s AND user = %s", uDomain, uName);
				result = radb_fetch_row(dbo);
				if (result) {
					printf("%02u: %s@%s  %s\n", result->column[0].data.int32, uName, uDomain, result->column[2].data.string);
					exit(EXIT_SUCCESS);
				}
				else {
					printf("Error: No such user, %s@%s\n", uName, uDomain);
					exit(EXIT_FAILURE);
				}
				break;
			case A_UADD:
				if (!strlen(uDomain)) { printf("Error: Invalid domain name specified!\n"); needHelp = 1; break;}
				if (!strlen(uName)) { printf("Error: Invalid user name specified!\n"); needHelp = 1; break;}
				if (!strlen(uPass)) { printf("Error: Invalid password or type specified!\n"); needHelp = 1; break;}
				dbo = radb_prepare(db, "SELECT `id` FROM `domains` WHERE domain = %s LIMIT 1", uDomain);
				if (!radb_fetch_row(dbo)) { printf("Error: Invalid domain name specified!\n"); needHelp = 1; break; }
				if (!strlen(uType)) sprintf(uType, "mbox");
				radb_run_inject(db, "INSERT INTO `accounts` (domain, user, password, type, arg) VALUES (%s,%s,%s,%s, %s)", uDomain, uName, rumble_sha256((const char *)uPass), uType, uArgs);
				break;
			case A_UEDIT:
				if (!strlen(uDomain)) { printf("Error: Invalid domain name specified!\n"); needHelp = 1; break;}
				if (!strlen(uName)) { printf("Error: Invalid user name specified!\n"); needHelp = 1; break;}
				if (!strlen(uPass)) { printf("Error: Invalid password or type specified!\n"); needHelp = 1; break;}
				dbo = radb_prepare(db, "SELECT `id` FROM `domains` WHERE domain = %s LIMIT 1", uDomain);
				if (!radb_fetch_row(dbo)) { printf("Error: Invalid domain name specified!\n"); needHelp = 1; break; }
				if (!strlen(uType)) sprintf(uType, "mbox");
				radb_run_inject(db, "UPDATE `accounts` SET password = %s, type = %s, arg = %s WHERE domain = %s AND user = %s", rumble_sha256((const char *)uPass), uType, uArgs, uDomain, uName);
				break;
			case A_UDEL:
				if (!strlen(uDomain)) { printf("Error: Invalid domain name specified!\n"); needHelp = 1; }
				if (!strlen(uName)) { printf("Error: Invalid user name specified!\n"); needHelp = 1; }
				radb_run_inject(db, "DELETE FROM `accounts` WHERE domain = %s AND user = %s", uDomain, uName);
				break;
			default:
				needHelp = 1;
				break;
		}
		if (!needHelp) { printf("Done!\n"); exit(EXIT_SUCCESS); }

	}



	if (needHelp) {
		printf("\
Usage: rumblectrl [action [parameters]]\n\
Available actions:\n\
 Domain actions:\n\
  --add --domain=<domain> --path=<path>	   : Adds <domain> to the server\n\
  --delete --domain=<domain>				  : Deletes <domain> from the server\n\
  --list									  : Lists available domains\n\
 Account actions:\n\
  --listusers --domain=<domain>			   : Lists users on this <domain>\n\
  --userinfo --email=<email>				  : Displays user information\n\
  --adduser --email=<email> --pass=<password> [--type=<type>] [--args=<args>]\n\
											  : Creates a new user account\n\
  --edituser --email=<email> --pass=<password> [--type=<type>] [--args=<args>]\n\
											  : Updates user account\n\
  --deleteuser --email=<email]				: Deletes a user account\n\
  \n\
Example: rumblectrl --adduser --email=some@thing.org --pass=Hello!\n\
");
		exit(EXIT_FAILURE);
	}


	radb_close(db);
	return 0;
}

