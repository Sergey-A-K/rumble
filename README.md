![Rumble — The mail server](https://raw.githubusercontent.com/Sergey-A-K/rumble/master/src/modules/rumblelua/rumble_icon.png)

----

## Overview

Rumble is a mail server for SMTP, POP3 and IMAP4 with an extensive C and Lua API for scripting.
It comes with support for TLS, SQLite and has a web-based administration.
Additional includes modules feature greylisting, DNS blacklisting, SpamAssassin support and dynamic performance scaling.
Rumble works with both IPv4 and IPv6.

The following service extensions:

* **SMTP**

    EXPN
    PIPELINING
    8BITMIME
    AUTH (LOGIN, PLAIN)
    DELIVERBY
    DSN
    SIZE
    XVERP
    STARTTLS
    BATV

* **POP3**

    PIPELINING
    UIDL
    STARTTLS

* **IMAP4**

    UIDPLUS
    LEMONADE compliance (CONDSTORE, IDLE)
    STARTTLS


## Troubleshooting

* Windows support removed. Only POSIX compatible platform works.
* MySQL support has been removed from radb.

## Contributing and Credits

Rumble was originally created by [Daniel Gruno](https://github.com/Humbedooh), and is currently not maintained by.


## Running

To run Rumble, simply copy the compiled binary and its files to an appropriate folder and run

```bash
/path/to/rumble
```
To run the mail server as a daemon process (recommended), run

```bash
/path/to/rumble --service
```

### Build dependencies

If you've downloaded the source code, you can compile the program by running the following command:

```bash
bash ./compile.sh
```

Compiling the source requires the following libraries and headers to be installed:

* **libgnutls-devel** Development package for the GnuTLS C API.
* **libgcrypt-devel** Development package for the GNU Crypto Library.
* **sqlite3-devel** SQLite is a C library that implements an embeddable SQL database engine. Development package.
* **lua51-devel** This package contains files needed for embedding lua into your application.

## More information

[Original repository](https://github.com/Humbedooh/rumble)


Work on this project is for learning. I do not recommend to use it.
