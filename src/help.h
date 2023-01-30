/* copyright (c) 2023, William Tang <galaxyking0419@gmail.com> */

#ifndef TROJAN_NGINX_HELP_H
#define TROJAN_NGINX_HELP_H

#define VERSION "1.0.0"
#define SHOW_USAGE() \
    printf( \
        "Usage: trojan [OPTION]...\n"  \
        "Run the trojan server, version %s\n"  \
        "\n" \
        "-p [string]  Set the password for server (Required)\n" \
        "-f [path]    Set the fallback server listened on a unix domain socket by NGINX (Required)\n" \
        "-h           Display this help and exit\n" \
        "\n" \
        "Report any bugs to <https://github.com/ttc0419/trojan>\n", \
        VERSION \
   )

#endif //TROJAN_NGINX_HELP_H
