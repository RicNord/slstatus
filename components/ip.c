/* See LICENSE file for copyright and license details. */
#include <errno.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#if defined(__OpenBSD__)
	#include <sys/socket.h>
	#include <sys/types.h>
#elif defined(__FreeBSD__)
	#include <netinet/in.h>
	#include <sys/socket.h>
#endif

#include "../slstatus.h"
#include "../util.h"

struct ipalias {
  char ip[16];
  char alias[14];
};

static int
get_aliases(struct ipalias *p_ipalias[]) {
  char ip_alias[41];
  char *homedir = strcat(getenv("HOME"), "/");
  char *alias_file_name = ".ip_alias";
  char *ip_alias_path =
      (char *)malloc(strlen(homedir) + strlen(alias_file_name) + 1);
  strcpy(ip_alias_path, strcat(homedir, alias_file_name));
  char *config_delimiter = ":";
  FILE *fip;

  if ((fip = fopen(ip_alias_path, "r"))) {
    int i = 0;
    while (fgets(ip_alias, sizeof(ip_alias), fip)) {
      char *ip = strtok(ip_alias, config_delimiter);
      char *alias = strtok(NULL, config_delimiter);
      alias[strcspn(alias, "\n")] = 0;
      p_ipalias[i] = (struct ipalias *)malloc(sizeof(struct ipalias));
      strcpy(p_ipalias[i]->ip, ip);
      strcpy(p_ipalias[i]->alias, alias);
      i++;
    }
    free(ip_alias_path);
    fclose(fip);
    return i > 0 ? i: 0;
  } else {
    free(ip_alias_path);
    return 0;
  }
}

static char *
str_replace(char *orig, char *rep, char *with) {
/* credit to 
 * https://stackoverflow.com/questions/779875/what-function-is-to-replace-a-substring-from-a-string-in-c 
*/
    char *result; // the return string
    char *ins;    // the next insert point
    char *tmp;    // varies
    int len_rep;  // length of rep (the string to remove)
    int len_with; // length of with (the string to replace rep with)
    int len_front; // distance between rep and end of last rep
    int count;    // number of replacements

    // sanity checks and initialization
    if (!orig || !rep)
        return orig;
    len_rep = strlen(rep);
    if (len_rep == 0)
        return orig; // empty rep causes infinite loop during count
    if (!with)
        with = "";
    len_with = strlen(with);

    // count the number of replacements needed
    ins = orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
        return orig;

    // first time through the loop, all the variable are set correctly
    // from here on,
    //    tmp points to the end of the result string
    //    ins points to the next occurrence of rep in orig
    //    orig points to the remainder of orig after "end of rep"
    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep; // move to next "end of rep"
    }
    strcpy(tmp, orig);
    return result;
}

static const char *
ip(const char *interface, unsigned short sa_family)
{
	struct ifaddrs *ifaddr, *ifa;
	int s;
	char host[NI_MAXHOST];

	if (getifaddrs(&ifaddr) < 0) {
		warn("getifaddrs:");
		return NULL;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr) {
			continue;
		}
		s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6),
		                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if (!strcmp(ifa->ifa_name, interface) &&
		    (ifa->ifa_addr->sa_family == sa_family)) {
			freeifaddrs(ifaddr);
			if (s != 0) {
				warn("getnameinfo: %s", gai_strerror(s));
				return NULL;
			}
			return bprintf("%s", host);
		}
	}

	freeifaddrs(ifaddr);

	return NULL;
}

const char *
ipv4(const char *interface)
{
	return ip(interface, AF_INET);
}

const char *
ipv6(const char *interface)
{
	return ip(interface, AF_INET6);
}

const char *
leaked_ip(void)
{
	static const char *check_domain = "ip-api.com";
	static const char *check_request =
		"GET /line/?fields=query,country HTTP/1.1\r\n"
		"Host: ip-api.com\r\n\r\n";
	static const char *bad_addr = "X.X.X.X(Unavailable)";
	
	struct addrinfo *ai;
	int remote_fd;
	char *p;
	int s, n;
	int gai_errno;

	if ((gai_errno = getaddrinfo(check_domain, "http", NULL, &ai)))
	{
		warn("Can't resolve domain %s: %s", check_domain, gai_strerror(gai_errno));
		return bad_addr;
	}
	if ((remote_fd = socket(ai->ai_family, ai->ai_socktype, 0)) == -1)
	{
		freeaddrinfo(ai);
		warn("socket:");
		return bad_addr;
	}
	
	if (connect(remote_fd, ai->ai_addr, ai->ai_addrlen) == -1)
	{
		freeaddrinfo(ai);
		close(remote_fd);
		warn("connect:", check_domain);
		return bad_addr;
	}
	freeaddrinfo(ai);

	// send request
	n = strlen(check_request);
	p = (char *) check_request;
	while (n)
	{
		s = write(remote_fd, p, n);

		if (s == -1)
		{
			if (errno == EINTR)
				continue;
			close(remote_fd);
			warn("write:");
			return bad_addr;
		}
		n -= s;
		p += s;
	}
	
	p = buf;
	n = sizeof(buf);
	s = read(remote_fd, p, n);
	close(remote_fd);
	p = strstr(buf, "\r\n\r\n");
	if (!p)
	{
		warn("Can't resolve %s: Bad response from server", check_domain);
		return bad_addr;
	}
	p += 4;
	sscanf(p, "%*s%s", buf);
	strcat(buf, "(");
	sscanf(p, "%s", buf+strlen(buf));
	strcat(buf, ")");

    /* Add string replacement of known ip:s to aliases */
    static struct ipalias *p_ipalias[10];
    static int ALIASES_LOADED;
    static int ALIASES_ATTEMPTED;
    if (!ALIASES_LOADED && !ALIASES_ATTEMPTED) {
        ALIASES_LOADED = get_aliases(p_ipalias);
        ALIASES_ATTEMPTED = 1;
    } else {
        ALIASES_ATTEMPTED = 1;
    }
    int i;
    if (ALIASES_LOADED) {
        for (i =0 ; i < ALIASES_LOADED; i++) {
            char tmp_ip[16];
            char tmp_alias[14];
            strcpy(tmp_ip,p_ipalias[i]->ip);
            strcpy(tmp_alias,p_ipalias[i]->alias);
            strcpy(buf,str_replace(buf,tmp_ip , tmp_alias));
        }
    }

	return buf;
}
