/* Based on http://man7.org/linux/man-pages/man3/getifaddrs.3.html and
 * https://www.linuxquestions.org/questions/linux-networking-3/howto-find-gateway-address-through-code-397078/ */
#if 0
#define _GNU_SOURCE     /* To get defns of NI_MAXSERV and NI_MAXHOST */
#endif
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h> /* definitions for NI_* */
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef __APPLE__
#include <linux/if_link.h> /* struct rtnl_link_stats */
#include <linux/rtnetlink.h> /* struct rtmsg, rtattr */
#endif

#include <net/if.h> /* definitions IFF_* */

/* Check http://opensource.apple.com/source/network_cmds/network_cmds-481.20.1/ifconfig.tproj/ifconfig.c */
#define	IFFBITS \
"\020\1UP\2BROADCAST\3DEBUG\4LOOPBACK\5POINTOPOINT\6SMART\7RUNNING" \
"\10NOARP\11PROMISC\12ALLMULTI\13OACTIVE\14SIMPLEX\15LINK0\16LINK1\17LINK2" \
"\20MULTICAST"

#define BUFSIZE 8192

struct route_info {
    struct in_addr dst_addr;
    struct in_addr src_addr;
    struct in_addr gw_addr;
    char if_name[IF_NAMESIZE];
};

/*
 * Print a value a la the %b format of the kernel's printf
 */
void
printb (const char *s,
        unsigned v,
        const char *bits)
{
    int i, any = 0;
    char c;

    if (bits && *bits == 8)
        printf ("%s=%o", s, v);
    else
        printf ("%s=0x%x", s, v);
    bits++;
    if (bits) {
        putchar ('<');
        while ((i = *bits++) != '\0') {
            if (v & (1 << (i-1))) {
                if (any)
                    putchar (',');
                any = 1;
                for (; (c = *bits) > 32; bits++)
                    putchar (c);
            } else
                for (; *bits > 32; bits++)
                    ;
        }
        putchar ('>');
    }
    putchar ('\n');
}

void
print_network_interfaces (struct ifaddrs ifa) {
    int family, s;
    char host[NI_MAXHOST];

    family = ifa.ifa_addr->sa_family;

    /* Display interface name and family (including symbolic
       form of the latter for the common families) */
    fprintf (stdout, "%-8s %s (%d)\n",
             ifa.ifa_name,
#ifndef __APPLE__
             (family == AF_PACKET) ? "AF_PACKET" :
#else
             (family == AF_LINK) ? "AF_LINK" :
#endif
             (family == AF_INET) ? "AF_INET" :
             (family == AF_INET6) ? "AF_INET6" : "???",
             family);

    printb ("\tflags", ifa.ifa_flags, IFFBITS);

    /* For an AF_INET* interface address, display the address */
    if (family == AF_INET || family == AF_INET6) {
        s = getnameinfo (ifa.ifa_addr,
                         (family == AF_INET) ? sizeof (struct sockaddr_in) :
                                               sizeof (struct sockaddr_in6),
                         host, NI_MAXHOST,
                         NULL, 0, NI_NUMERICHOST);
        if (s != 0) {
            fprintf (stderr, "*%s(): getnameinfo() failed: %s\n", __func__,
                     gai_strerror (s));
            return;
        }

        fprintf (stdout, "\t\taddress: <%s>\n", host);
    }
#ifndef __APPLE__
    else if (family == AF_PACKET && ifa.ifa_data != NULL) {
        struct rtnl_link_stats *stats = ifa.ifa_data;

        fprintf (stdout, "\t\ttx_packets = %10u; rx_packets = %10u\n"
                 "\t\ttx_bytes   = %10u; rx_bytes   = %10u\n",
                 stats->tx_packets, stats->rx_packets,
                 stats->tx_bytes, stats->rx_bytes);
    }
#endif
}

/** @brief Get a list of network interface names for a specific
 *         address family
 *
 * @param [out] ifa_names A list of network interface names.
 * @param [out] ifa_names_sz The size of the above list.
 * @param [in]  sa_family The address family to filter the interfaces.
 * @return 0 on success<br>
 *         -1 otherwise
 *
 * @note The loopback and not running interfaces are ignored.
 * @note The list of names returned is allocated dynamically and needs
 *       to be free()d when not needed anymore.
 */
int
get_interface_names_by_family (char ***ifa_names,
                               size_t *ifa_names_sz,
                               int sa_family)
{
    struct ifaddrs *ifaddr, *ifa;
    char **tmp;
    int ret = 0;
    *ifa_names_sz = 0;

    /* Get a linked list of network interfaces */
    if (getifaddrs (&ifaddr) == -1) {
        fprintf (stderr, "*%s(): error getting linked list of interfaces",
                 __func__);
        return -1;
    }

    /* Walk through the linked list and find the
     * interfaces that have the specific *family* and
     * get the name */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

        /* No loopback interfaces or not running */
        if (ifa->ifa_addr == NULL
            || ifa->ifa_flags & IFF_LOOPBACK
            || !(ifa->ifa_flags & IFF_RUNNING))
            continue;

        if (ifa->ifa_addr->sa_family == sa_family) {
            *ifa_names_sz += 1;
            tmp = realloc (*ifa_names, *ifa_names_sz * sizeof (char *));
            if (tmp)
                *ifa_names = tmp;
            else {
                fprintf (stderr, "*%s(): error realloc\n", __func__);
                if (*ifa_names)
                    free (*ifa_names);
                ret = -1;
                goto out;
            }
            (*ifa_names)[*ifa_names_sz - 1] = strdup (ifa->ifa_name);
        }
    }

out:
    freeifaddrs (ifaddr);
    return ret;
}


/** @brief Get the network address from a specific network
 *         interface name
 *
 * @param [out] address The address to get.
 * @param [in]  ifa_name The interface name to get the address.
 * @param [in]  sa_family The address family to filter the interfaces.
 *                        Currently only AF_INET and AF_INET6 are supported.
 * @return 0 on success<br>
 *         -1 otherwise
 *
 * @note The loopback and not running interfaces are ignored.
 * @note The address returned is allocated dynamically and needs
 *       to be free()d when not needed anymore.
 */
int
get_address_from_interface_name (char **address,
                                 const char *ifa_name,
                                 int sa_family)
{
    struct ifaddrs *ifaddr, *ifa;
    int ret = 0, s;
    char ifa_address[NI_MAXHOST];
    *address = NULL;

    if (sa_family != AF_INET && sa_family != AF_INET6) {
        fprintf (stderr, "*%s(): only AF_INET and AF_INET6 are supported\n",
                 __func__);
        return -1;
    }

    /* Get a linked list of network interfaces */
    if (getifaddrs (&ifaddr) == -1) {
        fprintf (stderr, "*%s(): error getting linked list of interfaces\n",
                 __func__);
        return -1;
    }

    /* Walk through the linked list and find the
     * interface with the specific name */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

        /* No loopback interfaces or not running */
        if (ifa->ifa_addr == NULL
            || ifa->ifa_flags & IFF_LOOPBACK
            || !(ifa->ifa_flags & IFF_RUNNING))
            continue;

        if (ifa->ifa_addr->sa_family == sa_family
            && !strcmp (ifa->ifa_name, ifa_name)) {

            s = getnameinfo (ifa->ifa_addr,
                             (sa_family == AF_INET)
                             ? sizeof (struct sockaddr_in)
                             : sizeof (struct sockaddr_in6),
                             ifa_address, NI_MAXHOST,
                             NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                fprintf (stderr, "*%s(): getnameinfo() failed: %s\n",
                         __func__, gai_strerror (s));
                goto out;
            }
            *address = strdup (ifa_address);
            break;
        }
    }

    if (!*address) {
        fprintf (stderr, "*%s(): interface %s not found.\n",
                 __func__, ifa_name);
        ret = -1;
    }

out:
    freeifaddrs (ifaddr);
    return ret;

}

static ssize_t
read_netlink_socket (int sock_fd, char *buffer, size_t buffer_sz,
                     uint32_t seq, uint32_t pid)
{
    struct nlmsghdr *nl_hdr;
    ssize_t read_len = 0, msg_len = 0;

    do {
        if ((size_t) msg_len > buffer_sz) {
            fprintf (stderr, "*%s(): no size in buffer\n", __func__);
            return -1;
        }

        /* Receive response from the kernel */
        read_len = recv (sock_fd, buffer, buffer_sz - (size_t) msg_len, 0);
        if (read_len < 0) {
            fprintf (stderr, "*%s(): error receiving message from socket.\n",
                     __func__);
            return -1;
        }

        /* Point the struct nlmsghdr to the buffer */
        nl_hdr = (struct nlmsghdr *) buffer;

        /* Check if the header is valid */
        if (!NLMSG_OK (nl_hdr, read_len)
            || (nl_hdr->nlmsg_type == NLMSG_ERROR)) {
            fprintf (stderr, "*%s(): error in received packet.\n", __func__);
            return -1;
        }

        /* Check if the its the last message */
        if (nl_hdr->nlmsg_type == NLMSG_DONE)
            break;
        else {
        /* Else move the pointer to buffer appropriately */
            buffer += read_len;
            msg_len += read_len;
        }

        /* Check if its a multi part message */
        if (!(nl_hdr->nlmsg_flags & NLM_F_MULTI))
        /* return if its not */
            break;

    } while ((nl_hdr->nlmsg_seq != seq)
             || (nl_hdr->nlmsg_pid != pid));

    return msg_len;
}

/* parse the route info returned */
static int
parse_routes (struct nlmsghdr *nl_hdr, struct route_info *rt_info)
{
    struct rtmsg *rt_msg;
    struct rtattr *rt_attr;
    size_t rt_len;

    rt_msg = (struct rtmsg *) NLMSG_DATA (nl_hdr);

    /* If the route is not for AF_INET or
     * does not belong to main routing table then return. */
    if ((rt_msg->rtm_family != AF_INET)
        || (rt_msg->rtm_table != RT_TABLE_MAIN))
        return -1;

    /* get the rtattr field */
    rt_attr = (struct rtattr *) RTM_RTA (rt_msg);
    rt_len = RTM_PAYLOAD (nl_hdr);

    for (; RTA_OK (rt_attr, rt_len); rt_attr = RTA_NEXT (rt_attr, rt_len)) {
        switch (rt_attr->rta_type) {
        case RTA_OIF:
            if_indextoname (*(unsigned int *) RTA_DATA (rt_attr),
                            rt_info->if_name);
            break;
        case RTA_GATEWAY:
            memcpy (&rt_info->gw_addr, RTA_DATA (rt_attr),
                    sizeof (rt_info->gw_addr));
            break;
        case RTA_PREFSRC:
            memcpy (&rt_info->src_addr, RTA_DATA (rt_attr),
                    sizeof (rt_info->src_addr));
            break;
        case RTA_DST:
            memcpy (&rt_info->dst_addr, RTA_DATA (rt_attr),
                    sizeof (rt_info->dst_addr));
            break;
        default:
            break;
        }
    }

    return 0;
}

/** @brief Get the default interface name
 *
 * @param [out] default_iface_name The name of the default interface
 * @return 0 on success<br>
 *         -1 otherwise
 *
 * @note The name returned is allocated dynamically and needs
 *       to be free()d when not needed anymore.
 */
int
get_default_interface_name (char **default_iface_name)
{
    struct nlmsghdr *nl_msg;
    struct route_info route_info;
    char msg_buffer[BUFSIZE];
    int sock;
    ssize_t len;
    uint32_t msg_seq = 0;

    /* Create socket */
    sock = socket (PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (sock < 0) {
        fprintf (stderr, "*%s(): error creating socket.\n", __func__);
        return -1;
    }

    /* Initialize the buffer */
    memset (msg_buffer, 0, sizeof (msg_buffer));

    /* Point the header and the msg structure pointers into the buffer */
    nl_msg = (struct nlmsghdr *) msg_buffer;

    /* Fill in the nlmsg header*/
    /* Length of the message */
    nl_msg->nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg));
    /* Get the routes from the kernel routing table */
    nl_msg->nlmsg_type = RTM_GETROUTE;
    /* The message is a request for dump */
    nl_msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    /* Sequence of the message packet */
    nl_msg->nlmsg_seq = msg_seq++;
    /* PID of the process sending the request */
    nl_msg->nlmsg_pid = (uint32_t) getpid ();

    /* Send the request */
    if (send (sock, nl_msg, nl_msg->nlmsg_len, 0) < 0) {
        fprintf (stderr, "*%s(): error sending the request.\n", __func__);
        return -1;
    }

    /* Read the response */
    len = read_netlink_socket (sock, msg_buffer, sizeof (msg_buffer),
                               msg_seq, nl_msg->nlmsg_pid);
    if (len < 0) {
        fprintf (stderr, "*%s(): error reading the response.\n", __func__);
        return -1;
    }
    close (sock);

    /* Parse and print the response */
    for (; NLMSG_OK (nl_msg, len); nl_msg = NLMSG_NEXT (nl_msg, len)) {
        memset (&route_info, 0, sizeof (route_info));
        if (parse_routes (nl_msg, &route_info) < 0)
            continue;

        /* Check if it's the default interface */
        if (strstr ((char *) inet_ntoa (route_info.dst_addr), "0.0.0.0")) {
            *default_iface_name = strdup (route_info.if_name);
            break;
        }
    }

    return 0;
}


int main (int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    char **names = NULL;
    int ret;
    size_t names_sz;
    ret = get_interface_names_by_family (&names, &names_sz, AF_INET);
    if (ret == -1) {
        fprintf (stderr, "*%s(): error getting network interfaces\n",
                 __func__);
        return -1;
    }
    for (size_t i = 0;i<names_sz;i++)
        printf ("%zu. Name: %s\n", i, names[i]);

    for (size_t i = 0;i<names_sz;i++)
        free (names[i]);
    free (names);

    fprintf (stdout, "* *** *\n");

    char *adr = NULL;
    const char *iface_name = "eth0";
    ret = get_address_from_interface_name (&adr, iface_name, AF_INET);
    if (ret == -1) {
        fprintf (stderr, "*%s(): error getting address from interface %s\n",
                 __func__, iface_name);
        return -1;
    }
    if (adr) {
        printf ("Address for iface %s is %s\n", "eth0", adr);
        free (adr);
    }

    fprintf (stdout, "* *** *\n");

    int n;
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs (&ifaddr) == -1) {
        fprintf (stderr, "*%s(): getifaddrs", __func__);
        return -1;
    }

    /* Walk through linked list, maintaining head pointer so we
       can free list later */
    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL)
            continue;

        print_network_interfaces (*ifa);
    }

    freeifaddrs (ifaddr);

    fprintf (stdout, "* *** *\n");

    char *if_name = NULL;

    if (get_default_interface_name (&if_name) == -1) {
        fprintf (stderr, "*%s(): error getting the default interface name.\n",
                 __func__);
        return -1;
    }

    if (if_name) {
        printf ("Default interface name: %s\n", if_name);
        free (if_name);
    }

    return 0;
}
