#include <stdlib.h>
#include <libconfig.h>
//#include <stropts.h>
#include <unistd.h>
#include <asm-generic/sockios.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "config.h"
#include "configuration.h"
#include "contchan.h"
#include "debug.h"
#include "gps_handler.h"
#include "interface.h"
#include "netlink.h"
#include "ping.h"
#include "rootchan.h"
#include "rwlock.h"
#include "sockets.h"
#include "select_interface.h"
#include "timing.h"
#include "tunnel.h"

static int send_ping(struct interface* ife);
static void* ping_thread_func(void* arg);
static int send_second_response(struct interface *ife, 
        const char *buffer, int len, struct interface *dst_ife);
static void mark_inactive_interfaces();

static int          running = 0;
static pthread_t    ping_thread;

int start_ping_thread()
{
    if(running) {
        DEBUG_MSG("Ping thread already running");
        return 0;
    }

    pthread_attr_t attr;

    // Initialize and set thread detached attribute
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int result = pthread_create(&ping_thread, &attr, ping_thread_func, 0);
    if(result != 0) {
        ERROR_MSG("Creating thread failed");
        return FAILURE;
    }

    running = 1;

    pthread_attr_destroy(&attr);
    return 0;
}

/*
 * PING ALL INTERFACES
 *
 * Locking: Assumes the calling thread does not have a lock on the interface list.
 */
int ping_all_interfaces()
{
    int pings_sent = 0;

    struct sockaddr_storage dest_addr;
    unsigned dest_len;
    dest_len = build_data_sockaddr(get_controller_ife(), &dest_addr);
    if(dest_len < 0) {
        return FAILURE;
    }

    //We need a read lock on the interface list to prevent anyone from adding
    //or removing interfaces while we iterate over the list.
    obtain_read_lock(&interface_list_lock);

    struct interface* curr_ife = interface_list;
    while(curr_ife) {
        send_ping(curr_ife);

        assert(curr_ife != curr_ife->next);
        curr_ife = curr_ife->next;
    }

    release_read_lock(&interface_list_lock);
    return pings_sent;
}

/*
 * PING INTERFACE
 *
 * This is a more convenient method for initiating a connectivity test
 * from outside this module -- eg. to be used by the netlink module when
 * a link comes up.
 *
 * Locking: Assumes the calling thread has a read lock on the interface list.
 */
int ping_interface(struct interface* ife)
{
    struct sockaddr_storage dest_addr;
    unsigned dest_len;
    dest_len = build_data_sockaddr(get_controller_ife(), &dest_addr);
    if(dest_len < 0) {
        DEBUG_MSG("build_sockaddr failed");
        return FAILURE;
    }

    if(send_ping(ife) == FAILURE) {
        DEBUG_MSG("send_ping failed");
        return FAILURE;
    }

    return 0;
}   

/*
 * SEND PING
 *
 * Locking: Assumes the calling thread has a read lock on the interface list.
 */
static int send_ping(struct interface* ife)
{
    char *buffer = malloc(MAX_PING_PACKET_SIZE);
    if(!buffer) {
        DEBUG_MSG("out of memory");
        return FAILURE;
    }

    memset(buffer, 0, MAX_PING_PACKET_SIZE);
    unsigned send_size = MIN_PING_PACKET_SIZE;

    struct ping_packet *pkt = (struct ping_packet *)(buffer);
    pkt->seq_no = htonl(ife->next_ping_seq_no++);
    pkt->link_state = ife->state;
    pkt->src_id = htons(get_unique_id());
    pkt->link_id = htonl(ife->index);

    struct gps_payload *gps = (struct gps_payload *)
        ((char *)pkt + sizeof(struct ping_packet));
    gps->next = PING_NO_PAYLOAD;

    // Attempt to stuff GPS data into the packet
    if(fill_gps_payload(gps) < 0) {
        pkt->type = PING_REQUEST;
        send_size = MIN_PING_PACKET_SIZE;
    } else {
        pkt->type = PING_REQUEST | PING_GPS_PAYLOAD;
        send_size = MIN_PING_PACKET_SIZE + sizeof(struct gps_payload);
    }
   
    // Store a timestamp in the packet for calculating RTT.
    pkt->sender_ts = htonl(timeval_to_usec(0));
    pkt->receiver_ts = 0;

    fill_ping_digest(pkt, buffer, send_size, private_key);

    if(sendPacket(TUNFLAG_PING, buffer, send_size, get_unique_id(), ife, get_controller_ife())) {
        /* We get an error ENETUNREACH if we try pinging out an interface which
         * does not have an IP address.  That case is not interesting, so we
         * suppress the error message. */
        if(errno != ENETUNREACH)
            ERROR_MSG("sending ping packet on %s failed", ife->name);
        free(buffer);
        return -1;
    }

    // This last_ping_time timestamp will be compared to the timestamp in the ping
    // response packet to make sure the response is for the most recent
    // request.
    //ife->last_ping_time = now.tv_sec;
    ife->last_ping_time = time(NULL);
    ife->pings_outstanding++;

    ife->next_ping_time = ife->last_ping_time + ife->ping_interval;
    ife->next_ping_timeout = ife->last_ping_time + ife->ping_timeout;

    free(buffer);
    return 0;
}

static int should_send_ping(const struct interface *ife)
{
    if(ife->state == DEAD)
        return 0;

    if(time(NULL) >= ife->next_ping_time)
        return 1;

    return 0;
}

void* ping_thread_func(void* arg)
{   
	const unsigned int ping_interval = get_ping_interval();

	// Initialize this so that the first ping will be sent immediately.
	struct timeval last_ping_time = {
		.tv_sec = time(0) - ping_interval, .tv_usec = 0};

	int num_ifaces = 0;
	int curr_iface_pos = 0;

	unsigned ping_spacing = ping_interval * USEC_PER_SEC;
	unsigned next_timeout;

	struct timeval now;

	while(1) {
		obtain_read_lock(&interface_list_lock);
		num_ifaces = count_all_interfaces(interface_list);
	    release_read_lock(&interface_list_lock);

		if(curr_iface_pos >= num_ifaces) {
			curr_iface_pos = 0;
		}

        if(num_ifaces > 0)
			ping_spacing = ping_interval * USEC_PER_SEC / num_ifaces;
		else
			ping_spacing = ping_interval * USEC_PER_SEC;


		gettimeofday(&now, 0);

		long time_diff = timeval_diff(&now, &last_ping_time);
		if(time_diff >= ping_spacing) {
			mark_inactive_interfaces();

			obtain_read_lock(&interface_list_lock);
			struct interface *ife = find_interface_at_pos(
				interface_list, curr_iface_pos);
            if(ife && should_send_ping(ife)) {
                ping_interface(ife);
            }
			release_read_lock(&interface_list_lock);

			memcpy(&last_ping_time, &now, sizeof(last_ping_time));
			next_timeout = ping_spacing;

			curr_iface_pos++;
		} else {
			// Set the timeout on select such that it will return in time for
			// the next ping.
			next_timeout = ping_spacing - time_diff;
		}
        //TODO: This is implicitly defined because I can't use -D_BSD_SOURCE for that linux/if vs net/if issue
        usleep(next_timeout);
	}

	running = 0;
	return 0;
}

/*
 * HANDLE INCOMING
 *
 * Locking: Assumes the calling thread does not have a lock on the interface list.
 */
int handle_incoming_ping(struct sockaddr_storage *from_addr, struct timeval recv_time, struct interface *local_ife, struct interface *remote_ife, char *buffer, int size)
{
    if(size < MIN_PING_PACKET_SIZE) {
        DEBUG_MSG("Incoming packet was too small (%d bytes)", size);
    }

    struct ping_packet *pkt = (struct ping_packet *)(buffer);

    int notif_needed = 0;

    // TODO: interface_list is supposed to be locked, but I do not want to wait
    // for a lock before sending the response packet

    /* Under normal circumstances, we will send a ping response back to the
     * controller so that it can measure RTT.  The response will be suppressed
     * if there is an error condition or a secret_word mismatch. */
    int send_response = 1;

    /*
     * If the controller does not recognize our id (this can happen if the
     * controller is restarted), then it responds with the error bit set.  We
     * can re-establish state with the controller by sending a notification.
     */
    if(pkt->type == PING_RESPONSE_ERROR) {
        DEBUG_MSG("Controller responded with an error, will send a notification");
        send_response = 0;
        notif_needed = 1;
    }

    if(iszero(pkt->digest, sizeof(pkt->digest))) {
        send_response = 0;
    } else if(verify_ping_sender(pkt, buffer, size, private_key) != 0) {
        DEBUG_MSG("SHA hash mismatch, ping packet discarded");
        return -1;
    }

    unsigned link_id = ntohl(pkt->link_id);

    struct interface* ife = find_interface_by_index(interface_list, link_id);
    if(!ife) {
        DEBUG_MSG("Ping response for unknown interface %u", link_id);
        return 0;
    }
    if(send_response) {
        if(send_second_response(ife, buffer, size, get_controller_ife()) < 0) {
            ERROR_MSG("send_second_response failed");
        }
    }

    uint32_t send_ts = ntohl(pkt->sender_ts);
    uint32_t recv_ts = timeval_to_usec(&recv_time);
    long diff = (long)recv_ts - (long)send_ts;

    // If the ping response is older than the ping interval we ignore it.
    if(diff < (get_ping_interval() * USEC_PER_SEC)) {
        ife->avg_rtt = ewma_update(ife->avg_rtt, (double)diff, RTT_EWMA_WEIGHT);
        if(ife->state == INIT_INACTIVE || ife->state == INACTIVE) {
            change_interface_state(ife, ACTIVE);
            notif_needed = 1;
        }

        char network[NETWORK_NAME_LENGTH];
        read_network_name(ife->name, network, sizeof(network));

        if(strncmp(network, ife->network, sizeof(network)) != 0) {
            // If we detect a different network name, send another notification.
            strncpy(ife->network, network, sizeof(ife->network));
            notif_needed = 1;
        }

        ife->last_ping_success = time(NULL);
        ife->last_ping_seq_no = ntohl(pkt->seq_no);

        ife->next_ping_timeout = ife->next_ping_time + ife->ping_timeout;

        /* Reset on a successful ping so that we do not accumulate spurious losses. */
        ife->pings_outstanding = 0;

        DEBUG_MSG("Ping on %s (%s) rtt %d avg_rtt %f", 
                ife->name, ife->network, diff, ife->avg_rtt);
    }

    if(notif_needed) {
        send_notification(1);
    }

    return 0;
}

/*
 * Send a response back to the controller.  This allows the controller
 * to measure RTT as well.
 *
 * Assumes the buffer is at least MIN_PING_PACKET_SIZE in length.
 */
static int send_second_response(struct interface *ife, 
        const char *buffer, int len, struct interface *dst_ife)
{
    assert(len >= MIN_PING_PACKET_SIZE);

    int send_size = MIN_PING_PACKET_SIZE + sizeof(struct passive_payload);
    char *response = malloc(send_size);
    if(!response) {
    	DEBUG_MSG("out of memory");
        return -1;
    }

    memcpy(response, buffer, MIN_PING_PACKET_SIZE);

    struct ping_packet *ping = (struct ping_packet *)(response);

    ping->type = PING_SECOND_RESPONSE | PING_PASSIVE_PAYLOAD;
    ping->src_id = htons(get_unique_id());
    ping->sender_ts = 0;

    struct passive_payload *passive = (struct passive_payload *)
        ((char *)ping + sizeof(struct ping_packet));

    if(fill_passive_payload(ife->name, passive) < 0) {
        send_size = MIN_PING_PACKET_SIZE;
    }
    
    fill_ping_digest(ping, response, send_size, private_key);
    int result = sendPacket(TUNFLAG_PING, response, send_size, get_unique_id(), ife, dst_ife);
    //int result = sendto(sockfd, response, send_size, 0, to, to_len);

    free(response);

    if(result < 0) {
        ERROR_MSG("sendto failed");
        return -1;
    }
    return 0;
}

static void mark_inactive_interfaces()
{
	int notif_needed = 0;

	const int MAX_PING_FAILURES = get_max_ping_failures();

	obtain_read_lock(&interface_list_lock);

	struct interface* curr_ife = interface_list;
	while (curr_ife) {
        if(curr_ife->state == ACTIVE) {
            if(curr_ife->pings_outstanding > MAX_PING_FAILURES) {
                /* This is a fail-safe condition.  If timeout <= interval, then
                 * we may never explicitly record a timeout because the next
                 * ping may be sent before we see a timeout; however, we will
                 * see the number of outstanding pings start to accumulate. */
                DEBUG_MSG("Max ping failures reached on %s (%d)",curr_ife->name, curr_ife->pings_outstanding);
                change_interface_state(curr_ife, INACTIVE);
                notif_needed = 1;
            }
        }
		assert(curr_ife != curr_ife->next);

		curr_ife = curr_ife->next;
	}

	release_read_lock(&interface_list_lock);

	if(notif_needed) {
		send_notification(1);
	}
}
