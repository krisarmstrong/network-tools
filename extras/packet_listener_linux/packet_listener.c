#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>

const uint8_t TARGET_MAC_PREFIX[] = {0x00, 0xc0, 0x17};
#define TARGET_MAC_PREFIX_LEN 3
const char PAYLOAD[] = "DATA:)T";
#define PAYLOAD_LEN (sizeof(PAYLOAD) - 1)

typedef struct {
    size_t packet_size;
    size_t count;
    size_t bytes;
} packet_stats_t;

packet_stats_t stats[10];
size_t total_count = 0;
size_t total_bytes = 0;
time_t start_time;

void update_stats(size_t size) {
    int i;
    for (i = 0; i < 10; i++) {
        if (stats[i].packet_size == size || stats[i].packet_size == 0) {
            stats[i].packet_size = size;
            stats[i].count++;
            stats[i].bytes += size;
            total_count++;
            total_bytes += size;
            break;
        }
    }
}

void print_stats() {
    time_t now = time(NULL);
    double elapsed = difftime(now, start_time);
    printf("\n--- Statistics ---\n");
    for (int i = 0; i < 10 && stats[i].packet_size != 0; i++) {
        double pps = stats[i].count / elapsed;
        double throughput = (stats[i].bytes * 8) / elapsed;
        printf("Size %zu bytes: %zu packets, %.2f PPS, %.2f bps\n",
               stats[i].packet_size, stats[i].count, pps, throughput);
    }
    printf("Total: %zu packets, %.2f PPS, %.2f bps\n",
           total_count, total_count / elapsed, (total_bytes * 8) / elapsed);
    fflush(stdout);
}

int create_socket(const char *iface) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

void process_packet(int sockfd, const uint8_t *packet, ssize_t len) {
    struct ethhdr *eth = (struct ethhdr *)packet;

    if (memcmp(eth->h_source, TARGET_MAC_PREFIX, TARGET_MAC_PREFIX_LEN) == 0) {
        update_stats(len);
        uint8_t response[len];
        memcpy(response, packet, len);
        memcpy(response + sizeof(struct ethhdr), PAYLOAD, PAYLOAD_LEN);

        memcpy(response, eth->h_source, ETH_ALEN);
        memcpy(response + ETH_ALEN, eth->h_dest, ETH_ALEN);

        if (send(sockfd, response, len, 0) == -1) {
            perror("send");
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *iface = argv[1];
    int sockfd = create_socket(iface);
    start_time = time(NULL);

    struct epoll_event event, events[10];
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    event.events = EPOLLIN;
    event.data.fd = sockfd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &event) == -1) {
        perror("epoll_ctl");
        close(sockfd);
        close(epoll_fd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        int n = epoll_wait(epoll_fd, events, 10, 60000); // Wait up to 60 seconds
        if (n == -1) {
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == sockfd) {
                uint8_t buffer[ETH_FRAME_LEN];
                ssize_t len = recv(sockfd, buffer, sizeof(buffer), 0);
                if (len == -1) {
                    perror("recv");
                    continue;
                }

                process_packet(sockfd, buffer, len);
            }
        }

        // Print stats every 60 seconds
        print_stats();
    }

    close(sockfd);
    close(epoll_fd);
    return 0;
}