/*
 *      (C) 2024 Alin Anton <alin.anton@cs.upt.ro>
 * 
 *      This software servers as an example of how to amplify and pipe syslog UDP messages through optical data diodes in order to mitigate for
 *      UDP packet loss. 
 *
 *      It is based on "Beej's Guide on Network Programming". 
 *
 *      Principal Investigator: Alin-Adrian Anton <alin.anton@cs.upt.ro>
 *      Project members: Razvan-Dorel Cioarga <razvan.cioarga@cs.upt.ro>
 *                       Eugenia Capota <eugenia.capota@cs.upt.ro>
 *                       Petra Csereoka <petra.csereoka@cs.upt.ro>
 *                       Bianca Gusita <bianca.gusita@cs.upt.ro>
 *
 *      This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation,
 *      either version 3 of the License, or (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *      You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
 *
 *      An unofficial Romanian translation of the GNU General Public License is available here: <https://staff.cs.upt.ro/~gnu/Licenta_GPL-3-0_RO.html>.                                        
 */   

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h>

#include "../src/speckr.h"

#define AMPFACTOR 20   // send each line AMPFACTOR times using AMPFACTOR packets
#define SERIALNUMBER "6a8e48cf+F90F785F"
#define MAXLINESIZE 8192 // jumbo frames multiple of 8 bytes

// listener port
#define MYPORT "1514"    // 514 default SYSLOG port requires root, RFC 5424, need to drop privileges and maybe chroot

// destination port for datadiode-deamplify514
#define SERVERPORT "2514"    // the port users will be connecting to, same 514 from RFC 5424

#define MAXBUFLEN 1024 + 2*sizeof(uint32_t)  // needs jumbo frames for longer lines like 8192+2, set MTU to 9000 on data-diode interfaces

uint64_t counter64 = 0;

void split_uint64_to_uint32_be(uint64_t value, uint32_t result[2]) {
    // Ensure the conversion is endianness-portable by manually handling bytes
    result[0] = (uint32_t)((value >> 56) & 0xFF) |
                (uint32_t)((value >> 40) & 0xFF00) |
                (uint32_t)((value >> 24) & 0xFF0000) |
                (uint32_t)((value >> 8) & 0xFF000000);

    result[1] = (uint32_t)((value >> 24) & 0xFF) |
                (uint32_t)((value >> 8) & 0xFF00) |
                (uint32_t)((value << 8) & 0xFF0000) |
                (uint32_t)((value << 24) & 0xFF000000);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Helper function to extract a specific byte from a multi-byte value
// regardless of system's endianness (assuming big-endian processing)
uint8_t get_byte(uint32_t value, size_t index) {
  return (value >> (8 * (3 - index))) & 0xFF;
}

// Function to convert a string to blocks
void string_to_blocks(const char *input, size_t input_len, uint32_t *blocks,
                      size_t *num_blocks) {
  size_t i, j;
  size_t num_full_blocks = input_len / 4;
  size_t remaining_bytes = input_len % 4;

  *num_blocks = num_full_blocks + (remaining_bytes > 0 ? 1 : 0);

  for (i = 0; i < num_full_blocks; i++) {
    blocks[i] = 0;
    for (j = 0; j < 4; j++) {
      blocks[i] = (blocks[i] << 8) | (uint8_t)input[i * 4 + j];
    }
  }

  if (remaining_bytes > 0) {
    blocks[*num_blocks - 1] = 0;
    for (j = 0; j < remaining_bytes; j++) {
      blocks[*num_blocks - 1] = (blocks[*num_blocks - 1] << 8) |
                                (uint8_t)input[num_full_blocks * 4 + j];
    }
  }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server1> <server2> ...\n", argv[0]);
        return 1;
    }

    int sockfd, *sockfdout, i;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    int numbytes, len;
    struct sockaddr_storage their_addr;
    char buf[MAXBUFLEN];
    socklen_t addr_len;
    speckr_ctx CTX;
    uint32_t pt[2], ct[2];
    size_t pwdlen, input_len = 0, num_blocks;
    char msg[MAXLINESIZE];
    uint32_t ct_blocks[MAXLINESIZE * 2 / 8 + 2], pt_blocks[MAXLINESIZE * 2 / 8]; // multiple of 8

    int num_servers = argc - 1;
    sockfdout = malloc(num_servers * sizeof(int)); // Create array of sockets for each server

    printf("Preparing serial-number to be used as password..\n");
    speckr_init(&CTX, SERIALNUMBER);
    printf("Current serial number for amplifier device is %s\n", SERIALNUMBER);
    printf("MYPORT is %s, SERVERPORT on the other side is %s\n", MYPORT, SERVERPORT);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6; // set to AF_INET6 to use IPv6
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, MYPORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("listener: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: bind");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        return 2;
    }

    freeaddrinfo(servinfo);

    // Set up the destination sockets
    for (int server_index = 0; server_index < num_servers; server_index++) {
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET6; // set to AF_INET6 to use IPv6
        hints.ai_socktype = SOCK_DGRAM;

        if ((rv = getaddrinfo(argv[server_index + 1], SERVERPORT, &hints, &servinfo)) != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
            return 1;
        }

        // loop through all the results and make a socket for each destination
        for (p = servinfo; p != NULL; p = p->ai_next) {
            if ((sockfdout[server_index] = socket(p->ai_family, p->ai_socktype,
                    p->ai_protocol)) == -1) {
                perror("talker: socket");
                continue;
            }
            break;
        }

        if (p == NULL) {
            fprintf(stderr, "talker: failed to create socket for %s\n", argv[server_index + 1]);
            return 2;
        }

        freeaddrinfo(servinfo);
    }

    printf("listener: waiting to recvfrom...\n");
    addr_len = sizeof their_addr;

    counter64 = 0;
    uint32_t counter32[2];

    while (1) {  // infinite loop, in UDP packets may be lost so this is preferred
        if ((numbytes = recvfrom(sockfd, &buf, MAXBUFLEN - 1 - sizeof(uint16_t), 0,
                (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
        }
        buf[numbytes] = '\0';
        len = numbytes;
        for (size_t i = 0; i < MAXLINESIZE * 2 / 8; i++) {
            pt_blocks[i] = 0;
            ct_blocks[i] = 0; // smaller
        }
        string_to_blocks(buf, numbytes, pt_blocks, &num_blocks);

        split_uint64_to_uint32_be(counter64, counter32);

        ct_blocks[0] = counter32[0];
        ct_blocks[1] = counter32[1];

        if (num_blocks % 2 == 1) num_blocks++;

        // Encrypt each block but first 2 blocks are the plaintext counter
        for (size_t i = 0; i < num_blocks; i += 2) {
            pt[0] = pt_blocks[i];
            pt[1] = pt_blocks[i + 1];

            SpeckREncrypt_async(pt, ct, &CTX, counter64, MAXLINESIZE, i); // i*4
            ct_blocks[2 + i] = ct[0];
            ct_blocks[2 + i + 1] = ct[1];
        }

        // Print blocks
        printf("Counter + Encrypted Blocks:\n");
        for (size_t i = 0; i < num_blocks + 2; i++) {
            printf("%08x ", ct_blocks[i]);
        }
        printf("\n");

        for (i = 0; i < AMPFACTOR; i++) {
            int server_index = i % num_servers; // Round-robin
            if ((numbytes = sendto(sockfdout[server_index], ct_blocks, sizeof(uint32_t) * (num_blocks + 2), 0, p->ai_addr, p->ai_addrlen)) == -1) { // send AMPFACTOR times
                perror("talker: sendto");
            }
        }

        counter64 += MAXLINESIZE; // this normally overflows
    }

    // Clean up (although this point will never be reached)
    for (int server_index = 0; server_index < num_servers; server_index++) {
        close(sockfdout[server_index]);
    }
    free(sockfdout);
    close(sockfd);

    return 0;
}

