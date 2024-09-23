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

#define SERIALNUMBER "6a8e48cf+F90F785F"
#define MAXLINESIZE 8192 // jumbo frames multiple of 8 bytes

// listener port
#define MYPORT "2514"    // 514 default SYSLOG port requires root, RFC 5424, need to drop privileges and maybe chroot

// destination port for datadiode-deamplify514
#define SERVERPORT "514"    // the port users will be connecting to, same 514 from RFC 5424

#define MAXBUFLEN 1024 + 2*sizeof(uint32_t)  // needs jumbo frames for longer lines like 8192+2, set MTU to 9000 on data-diode interfaces

uint64_t prevcounter = 0;   // this normally overflows, as it should. we just want to clear duplicate packets on the receiver side

uint64_t combine_uint32_to_uint64_be(const uint32_t values[2]) {
    // Ensure the conversion is endianness-portable by manually handling bytes
    uint64_t result = ((uint64_t)values[0] << 32) | (uint64_t)values[1];
    return result;
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

void blocks_to_string(const uint32_t *blocks, size_t num_blocks, char *output, size_t *output_len) {
  size_t i, j;
  size_t output_index = 0;

  for (i = 0; i < num_blocks; i++) {
    for (j = 0; j < 4; j++) {
      uint8_t byte = get_byte(blocks[i], j);
      if (byte) {
        output[output_index++] = byte;
      }
    }
  }
  output[output_index] = '\0';  // Null terminate the output string
  *output_len = output_index;   // Set the output length to the number of characters written
}

// Function to check system endianness
int is_little_endian() {
    uint16_t num = 1;
    return (*(uint8_t *)&num == 1);
}

// Function to swap endianness of a uint64_t number
uint64_t swap_endianness(uint64_t num) {
    return ((num >> 56) & 0x00000000000000FF) |
           ((num >> 40) & 0x000000000000FF00) |
           ((num >> 24) & 0x0000000000FF0000) |
           ((num >> 8) & 0x00000000FF000000) |
           ((num << 8) & 0x000000FF00000000) |
           ((num << 24) & 0x0000FF0000000000) |
           ((num << 40) & 0x00FF000000000000) |
           ((num << 56) & 0xFF00000000000000);
}

// Function to convert a big-endian uint64_t to little-endian if the system is little-endian
uint64_t convert_to_little_endian_if_needed(uint64_t big_endian_value) {
    if (is_little_endian()) {
        return swap_endianness(big_endian_value);
    }
    return big_endian_value;
}

int main(void)
{
    int sockfd, sockfdout;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    int numbytes, len;
    speckr_ctx CTX;
    uint32_t pt[2], ct[2]; 
    size_t pwdlen, input_len = 0;
    struct sockaddr_storage their_addr;
    char buf[MAXBUFLEN];
    char msg[MAXLINESIZE];
    socklen_t addr_len;
    uint32_t ct_blocks[MAXLINESIZE * 2 / 8 + 2], pt_blocks[MAXLINESIZE * 2 / 8]; // multiple of 8

    printf("Preparing serial-number to be used as password..\n");
    speckr_init(&CTX, SERIALNUMBER);
    printf("Current serial number for amplifier device is %s\n", SERIALNUMBER);
    printf("MYPORT is %s, SERVERPORT on the other side is %s\n", MYPORT, SERVERPORT);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Use AF_UNSPEC to listen on both IPv4 and IPv6
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // Use my IP

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

    printf("listener: waiting to recvfrom...\n");
    addr_len = sizeof their_addr;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // set to AF_INET6 to use IPv6
    hints.ai_socktype = SOCK_DGRAM;

    if ((rv = getaddrinfo("localhost", SERVERPORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and make a socket
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfdout = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("talker: socket");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "talker: failed to create socket\n");
        return 2;
    }

    uint64_t counter64 = 0;
    uint32_t counter32[2];
    size_t num_blocks, backup_num_blocks;

    prevcounter = 65535;
    char *ptr = buf + sizeof(uint16_t);
    while (1) {  // infinite loop, in UDP packets may be lost so this is preferred 
        for (size_t i = 0; i < MAXLINESIZE * 2 / 8; i++) {
            ct_blocks[i] = 0; // smaller
            pt_blocks[i] = 0;
        }

        if ((numbytes = recvfrom(sockfd, ct_blocks, sizeof(ct_blocks), 0, (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("listener: recvfrom");
        }

        num_blocks = numbytes / sizeof(uint32_t); // Number of uint32_t blocks received
        printf("Number of blocks received: %zu\n", num_blocks);
        printf("listener: packet contains: ");
        for (size_t i = 0; i < num_blocks; i++) {
            printf("%08X ", ct_blocks[i]);
        }
        printf("\n");

        if (is_little_endian()) {
            counter32[0] = ct_blocks[1];
            counter32[1] = ct_blocks[0];
        } else {
            counter32[0] = ct_blocks[0];
            counter32[1] = ct_blocks[1];
        }
        counter64 = combine_uint32_to_uint64_be(counter32);
        counter64 = convert_to_little_endian_if_needed(counter64);

        backup_num_blocks = num_blocks;
        if (num_blocks % 2 == 1) num_blocks++;

        if (counter64 != prevcounter) { // skip duplicate (amplified) lines

            // Decrypt each block but first 2 blocks are the plaintext counter
            for (size_t i = 2; i < num_blocks; i += 2) {
                ct[0] = ct_blocks[i];
                ct[1] = ct_blocks[i + 1];

                /* 
                 * it is recommended to use fixed packet size like MAXLINESIZE to avoid repeating counters 
                 *
                 * make sure you read the comments in the amplifier (sender) so that you understand SpeckR
                 * in asynchronous (shuffled) mode requires that we encrypt/decrypt the same number of blocks
                 * in order to keep the dynamic Sboxes consistent between the sender and the receiver
                 */
                SpeckREncrypt_async(ct, pt, &CTX, counter64, MAXLINESIZE, i - 2); // i-2
                pt_blocks[i - 2] = pt[0];
                pt_blocks[i + 1 - 2] = pt[1];
            }
            // Print blocks
            printf("Decrypted Blocks:\n");
            for (size_t i = 0; i < num_blocks - 2; i++) {
                printf("%08x ", pt_blocks[i]);
            }
            printf("\n");
            memset(msg, 0x0, MAXLINESIZE);
            blocks_to_string(pt_blocks, backup_num_blocks, msg, &input_len);

            if ((numbytes = sendto(sockfdout, msg, input_len, 0, p->ai_addr, p->ai_addrlen)) == -1) { // send to syslog
                perror("talker: sendto");
            }
            prevcounter = counter64;
        }
    }

    /* 
     * we do not reach here 
     */

    freeaddrinfo(servinfo);
    close(sockfd); close(sockfdout);

    return 0;
}
