#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <assert.h>
#include <stdint.h>

#include "wolfpack.h"

#define SHIFT_BYTES(x, y) ((uint64_t)(x) & 0xFF) << ((y) * 8)

struct packet_header {
	uint64_t src_addr;
	uint64_t dst_addr;
	uint8_t	src_prt;
	uint8_t	dst_prt;
	uint32_t frag_off;
	uint16_t flags;
	uint32_t len;
	uint32_t checksum;
};

struct packet_header load_packet_header(const unsigned char *packet){
	struct packet_header h;
	memset(&h, 0, sizeof(struct packet_header));

	for(int i = 0; i < 5; i++)
		h.src_addr |= SHIFT_BYTES(packet[i], 5 - i - 1);

	for(int i = 0; i < 5; i++)
		h.dst_addr |= SHIFT_BYTES(packet[i + 5], 5 - i - 1);
	
	h.src_prt = packet[10];
	h.dst_prt = packet[11];

	for(int i = 0; i < 3; i++)
		h.frag_off |= SHIFT_BYTES(packet[i + 12], 3 - i - 1);

	for(int i = 0; i < 2; i++)
		h.flags |= SHIFT_BYTES(packet[i + 15], 2 - i - 1);
	
	for(int i = 0; i < 3; i++)
		h.len |= SHIFT_BYTES(packet[i + 17], 3 - i - 1);

	for(int i = 0; i < 4; i++)
		h.checksum |= SHIFT_BYTES(packet[i + 20], 4 - i - 1);

	return h;
}

void print_packet_sf(const unsigned char *packet) {
	
	struct packet_header h = load_packet_header(packet);

	printf("%010lx\n", h.src_addr);
	printf("%010lx\n", h.dst_addr);
	printf("%02x\n", h.src_prt);
	printf("%02x\n", h.dst_prt);
	printf("%06x\n", h.frag_off);
	printf("%04x\n", h.flags);
	printf("%06x\n", h.len);
	printf("%08x\n", h.checksum);
	for(int i = 0; i < h.len - 24; i++)
		printf("%c", packet[i + 24]);
	
	printf("\n");
}

unsigned char *create_packet(struct packet_header h, unsigned char *payload)
{
	unsigned char *packet = malloc(h.len);

	for(int i = 0; i < 5; i++)
		packet[i] = (h.src_addr >> ((5 - i - 1) * 8)) & 0xFF;

	for(int i = 0; i < 5; i++)
		packet[i + 5] = (h.dst_addr >> ((5 - i - 1) * 8)) & 0xFF;
	
	packet[10] = h.src_prt;
	packet[11] = h.dst_prt;

	for(int i = 0; i < 3; i++)
		packet[i + 12] = (h.frag_off >> ((3 - i - 1) * 8)) & 0xFF;

	for(int i = 0; i < 2; i++)
		packet[i + 15] = (h.flags >> ((2 - i - 1) * 8)) & 0xFF;

	//printf("testing %x\n", h.len);
	for(int i = 0; i < 3; i++)
	{
		packet[i + 17] = (h.len >> ((3 - i - 1) * 8)) & 0xFF;
		//printf("%d %x\n", i, packet[i + 17]);
	}

	for(int i = 0; i < 4; i++)
		packet[i + 20] = (h.checksum >> ((4 - i - 1) * 8)) & 0xFF;
	
	memcpy(packet + 24, payload, h.len - 24);
	
	return packet;
}

unsigned int packetize_sf(const char *message, unsigned char *packets[], unsigned int packets_len, unsigned int max_payload,
    unsigned long src_addr, unsigned long dest_addr, unsigned short flags) {
	int len = strlen(message);
	int payloads = 0;

	//printf("MAX: %u LEN: %d\n", max_payload, len);

	while(len > 0 && payloads < packets_len)
	{
		unsigned int payload_size = max_payload;
		if(len < max_payload)
			payload_size = len;

		//printf("payload size %u\n", payload_size);

		len -= payload_size;

		//printf("length left %u\n", len);

		struct packet_header h;
		h.src_addr = src_addr;
		h.dst_addr = dest_addr;
		h.src_prt = 32;
		h.dst_prt = 64;
		h.frag_off = payloads * max_payload;
		h.flags = flags;
		h.len = 24 + payload_size;

		uint64_t c =  h.src_addr
					+ h.dst_addr
					+ h.src_prt
					+ h.dst_prt
					+ h.frag_off
					+ h.flags
					+ h.len;
	
		h.checksum = (uint32_t)(c % (uint64_t)0xFFFFFFFF);
		packets[payloads++] = create_packet(h, message + h.frag_off);
	}

    return payloads;
}

unsigned int checksum_sf(const unsigned char *packet) {
	struct packet_header h = load_packet_header(packet);
	uint64_t c =  h.src_addr
				+ h.dst_addr
				+ h.src_prt
				+ h.dst_prt
				+ h.frag_off
				+ h.flags
				+ h.len;
	
	return (uint32_t)(c % (uint64_t)0xFFFFFFFF);
}

unsigned int reconstruct_sf(unsigned char *packets[], unsigned int packets_len, char *message, unsigned int message_len) {
	int num_payloads = 0;
	unsigned int terminator_index = 0;
	for(int i = 0; i < packets_len; i++)
	{
		struct packet_header h = load_packet_header(packets[i]);
		if(h.checksum != checksum_sf(packets[i]))
			continue;
		
		if(h.frag_off >= message_len - 1)
			continue;

		num_payloads++;
		int j;
		for(j = 0; j < h.len - 24 && j + h.frag_off < message_len - 1; j++)
			message[h.frag_off + j] = packets[i][j + 24];

		if(h.frag_off + j > terminator_index)
			terminator_index = j + h.frag_off;
	}

	if(num_payloads > 0)
		message[terminator_index] = '\0';

	return num_payloads;
}
