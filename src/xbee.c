#include <stdio.h>
#include <endian.h>
#include <sys/time.h>
#include <time.h>

#include <slash/slash.h>
#include <slash/dflopt.h>
#include <slash/optparse.h>

#include <csp/csp.h>
#include <csp/csp_cmp.h>
#include <csp/csp_crc32.h>
#include <csp/drivers/usart.h>
#include <csp/csp_types.h>
#include <csp/csp_interface.h>
#include <csp/csp_iflist.h>
#include <csp/csp_id.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>
#include "csp/autoconfig.h"
#include "csp/csp_buffer.h"

typedef enum {
	XBEE_MODE_NOT_STARTED,
	XBEE_MODE_LENGTH_MSB,
	XBEE_MODE_LENGTH_LSB,
	XBEE_MODE_SKIP_FRAMING,
	XBEE_MODE_RECEIVING,
} xbee_receive_state_t;

void send_16bit_frame(uint16_t dest_address, void * driver_data, const uint8_t * payload, uint16_t len);

typedef struct {
	char name[CSP_IFLIST_NAME_MAX + 1];
	csp_iface_t iface;
	int fd;
	csp_packet_t * rx_packet;
	xbee_receive_state_t xbee_mode;
	uint16_t data_index;
	uint16_t length;
	uint8_t checksum;
	bool escape_next;
} xbee_ctx_t;

void libinfo(void) {
	printf("Create csp xbee interface\n");
}

void escape_byte(uint8_t byte, uint8_t * output, uint16_t * index) {
	if (byte == 0x7E || byte == 0x7D || byte == 0x11 || byte == 0x13) {
		output[(*index)++] = 0x7D;         // Escape character
		output[(*index)++] = byte ^ 0x20;  // XOR with 0x20
	} else {
		output[(*index)++] = byte;
	}
}

int csp_xbee_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {

	//packet->id.flags |= 0xFE;
	csp_id_prepend(packet);
	send_16bit_frame(packet->id.dst, iface->driver_data, packet->frame_begin, packet->frame_length);
	csp_buffer_free(packet);

	return 0;
}

void send_16bit_frame(uint16_t dest_address, void * driver_data, const uint8_t * payload, uint16_t len) {
	uint8_t frame[128];
	uint16_t length = 0;
	uint8_t sum = 0x01;

	// Start delimiter
	frame[length++] = 0x7E;

	// Length (MSB, LSB)
	uint16_t frame_data_length = 5 + len;  // 5 bytes of frame data + payload length
	escape_byte((frame_data_length >> 8) & 0xFF, frame, &length);
	escape_byte(frame_data_length & 0xFF, frame, &length);

	// Transmit Request (16-bit address)
	frame[length++] = 0x01;
	frame[length++] = 0x00;

	// Destination address (MSB, LSB)
	sum += (dest_address >> 8) & 0xFF;
	escape_byte((dest_address >> 8) & 0xFF, frame, &length);
	sum += dest_address & 0xFF;
	escape_byte(dest_address & 0xFF, frame, &length);

	// no options
	frame[length++] = 0x00;
	// add payload
	for (uint8_t i = 0; i < len; i++) {
		sum += payload[i];
		escape_byte(payload[i], frame, &length);
	}

	// Checksum after len
	escape_byte(0xFF - sum, frame, &length);

	// Send the frame over UART
	xbee_ctx_t * ctx = (xbee_ctx_t *)driver_data;
	int n = write(ctx->fd, frame, length);
	if (n < 0) {
		printf("failed write\n");
	}
}

void xbee_driver_rx(void * user_data, uint8_t * data, size_t data_size, void * pxTaskWoken) {
	xbee_ctx_t * ctx = (xbee_ctx_t *)user_data;


	for (int i = 0; i < data_size; i++) {
		if (data[i] == 0x7D) {
			ctx->escape_next = true;  // Next byte is escaped
			continue;                   // Wait for next byte
		}

		if (ctx->escape_next) {
			data[i] ^= 0x20;  // Unescape the byte
			ctx->escape_next = false;
		}

		switch (ctx->xbee_mode) {
			case XBEE_MODE_NOT_STARTED:
				if (data[i] == 0x7E) {
					// Start delimiter detected
					ctx->rx_packet = csp_buffer_get(0);
					csp_id_setup_rx(ctx->rx_packet);
					ctx->xbee_mode = XBEE_MODE_LENGTH_MSB;
					ctx->length = 0;
					ctx->data_index = 0;
					ctx->checksum = 0;
				}
				break;

			case XBEE_MODE_LENGTH_MSB:
				ctx->length = data[i] << 8;  // Store MSB of length
				ctx->xbee_mode = XBEE_MODE_LENGTH_LSB;
				break;

			case XBEE_MODE_LENGTH_LSB:
				ctx->length |= data[i];  // Store LSB of length
				if (ctx->length > CSP_BUFFER_SIZE) {
					ctx->iface.rx_error++;
					ctx->iface.drop++;
					ctx->xbee_mode = XBEE_MODE_NOT_STARTED;
				} else {
					ctx->xbee_mode = XBEE_MODE_SKIP_FRAMING;
				}
				break;
			case XBEE_MODE_SKIP_FRAMING:
				ctx->checksum += data[i];
				ctx->data_index++;

				if (ctx->data_index >= 5) {
					ctx->xbee_mode = XBEE_MODE_RECEIVING;
				}
				break;

			case XBEE_MODE_RECEIVING:
				//		7E 00 0A 81 00 02 14 00 68 65 6C 6C 6F 54
				if (ctx->data_index < ctx->length) {
					ctx->checksum += data[i];
					ctx->rx_packet->frame_begin[ctx->rx_packet->frame_length++] = data[i];  // xd
					ctx->data_index++;
				} else {
					// Last byte is the checksum
					uint8_t calculated_checksum = 0xFF - ctx->checksum;
					if (calculated_checksum == data[i]) {

						uint16_t frame_len = ctx->rx_packet->frame_length;
						ctx->iface.rxbytes += frame_len;
						ctx->iface.rx++;

						if (csp_id_strip(ctx->rx_packet) < 0) {
							ctx->iface.frame++;
							ctx->xbee_mode = XBEE_MODE_NOT_STARTED;
							break;
						}

						csp_qfifo_write(ctx->rx_packet, &ctx->iface, pxTaskWoken);
					} else {
						ctx->iface.rx_error++;
						ctx->iface.drop++;
						// Checksum invalid, handle error
					}
					// Reset state for next frame
					ctx->xbee_mode = XBEE_MODE_NOT_STARTED;
				}
				break;

			default:
				ctx->iface.rx_error++;
				ctx->iface.drop++;
				ctx->xbee_mode = XBEE_MODE_NOT_STARTED;
				break;
		}
	}
}

static int csp_ifadd_xbee_cmd(struct slash * slash) {

	static int ifidx = 0;

	char name[11];
	snprintf(name, 10, "XBEE%u", ifidx++);

	int promisc = 0;
	int mask = 8;
	int dfl = 0;
	int baudrate = 9600;
	char * device = "/dev/ttyUSB1";

	optparse_t * parser = optparse_new("csp add xbee", "<addr>");
	optparse_add_help(parser);
	optparse_add_set(parser, 'p', "promisc", 1, &promisc, "Promiscuous Mode ALWAYS ON");
	optparse_add_int(parser, 'm', "mask", "NUM", 0, &mask, "Netmask (defaults to 8)");
	optparse_add_int(parser, 'b', "baud", "NUM", 0, &baudrate, "Baudrate (defualts to 9600)");
	optparse_add_string(parser, 's', "dev", "STR", &device, "Device name (defaults to /dev/ttyUSB0)");
	optparse_add_set(parser, 'd', "default", 1, &dfl, "Set as default");

	int argi = optparse_parse(parser, slash->argc - 1, (const char **)slash->argv + 1);

	if (argi < 0) {
		return SLASH_EINVAL;
	}

	if (++argi >= slash->argc) {
		printf("missing parameter addr\n");
		optparse_del(parser);
		return SLASH_EINVAL;
	}
	char * endptr;
	unsigned int addr = strtoul(slash->argv[argi], &endptr, 10);

	xbee_ctx_t * ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return CSP_ERR_NOMEM;
	}
	/* Not needed just here to make csp_usart happy */
	csp_usart_conf_t conf = {
		.device = device,
		.baudrate = baudrate,
		.databits = 8,
		.stopbits = 1,
		.paritysetting = 0};

	strncpy(ctx->name, name, sizeof(ctx->name) - 1);
	ctx->iface.name = ctx->name;
	ctx->iface.addr = addr;
	ctx->iface.netmask = mask;
	ctx->iface.is_default = dfl;
	ctx->iface.driver_data = ctx;
	ctx->iface.nexthop = csp_xbee_tx;

	if (csp_usart_open(&conf, xbee_driver_rx, ctx, &ctx->fd) < 0) {
		printf("csp_usart_open() failed\n");
		return SLASH_SUCCESS;
	}
	csp_iflist_add(&ctx->iface);

	return SLASH_SUCCESS;
}
slash_command_subsub(csp, add, xbee, csp_ifadd_xbee_cmd, NULL, "Add a new xbee interface");
