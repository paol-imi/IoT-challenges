

#ifndef RADIO_ROUTE_H
#define RADIO_ROUTE_H

// Enum for message types.
typedef enum MSG_TYPE {
	// Data message.
  DATA_MSG = 0,
	// Route request.
  ROUTE_REQ_MSG = 1,
	// Route reply.
  ROUTE_REP_MSG = 2
} MSG_TYPE;

// Message structure.
typedef nx_struct radio_route_msg {
	// Message type.
	nx_uint8_t type;
	// Message payload.
	nx_uint16_t value;
	// Identifiers of the sender and destination. Those will be used only for 
	// data messages.
	nx_uint16_t sender;
	nx_uint16_t destination;
	// Identifier of the node that is requested in the route request message.
	// This field will be used only for route request and reply messages.
	nx_uint16_t node_requested;
	nx_uint16_t cost;
} radio_route_msg_t;

// Route table entry.
typedef struct route_table_entry {
	// Next hop for the destination.
	uint16_t next_hop;
	// Cost of the route.
	uint16_t cost;
} route_table_entry_t;

enum {
  AM_RADIO_COUNT_MSG = 10,
};

#endif