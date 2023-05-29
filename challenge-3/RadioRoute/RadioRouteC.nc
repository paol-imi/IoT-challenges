#include "Timer.h"
#include "RadioRoute.h"

#define NUMBER_OF_NODES 7

// TODO: Check what to put in the field "sender"

module RadioRouteC @safe() {
  uses {
    /****** INTERFACES *****/
	  interface Boot;
    interface Leds;
    interface Timer<TMilli> as Timer0;
    interface Timer<TMilli> as Timer1;
    interface AMSend;
    interface Receive;
    interface SplitControl as AMControl;
    interface Packet;
  }
}

implementation {
  int person_code[] = {1, 0, 6, 7, 7, 6, 6, 8};
  int person_code_len = 8;
  int current_digit = 0;

  // Route table for the nodes represented by an array of entries. Each index in 
  // the array will represent the node with ID = index + 1. Each entry will 
  // contain the next hop to reach the destination node and the number of hops
  // to reach the destination node (cost).
  route_table_entry_t route_table[NUMBER_OF_NODES];

  // Variable to store the current packet.
  message_t packet;
  bool locked;
  
  // Variables to store the message to send
  // MANDATORY: DO NOT MODIFY THOSE VARIABLES
  message_t queued_packet;
  uint16_t queue_addr;
  // Time delays in milliseconds.
  uint16_t time_delays[7]={61,173,267,371,479,583,689}; 
  // Flags to check if a REQ or REP message has been sent.
  bool route_req_sent=FALSE;
  bool route_rep_sent=FALSE;

  // Function headers
  bool generate_send (uint16_t address, message_t* pkt, uint8_t type);
  bool actual_send (uint16_t address, message_t* pkt);
  route_table_entry_t* lookup (uint16_t address);
  radio_route_msg_t* try_route_request_msg(uint16_t node_requested);
  radio_route_msg_t* try_route_reply_msg(uint16_t node_requested, uint16_t cost);
  radio_route_msg_t* try_data_msg(uint16_t sender, uint16_t destination, uint16_t value);

  // Event handler for the boot event.
  event void Boot.booted() {
    int i = 0;
    
    for (i = 0; i < NUMBER_OF_NODES; i=i+1) {
      // Initialize the next hop to 0. This means that the next hop is not
      // known yet.
      route_table[i].next_hop = 0;
      route_table[i].cost = 0;
    }

    // Initialize the radio channel.
    call AMControl.start();
    dbg("boot", "Application booted.\n");
  }

  // Event handler for the radio start done event.
  event void AMControl.startDone(error_t err) {
    if (err == SUCCESS) {
      dbg("radio", "Radio on on node %d!\n", TOS_NODE_ID);
      // Start a timer one shot for in 5 seconds.
      call Timer1.startOneShot(5000);
    } else {
      dbgerror("radio", "Radio failed to start, retrying...\n");
      // Try to start the radio again.
      call AMControl.start();
    }
  }

  event void AMControl.stopDone(error_t err) {
    dbg("boot", "Radio stopped!\n");
  }

  /*
	 * Implement here the logic to trigger the Node 1 to send the first REQ packet.
	 */
  event void Timer1.fired() {
    if (TOS_NODE_ID == 1) {
      // Next hop equals to "0" is our convetion to state that the route is not defined.
      if (lookup(7)->next_hop == 0) {
        radio_route_msg_t* rrm = try_route_request_msg(7);
        if(rrm != NULL) generate_send(AM_BROADCAST_ADDR, &packet, ROUTE_REQ_MSG);
      } else {
        radio_route_msg_t* rrm = try_data_msg(TOS_NODE_ID ,7, 5);
        if(rrm != NULL) generate_send(7, &packet, DATA_MSG);
      }
    }
  }
  
  /*
   * Function to be used when performing the send after the receive message 
   * event. It store the packet and address into a global variable and start the 
   * timer execution to schedule the send. It allow the sending of only one 
   * message for each REQ and REP type.
   *
   * @Input:
   *		address: packet destination address
   *		pkt: full packet to be sent (Not only Payload)
   *		type: payload message type
   *
   * MANDATORY: DO NOT MODIFY THIS FUNCTION
   */
  bool generate_send (uint16_t address, message_t* pkt, uint8_t type){
  	if (call Timer0.isRunning()) {
  		return FALSE;
  	} else {
      if (type == 1 && !route_req_sent ) {
        route_req_sent = TRUE;
        call Timer0.startOneShot( time_delays[TOS_NODE_ID-1] );
        queued_packet = *pkt;
        queue_addr = address;
      }else if (type == 2 && !route_rep_sent) {
        route_rep_sent = TRUE;
        call Timer0.startOneShot( time_delays[TOS_NODE_ID-1] );
        queued_packet = *pkt;
        queue_addr = address;
      }else if (type == 0) {
        call Timer0.startOneShot( time_delays[TOS_NODE_ID-1] );
        queued_packet = *pkt;
        queue_addr = address;	
      }
  	}

  	return TRUE;
  }

  /*
   * Timer triggered to perform the send.
   * MANDATORY: DO NOT MODIFY THIS FUNCTION
   */
  event void Timer0.fired() {
  	actual_send (queue_addr, &queued_packet);
  }

  // Function to perform the actual send of the packet.
  bool actual_send (uint16_t address, message_t* pkt) {
    if (call AMSend.send(address, pkt, sizeof(radio_route_msg_t)) == SUCCESS) {
      return TRUE;
    } else {
      dbgerror("radio_send", "Error sending packet");
      locked = FALSE;
      return FALSE;
    }
  }

  // Function to lookup the next hop for a given destination address.
  route_table_entry_t* lookup (uint16_t address) {
    if (address > NUMBER_OF_NODES || address < 1) {
      dbgerror("lookup", "Address %d is out of range.\n", address);
      exit(1);
    }

    return &route_table[address - 1];
  }

  // Update the led status.
  void update_leds() {
    char bitsString[4] = "000\0";

    // Led logic.
    int led = person_code[current_digit] % 3;
    if (current_digit == person_code_len - 1) {
      current_digit = 0;
    } else {
      current_digit++;
    }

    // Toggle the led based on the person code.
    switch (led) {
      case 0:
        call Leds.led0Toggle();
        break;
      case 1:
        call Leds.led1Toggle();
        break;
      case 2:
        call Leds.led2Toggle();
        break;
    }

    // Extract the bits from the leds.
    bitsString[0] += (call Leds.get() >> 2) & 0x01; // Extract the MSB of the extracted bits
    bitsString[1] += (call Leds.get() >> 1) & 0x01; // Extract the middle bit of the extracted bits
    bitsString[2] += (call Leds.get() >> 0) & 0x01;

    dbg("leds", "node %d has leds: %s\n", TOS_NODE_ID, bitsString);
    if (TOS_NODE_ID == 6) {
      // Print the led status on the debug fro node 6.
      dbg_clear("node6_leds", "%s,", bitsString);
    }
  }

  event message_t* Receive.receive(message_t* bufPtr, void* payload, uint8_t len) {
    /*
    * Parse the receive packet.
    * Implement all the functionalities
    * Perform the packet send using the generate_send function if needed
    * Implement the LED logic and print LED status on Debug
    */
    if (len != sizeof(radio_route_msg_t)) {
      return bufPtr;
    } else {
      radio_route_msg_t* rrm = (radio_route_msg_t*)payload;

      // Update the leds.
      update_leds();

      // Check the message type.
      switch (rrm->type) {
        case DATA_MSG: {
          dbg("radio_rec", "RECEIVE: {%d} <---(DATA_MSG: value %d for node {%d})--- {%d}\n", TOS_NODE_ID, rrm->value, rrm->destination, rrm->sender);
          // Check if the packet is for me.
          if (rrm->destination == TOS_NODE_ID) {
            dbg("radio_rec", "Packet is for me! :)\n");
          } else {
            route_table_entry_t* entry = lookup(rrm->node_requested);
            // If I don't know how to route the packet, I send a route request.
            if(entry->next_hop == 0) {
              // NOTE: we don't handle this case for the sake of this example.
              dbgerror("radio_rec", "Packet is not for me and I don't know how to route it :(.\n");
            } else {
              // If I know how to route the packet, I send it.
              radio_route_msg_t* msg = try_data_msg(rrm->sender, rrm->destination, rrm->value);
              if(msg != NULL) generate_send(entry->next_hop, &packet, DATA_MSG);
            }
          }
          return bufPtr;
        }
        case ROUTE_REQ_MSG: {
          dbg("radio_rec", "RECEIVE: {%d} <---(ROUTE_REQ_MSG: node requested {%d})---\n", TOS_NODE_ID, rrm->node_requested);

          // Check if the packet is for me.
          if (rrm->node_requested == TOS_NODE_ID) {
            // If the packet is for me, I send a route reply.
            radio_route_msg_t* msg = try_route_reply_msg(TOS_NODE_ID, 1);
            if(msg != NULL) generate_send(AM_BROADCAST_ADDR, &packet, ROUTE_REP_MSG);
          } else {
            route_table_entry_t* entry = lookup(rrm->node_requested);

            // If I don't know how to route the packet, I send a route request.
            if (entry->next_hop == 0) {
              radio_route_msg_t* msg = try_route_request_msg(rrm->node_requested);
              if(msg != NULL) generate_send(AM_BROADCAST_ADDR, &packet, ROUTE_REQ_MSG);
            } else {
              radio_route_msg_t* msg = try_route_reply_msg(rrm->node_requested, entry->cost + 1);
              if(msg != NULL) generate_send(AM_BROADCAST_ADDR, &packet, ROUTE_REP_MSG);
            }
          }

          return bufPtr;
        }
        case ROUTE_REP_MSG: {
          radio_route_msg_t* msg;
          route_table_entry_t* entry = lookup(rrm->node_requested);
          dbg("radio_rec", "RECEIVE: {%d} <---(ROUTE_REP_MSG: node requested {%d})--- {%d}\n", TOS_NODE_ID, rrm->node_requested, rrm->sender);

          // If the requested node is not me and I don't know how to route it or the cost is lower than the one I know.
          if(rrm->node_requested != TOS_NODE_ID && (entry->next_hop == 0 || entry->cost >= rrm->cost)) {
            // Send a route reply to the sender.
            // NOTE: To simplify the implementation, we avoid sending a route reply on node 1,
            //        To avoid collison with the data message.
            if (TOS_NODE_ID != 1) {
              msg = try_route_reply_msg(rrm->node_requested, rrm->cost + 1);
              if(msg != NULL) generate_send(AM_BROADCAST_ADDR, &packet, ROUTE_REP_MSG);
            }

            // If the sender is node 7 and the requested node is 1, send a data message.
            // Since we check next_hop == 0, we don't send a data message only the first time.
            if(TOS_NODE_ID == 1 && rrm->node_requested == 7 && entry->next_hop == 0) {
              msg = try_data_msg(TOS_NODE_ID, 7, 5);
              generate_send(rrm->sender, &packet, DATA_MSG);
            }

            // Update the routing table.
            entry->next_hop = rrm->sender;
            entry->cost = rrm->cost;
          }

          return bufPtr;
        }
        default: {
          dbgerror("radio_rec", "Received a packet of unknown type %d\n", rrm->type);          
          return bufPtr;
        }
      }  
    }
  }

  // Try to acquire the lock.
  bool try_aquire_lock() {
    if (locked) {
      dbgerror("radio_send", "Node {%d} is locked, cannot send packet.\n", TOS_NODE_ID);
      return FALSE;
    } else {
      locked = TRUE;
      return TRUE;
    }
  }

  // Generate a request message.
  radio_route_msg_t* try_route_request_msg(uint16_t node_requested) {
  	radio_route_msg_t* msg;

    if(route_req_sent) {
      return NULL;
    } 

    dbg("radio_send", "TRY SEND: {%d} ---(ROUTE_REQ_MSG: node requested {%d})--->      \n", TOS_NODE_ID, node_requested);
    
    if (!try_aquire_lock()) return NULL;

    msg = (radio_route_msg_t*)call Packet.getPayload(&packet, sizeof(radio_route_msg_t));
    if (msg == NULL) return NULL;
    
    msg->type = ROUTE_REQ_MSG;
    msg->node_requested = node_requested;

    return msg;
  }

  // Generate a reply message.
  radio_route_msg_t* try_route_reply_msg(uint16_t node_requested, uint16_t cost) {
  	radio_route_msg_t* msg;

    if (route_rep_sent) {
      return NULL;
    }

    dbg("radio_send", "TRY SEND: {%d} ---(ROUTE_REP_MSG: node requested {%d})---> \n", TOS_NODE_ID, node_requested);
    if (!try_aquire_lock()) return NULL;

    msg = (radio_route_msg_t*)call Packet.getPayload(&packet, sizeof(radio_route_msg_t));
    if (msg == NULL) return NULL;

    msg->type = ROUTE_REP_MSG;
    msg->node_requested = node_requested;
    msg->sender = TOS_NODE_ID;
    msg->cost = cost;

    return msg;
  }

  // Generate a data message.
  radio_route_msg_t* try_data_msg(uint16_t sender, uint16_t destination, uint16_t value) {
  	radio_route_msg_t* msg;
    dbg("radio_send", "TRY SEND: {%d} ---(DATA_MSG: value %d for node {%d})---> {%d}\n", TOS_NODE_ID, value, destination, lookup(destination)->next_hop);

    if (!try_aquire_lock()) return NULL;

    msg = (radio_route_msg_t*)call Packet.getPayload(&packet, sizeof(radio_route_msg_t));
    if (msg == NULL) return NULL;
    
    msg->type = DATA_MSG;
    msg->sender = sender;
    msg->destination = destination;
    msg->value = value;

    return msg;
  }

  event void AMSend.sendDone(message_t* bufPtr, error_t error) {
    // If we send the packet succesfuly, we release the lock.
    if(bufPtr == &queued_packet) {
      locked = FALSE;
    }
  }
}