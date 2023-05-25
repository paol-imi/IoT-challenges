
 
#include "RadioRoute.h"

configuration RadioRouteAppC {}

implementation {
  /**** COMPONENTS ****/
  components MainC, RadioRouteC as App, LedsC;
  components new AMSenderC(AM_RADIO_COUNT_MSG);
  components new AMReceiverC(AM_RADIO_COUNT_MSG);
  components new TimerMilliC() as TimerMilliC0;
  components new TimerMilliC() as TimerMilliC1;
  components ActiveMessageC;
  
  /***** INTERFACES ****/
  App.Boot -> MainC.Boot;

  App.Leds -> LedsC;
  App.Timer0 -> TimerMilliC0;
  App.Timer1 -> TimerMilliC1;
  App.AMSend -> AMSenderC;
  App.Receive -> AMReceiverC;
  App.AMControl -> ActiveMessageC;
  App.Packet -> AMSenderC;
}
