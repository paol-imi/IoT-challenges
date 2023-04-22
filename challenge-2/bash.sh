CHANNEL_ID=2111181
CLIENT_ID=
USERNAME=
PASSWORD=

mosquitto_pub -h "mqtt3.thingspeak.com" -p 1883 -u "$USERNAME" -P "$PASSWORD" -i "$CLIENT_ID" -t "channels/$CHANNEL_ID/publish" -m "field1=XX&field2=YY&status=MQTTPUBLISH"
