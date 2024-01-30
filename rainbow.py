import json
import colorsys
import time
import math
import paho.mqtt.client as mqtt


def on_mqtt_connect(client, userdata, flags, rc):
    pass

def main():
    client = mqtt.Client()
    client.on_connect = on_mqtt_connect
    client.connect("127.0.0.1", 1883, 60)

    color = (0.0, 1.0, 1.0) # HSV
    while True:
        r, g, b = colorsys.hsv_to_rgb(*color)
        print(f"RGB: {int(127 * r)} {int(127 * g)} {int(127 * b)}")
        brightness = 10
        payload = json.dumps({"brightness": brightness, 
                              "color": {"r": int(127 * r), "g": int(127 * g), "b": int(127 * b)}})
        client.publish('brMesh/2/set', payload)
        color = (math.fmod(color[0] + 0.002, 1.0), 1.0, 1.0)
        time.sleep(0.03)


if __name__ == '__main__':
    main()