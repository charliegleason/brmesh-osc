import json
import colorsys
import time
import math
import paho.mqtt.client as mqtt
from pythonosc.udp_client import SimpleUDPClient


def main():
    addr = '127.0.0.1'
    port = 5005
    client = SimpleUDPClient(addr, port)

    color = (0.0, 1.0, 1.0) # HSV
    while True:
        r, g, b = [int(127 * v) for v in colorsys.hsv_to_rgb(*color)]
        brightness = 10
        print(f"RGB: {r} {g} {b}")

        client.send_message("/brmesh/1/brightness", brightness)
        #client.send_message("/brmesh/2/brightness", brightness)
        client.send_message("/brmesh/1/rgb", (r, g, b))

        color = (math.fmod(color[0] + 0.002, 1.0), 1.0, 1.0)
        time.sleep(0.03)
        #time.sleep(0.5)


if __name__ == '__main__':
    main()