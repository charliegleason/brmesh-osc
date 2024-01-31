import colorsys
import time
import math
from pythonosc.udp_client import SimpleUDPClient


def main():
    addr = '127.0.0.1'
    port = 10000
    client = SimpleUDPClient(addr, port)

    color = (0.0, 1.0, 1.0) # HSV
    while True:
        r, g, b = [int(127 * v) for v in colorsys.hsv_to_rgb(*color)]
        brightness = 10
        print(f"RGB: {r} {g} {b}")

        #client.send_message("/brmesh/1/brightness", brightness)
        #client.send_message("/brmesh/2/brightness", brightness)
        client.send_message("/brmesh/2/rgba", (r, g, b, brightness))
        client.send_message("/brmesh/3/rgba", (r, g, b, brightness))
        client.send_message("/brmesh/4/rgba", (r, g, b, brightness))

        color = (math.fmod(color[0] + 0.002, 1.0), 1.0, 1.0)
        #time.sleep(0.03)
        time.sleep(0.03/15)
        #time.sleep(0.5)


if __name__ == '__main__':
    main()