import argparse
from itertools import pairwise
from subprocess import Popen, PIPE
from typing import List, Dict, Union
import paho.mqtt.client as mqtt
import json

#key = [0x8c, 0x89, 0x45, 0x94]        # See README how to get your secret key
DEFAULT_KEY = [0x5e, 0x36, 0x7b, 0xc4]   
DEFAULT_BLE_FASTCON_ADDRESS = [0xC1, 0xC2, 0xC3]
BLE_CMD_RETRY_CNT = 1
BLE_CMD_ADVERTISE_LENGTH = 3000
SEND_COUNT = 1
SEND_SEQ = 0


def reverse_8(d):
    result = 0
    for k in range(8):
        result |= ((d >> k) & 1) << (7 - k)
    return result


def reverse_16(d):
    result = 0
    for k in range(16):
        result |= ((d >> k) & 1) << (15 - k)
    return result


def crc16(addr, data):
    crc = 0xFFFF

    for i in range(len(addr) - 1, -1, -1):
        crc ^= addr[i] << 8
        for _ in range(4):
            tmp = crc << 1

            if crc & 0x8000 != 0:
                tmp ^= 0x1021

            crc = tmp << 1
            if tmp & 0x8000 != 0:
                crc ^= 0x1021

    for i in range(len(data)):
        crc ^= reverse_8(data[i]) << 8
        for _ in range(4):
            tmp = crc << 1

            if crc & 0x8000 != 0:
                tmp ^= 0x1021

            crc = tmp << 1
            if tmp & 0x8000 != 0:
                crc ^= 0x1021

    crc = (~reverse_16(crc)) & 0xFFFF
    return crc


def get_payload_with_inner_retry(i, data, i2, key, forward, use_22_data):
    global SEND_COUNT, SEND_SEQ
    SEND_COUNT += 1
    SEND_SEQ = SEND_COUNT & 0xff
    safe_key = 0xff
    if key[0] == 0 or key[1] == 0 or key[2] == 0 or key[3] == 0:
        pass
    else:
        safe_key = key[3]
    if use_22_data:
        #print("Ooops! use_22_data")
        return -1
    else:
        return package_ble_fastcon_body(i, i2, SEND_SEQ, safe_key, forward, data, key)


def package_ble_fastcon_body(i, i2, sequence, safe_key, forward, data, key):
    body = []
    body.append((i2 & 0b1111) | ((i & 0b111) << 4) | ((forward & 0xff) << 7))
    body.append(sequence & 0xff)
    body.append(safe_key)
    body.append(0)  # checksum (temporary placeholder)

    body += data

    checksum = 0
    for j in range(len(body)):
        if j == 3:
            continue
        checksum = (checksum + body[j]) & 0xff

    body[3] = checksum

    # pad payload with zeros
    for j in range(12 - len(data)):
        body.append(0)

    for j in range(4):
        body[j] = DEFAULT_KEY[j & 3] ^ body[j]

    for j in range(12):
        body[4 + j] = key[j & 3] ^ body[4 + j]

    return body


def get_rf_payload(addr, data):
    data_offset = 0x12
    inverse_offset = 0x0f
    result_data_size = data_offset + len(addr) + len(data)
    resultbuf = [0] * (result_data_size + 2)

    # some hardcoded values
    resultbuf[0x0f] = 0x71
    resultbuf[0x10] = 0x0f
    resultbuf[0x11] = 0x55
    
    #print("")
    #print("get_rf_payload")
    #print("------------------------")
    #print("addr:", bytes(addr).hex())
    #print("data:", bytes(data).hex())

    # reverse copy the address
    for i in range(len(addr)):
        resultbuf[data_offset + len(addr) - i - 1] = addr[i]

    resultbuf[data_offset + len(addr):data_offset + len(addr) + len(data)] = data[:]

    for i in range(inverse_offset, inverse_offset + len(addr) + 3):
        resultbuf[i] = reverse_8(resultbuf[i])

    #print("inverse_offset:", inverse_offset)
    #print("inverse_offset addr.len + 3:", (inverse_offset + len(addr) + 3))

    crc = crc16(addr, data)
    resultbuf[result_data_size] = crc & 0xFF
    resultbuf[result_data_size + 1] = (crc >> 8) & 0xFF
    return resultbuf


def whitening_init(val, ctx): 
    v0 = [(val >> 5) & 1, (val >> 4) & 1, (val >> 3) & 1, (val >> 2) & 1]
    ctx[0] = 1
    ctx[1] = v0[0]
    ctx[2] = v0[1]
    ctx[3] = v0[2]
    ctx[4] = v0[3]
    ctx[5] = (val >> 1) & 1
    ctx[6] = val & 1


def whitening_encode(data, ctx):
    result = list(data)
    for i in range(len(result)):
        varC = ctx[3]
        var14 = ctx[5]
        var18 = ctx[6]
        var10 = ctx[4]
        var8 = var14 ^ ctx[2]
        var4 = var10 ^ ctx[1]
        _var = var18 ^ varC
        var0 = _var ^ ctx[0]

        c = result[i]
        result[i] = ((c & 0x80) ^ ((var8 ^ var18) << 7)) & 0xFF
        result[i] += ((c & 0x40) ^ (var0 << 6)) & 0xFF
        result[i] += ((c & 0x20) ^ (var4 << 5)) & 0xFF
        result[i] += ((c & 0x10) ^ (var8 << 4)) & 0xFF
        result[i] += ((c & 0x08) ^ (_var << 3)) & 0xFF
        result[i] += ((c & 0x04) ^ (var10 << 2)) & 0xFF
        result[i] += ((c & 0x02) ^ (var14 << 1)) & 0xFF
        result[i] += ((c & 0x01) ^ (var18 << 0)) & 0xFF

        ctx[2] = var4
        ctx[3] = var8
        ctx[4] = var8 ^ varC
        ctx[5] = var0 ^ var10
        ctx[6] = var4 ^ var14
        ctx[0] = var8 ^ var18
        ctx[1] = var0

    return result    


def do_generate_command(i, data, key, _retry_count, _send_interval, forward, use_default_adapter, use_22_data, i2):

    i2_ = max(i2, 0)
    payload = get_payload_with_inner_retry(i, data, i2_, key, forward, use_22_data)

    payload = get_rf_payload(DEFAULT_BLE_FASTCON_ADDRESS, payload)

    whiteningContext = [0] * 7
    whitening_init(0x25, whiteningContext)
    payload = whitening_encode(payload, whiteningContext)
    payload = payload[0x0f:]
    return payload


def single_control(addr, key, data, delay):
    global mainloop
    # Implement your single_control function here
    # You can replace this function with your implementation to control the light
    #print("Reached single_control: ", str(addr))
    result = []
    result.append(2 | (((0xFFFFFFF & (len(data) + 1)) << 4) & 0xFF))
    result.append(addr & 0xFF)
    result += data

    ble_adv_data = [] #[0x02, 0x01, 0x1A, 0x1B, 0xFF, 0xF0, 0xFF]
    ble_adv_cmd = ble_adv_data + do_generate_command(5,
                                                    result,
                                                    key,
                                                    BLE_CMD_RETRY_CNT,
                                                    BLE_CMD_ADVERTISE_LENGTH,
                                                    True,  # forward?
                                                    True,  # use_default_adapter
                                                    (addr > 256) & 0xFF,  # use_22_data
                                                    (addr // 256) & 0xFF  # i2
                                                    )
    #ble_adv_cmd_btmgmt = "btmgmt add-adv -d 02011a1bfff0ff" + bytes(ble_adv_cmd).hex() + " 1"
    #print(f"Advertisement command: {ble_adv_cmd_btmgmt}")
    return ble_adv_cmd


def set_on_off(address, key, on, brightness):
    #print("brightness:", str(brightness))

    command = [0] * 1
    command[0] = 0

    if on:
        command[0] = 128 + (int(brightness) & 127)

    return single_control(address, key, command, 0)


def set_brightness(address, key, on, brightness):
    command = [0] * 1
    command[0] = 0

    if on:
        command[0] = int(brightness) & 127

    return single_control(address, key, command, 0)


def set_warm_white(address, key, on, brightness, i5, i6):
    command = [0] * 6
    command[0] = 0
    command[4] = i5 & 0xFF
    command[5] = i6 & 0xFF

    if on:
        command[0] = 128 + (int(brightness) & 127)

    return single_control(address, key, command, 0)


def set_color(address, key, on, brightness, r, g, b, abs_):
    command = [0] * 6
    color_normalization = 1
    command[0] = 0

    if on:
        command[0] += 128
    command[0] += int(brightness) & 127

    if not abs_:
        color_normalization = 255.0 / (r + g + b)

    command[1] = int(int(b * color_normalization) & 0xFF)
    command[2] = int(int(r * color_normalization) & 0xFF)
    command[3] = int(int(g * color_normalization) & 0xFF)

    return single_control(address, key, command, 0)


def make_add_adv_packet(controller_id, instance_id, flags, duration, timeout, 
                        adv_data_len, scan_rsp_len, adv_data, scan_rsp):
    """
    Command Code:		0x003e
	Controller Index:	<controller id>
	Command Parameters:	Instance (1 Octet)
				Flags (4 Octets)
				Duration (2 Octets)
				Timeout (2 Octets)
				Adv_Data_Len (1 Octet)
				Scan_Rsp_Len (1 Octet)
				Adv_Data (0-255 Octets)
				Scan_Rsp (0-255 Octets)
	Return Parameters:	Instance (1 Octet) 

    For more details, see https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/doc/mgmt-api.txt
    """
    command_code = 0x003e
    # TODO: make a raw Add Advertising packet and send it using a socket opened with btsocket.open()
    # (since the AddAdvertising command doesn't seem to work with btsocket.send())


def run_btmgmt_adv_command(shell_process, instance_id, command):
    shell_command = "add-adv -d 02011a1bfff0ff" + bytes(command).hex() + f" {instance_id}\n"
    shell_process.stdin.write(str.encode(shell_command))
    shell_process.stdin.flush()
    # TODO: read from stdout, and if there's an error, restart the bluetooth service
    #print(shell_process.stdout.readline())
    shell_process.stdout.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--addr', type=str, help="MQTT broker host IP address",  default='127.0.0.1')
    parser.add_argument('-p', '--port', type=int, help="MQTT broker host port", default='1883')
    parser.add_argument('-k', '--key', type=str,help="FastCon encryption key (8 bytes)", default='5e367bc4')
    args = parser.parse_args()

    addr = args.addr
    port = args.port
    key = [hex(int(f"{a}{b}", 16)) for a, b in pairwise(args.key)]

    global count
    count = 0

    # This might be the worst hack I've ever written
    processes = [Popen(['/usr/bin/bash', '-c', 'btmgmt'], stdin=PIPE, stdout=PIPE) for _ in range(60)]

    for process in processes:
        process.stdin.write(b'select hci0\n')
        process.stdin.flush()

    processes[0].stdin.write(b'power on\n')

    def on_mqtt_connect(client, userdata, flags, rc):
        print("Connected with result code " + str(rc))
        client.subscribe("brMesh/#")

    def on_mqtt_message(client, userdata, msg):
        topic = msg.topic
        payload = msg.payload

        if "/" in topic:
            topic_path = topic.split("/")

            if topic_path[0] == "brMesh":
                address = int(topic_path[1])

                if topic_path[2] == "set":
                    global count
                    brightness = 0
                    # Using the same instance ID will update an existing advertising instance.
                    # With multiple lights, this would be undesirable, since the advertisement for 
                    # a given light would be overridden by the advertisement for another. So, 
                    # using a different instance ID for each light allows them to be broadcast 
                    # simultaneously (or at least independently).
                    instance_id = address
                    payload = json.loads(payload.decode())

                    if "color" in payload:
                        r, g, b = (payload["color"]["r"], payload["color"]["g"], payload["color"]["b"])
                        if "brightness" in payload:
                            brightness = payload["brightness"]
                        command = set_color(address, key, 1, brightness, r, g, b, True)
                        run_btmgmt_adv_command(processes[count % len(processes)], instance_id, command)
                        count += 1
                    elif "brightness" in payload:
                        nb = payload["brightness"]
                        command = set_brightness(address, key, 1, nb)
                        run_btmgmt_adv_command(processes[count % len(processes)], instance_id, command)
                        count += 1
                    elif "color_temp" in payload:
                        if payload["color_temp"] == 500:
                            command = set_warm_white(address, key, 1, brightness, 127, 127)
                            run_btmgmt_adv_command(processes[count % len(processes)], instance_id, command)
                            count += 1
                    else:
                        if "state" in payload:
                            if payload["state"] == "ON":  # last state
                                command = set_on_off(address, key, 1, brightness)
                                run_btmgmt_adv_command(processes[count % len(processes)], instance_id, command)
                                count += 1
                            else:
                                command = set_on_off(address, key, 0, 0)
                                run_btmgmt_adv_command(processes[count % len(processes)], instance_id, command)
                                count += 1

    client = mqtt.Client()
    client.on_connect = on_mqtt_connect
    client.on_message = on_mqtt_message
    client.connect(addr, port, 60)
    client.loop_forever()

    process.stdin.close()
    process.wait()


if __name__ == '__main__':
    main()