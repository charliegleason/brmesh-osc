import threading
import subprocess
from typing import List, Dict, Union
from gi.repository import Gio, GLib

bus_type = Gio.BusType.SYSTEM
bus_name = 'org.bluez'

object_path = '/org/bluez/hci0'
interface_name = 'org.bluez.Adapter1'

adapter_interface = 'org.bluez.Adapter1'
adapter_path = '/org/bluez/hci0'

ble_adv_interface = 'org.bluez.LEAdvertisingManager1'

my_key = [0x8c, 0x89, 0x45, 0x94]        # See README how to get your secret key
#my_key = [0x5e, 0x36, 0x7b, 0xc4]        # See README how to get your secret key
default_key = [0x5e, 0x36, 0x7b, 0xc4]   
DEFAULT_BLE_FASTCON_ADDRESS = [0xC1, 0xC2, 0xC3]
BLE_CMD_RETRY_CNT = 1
BLE_CMD_ADVERTISE_LENGTH = 3000
SEND_COUNT = 1
SEND_SEQ = 0

# TODO: use GetManagedObjects to discover Bluetooth interfaces 

def _build_variant2(name, py_value):
        s_data = GLib.VariantDict.new()
        for key, value in py_value.items():
            gvalue = GLib.Variant('ay', value)
            s_data.insert_value(key, gvalue)
        return s_data.end()


introspection_xml = """
    <!DOCTYPE node PUBLIC
    "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
    "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
    <node>
        <interface name="org.bluez.LEAdvertisement1">
            <method name="Release"/>
            <property name="Type" type="s" access="read"/>
            <property name="ServiceUUIDs" type="as" access="readwrite"/>
            <property name="ManufacturerData" type="a{sv}" access="readwrite"/>
            <property name="SolicitUUIDs" type="as" access="readwrite"/>
            <property name="ServiceData" type="a{sv}" access="readwrite"/>
            <property name="Includes" type="as" access="readwrite"/>
            <property name="LocalName" type="s" access="readwrite"/>
            <property name="Appearance" type="q" access="readwrite"/>
            <property name="Duration" type="q" access="readwrite"/>
            <property name="Timeout" type="q" access="readwrite"/>
        </interface>
    </node>
    """


class Advertisement:
    def __init__(self, advertisement_id : int, advertisement_type : str):
        self._Type =  'peripheral'
        self._ServiceUUIDs = []
        self._ManufacturerData = {}
        self._SolicitUUIDs = []
        self._ServiceData = {}
        self._Data = None                   
        self._Discoverable = True
        self._DiscoverableTimeout = None    
        self._Includes = []
        self._LocalName = None
        self._Appearance = None
        self._Duration = None
        self._Timeout = None
        self._SecondaryChannel = None
        self._MinInterval = 0x0800
        self._MaxInterval = 0x0800
        self._TxPower = None 

        self.interface_info = Gio.DBusNodeInfo.new_for_xml(introspection_xml).interfaces[0]
        #self.interface_info.cache_build() # we're not modifying this, so we can use a cache to speed up `lookup_property`, etc.

        self.path = '/org/bluez/advertisement{0:04d}'.format(advertisement_id)
        print(self.path)

        self.connection = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        self.connection.register_object(self.path, self.interface_info, 
                                        self.on_method_call, 
                                        self.on_get_property, 
                                        self.on_set_property)

        self._thread = None
        self._mainloop = GLib.MainLoop()

    def _publish(self):
        self._mainloop.run()

    def start(self):
        self._thread = threading.Thread(target=self._publish)
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        self._mainloop.quit()

    def Release(self):
        print("Released")

    def on_method_call(self, connection: Gio.DBusConnection, sender: str, object_path: str, 
                       interface_name: str, method_name: str, params: GLib.Variant, 
                       invocation: Gio.DBusMethodInvocation):
        if method_name == 'Release':
            self.Release()
            return None
        else:
            return None


    def on_get_property(self, connection: Gio.DBusConnection, sender: str, object: str, iface: str, 
                        name: str):
        py_value = self.__getattribute__('_' + name)
        #logger.debug('prop_getter, %s, %s, %s, %s, %s',
        #             connection, sender, object, iface, name)
        #py_value = self.__getattribute__(name)
        signature = self.interface_info.lookup_property(name).signature
        if 'v' in signature:
            print('py_value', py_value)
            if isinstance(py_value, (list, dict)):
                dbus_value = _build_variant2(name, py_value)
            else:
                dbus_value = py_value
            print('dbus_value', dbus_value)
            return dbus_value
        if py_value:
            return GLib.Variant(signature, py_value)
        return None
        #property_ = self.interface_info.lookup_property(name)
        #signature = property_.signature
        ##flags = property_.flags
        #if py_value:
        #    print(py_value)
        #    #return py_value
        #    if 'v' in signature:
        #        dbus_value = GLib.VariantDict.new()
        #        for key, value in py_value.unpack().items():
        #            print(bytes(key), value, signature)
        #            dbus_value.insert_value(str(key), GLib.Variant('ay', value))
        #        return dbus_value
        #    else:
        #        return GLib.Variant(signature, py_value)
        #else:
        #    return None


    def on_set_property(self, connection: Gio.DBusConnection, sender: str, object: str, iface: str,
                        name: str, value: GLib.Variant):
        property_ = self.interface_info.lookup_property(name)
        flags = property_.flags

        if (property_.flags == Gio.DBusPropertyInfoFlags.WRITEABLE 
            or property_.flags == Gio.DBusPropertyInfoFlags.NONE):
            self._properties[name] = value.unpack()
            return True
        else:
            return False

    @property
    def type_(self):
        return self._Type
    
    @property
    def service_uuids(self):
        return self._ServiceUUIDs.unpack()
    
    @service_uuids.setter
    def service_uuids(self, uuid : List[str]) -> None:
        self._ServiceUUIDs = GLib.Variant('as', uuid)

    @property
    def manufacturer_data(self):
        return self._ManufacturerData.unpack()
    
    @manufacturer_data.setter
    def manufacturer_data(self, manufacturer_data: Dict[int, List[int]]) -> None:
        m_data = GLib.VariantBuilder(GLib.VariantType.new('a{qv}'))
        for key, value in manufacturer_data.items():
            g_key = GLib.Variant.new_uint16(key)
            g_value = GLib.Variant('ay', value)
            g_var = GLib.Variant.new_variant(g_value)
            g_dict = GLib.Variant.new_dict_entry(g_key, g_var)
            m_data.add_value(g_dict)
        self._ManufacturerData = m_data.end()

    @property
    def solicit_uuids(self):
        return self._SolicitUUIDs.unpack()
    
    @solicit_uuids.setter
    def solicit_uuids(self, data: List[str]) -> None:
        self._SolicitUUIDs = GLib.Variant('as', data)

    @property
    def service_data(self):
        return self._ServiceData.unpack()
    
    @service_data.setter
    def service_data(self, service_data):
        self._ServiceData = {key: GLib.Variant('ay', value) for key, value in service_data.items()}

    @property
    def local_name(self) -> Union[str, None]:
        try:
            return self._LocalName.unpack()
        except AttributeError:
            return None

    @local_name.setter
    def local_name(self, name: Union[str, None]) -> None:
        if name:
            self._LocalName = GLib.Variant.new_string(name)
        else:
            self._LocalName = None

    @property
    def appearance(self):
        return self._Appearance.unpack()

    @appearance.setter
    def appearance(self, appearance: int) -> None:
        if appearance:
            self._Appearance = GLib.Variant.new_uint16(appearance)
        else:
            self._Appearance = None


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
        print("Ooops! use_22_data")
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
        body[j] = default_key[j & 3] ^ body[j]

    for j in range(12):
        body[4 + j] = my_key[j & 3] ^ body[4 + j]

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
    
    print("")
    print("get_rf_payload")
    print("------------------------")
    print("addr:", bytes(addr).hex())
    print("data:", bytes(data).hex())

    # reverse copy the address
    for i in range(len(addr)):
        resultbuf[data_offset + len(addr) - i - 1] = addr[i]

    resultbuf[data_offset + len(addr):data_offset + len(addr) + len(data)] = data[:]

    for i in range(inverse_offset, inverse_offset + len(addr) + 3):
        resultbuf[i] = reverse_8(resultbuf[i])

    print("inverse_offset:", inverse_offset)
    print("inverse_offset addr.len + 3:", (inverse_offset + len(addr) + 3))

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
    print("Reached single_control: ", str(addr))
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
    print("Adv-Cmd          : btmgmt add-adv -d 02011a1bfff0ff" + bytes(ble_adv_cmd).hex() + " 1")
    return ble_adv_cmd


def bluez_proxy(object_path, interface, bus_type=Gio.BusType.SYSTEM):
    """Create a BlueZ proxy object"""
    return Gio.DBusProxy.new_for_bus_sync(
        bus_type=bus_type,
        flags=Gio.DBusProxyFlags.NONE,
        info=None,
        name='org.bluez',
        object_path=object_path,
        interface_name=interface,
        cancellable=None
    )


def setOnOff(id, key, on, brightness):
    print("brightness:", str(brightness))

    command = [0] * 1
    command[0] = 0

    if on:
        command[0] = 128 + (int(brightness) & 127)

    return single_control(id, key, command, 0)


def Brightness(id, key, on, brightness):
    command = [0] * 1
    command[0] = 0

    if on:
        command[0] = int(brightness) & 127

    return single_control(id, key, command, 0)
    # single_control(id, key, command, 0)


def WarmWhite(id, key, on, brightness, i5, i6):
    command = [0] * 6
    command[0] = 0
    command[4] = i5 & 0xFF
    command[5] = i6 & 0xFF

    if on:
        command[0] = 128 + (int(brightness) & 127)

    return single_control(id, key, command, 0)


def Colored(id, key, on, brightness, r, g, b, abs):
    command = [0] * 6
    color_normalization = 1
    command[0] = 0

    if on:
        command[0] += 128
    command[0] += int(brightness) & 127

    if not abs:
        color_normalization = 255.0 / (r + g + b)

    command[1] = int((b * color_normalization) & 0xFF)
    command[2] = int((r * color_normalization) & 0xFF)
    command[3] = int((g * color_normalization) & 0xFF)

    return single_control(id, key, command, 0)


def main():
    pass


if __name__ == '__main__':
    main()
    

#adapter_props_proxy = Gio.DBusProxy.new_for_bus_sync(bus_type=bus_type,
#                                                     flags=Gio.DBusProxyFlags.NONE,
#                                                     info=None,
#                                                     name=bus_name,
#                                                     object_path=object_path,
#                                                     interface_name='org.freedesktop.DBus.Properties',
#                                                     cancellable=None)
#
#
#adapter_proxy = Gio.DBusProxy.new_for_bus_sync(bus_type=bus_type,
#                                               flags=Gio.DBusProxyFlags.NONE,
#                                               info=None,
#                                               name=bus_name,
#                                               object_path=object_path,
#                                               interface_name=adapter_interface,
#                                               cancellable=None)
#
#ble_adv_proxy = Gio.DBusProxy.new_for_bus_sync(bus_type=bus_type,
#                                               flags=Gio.DBusProxyFlags.NONE,
#                                               info=None,
#                                               name=bus_name,
#                                               object_path=object_path,
#                                               interface_name=ble_adv_interface,
#                                               cancellable=None)                                               
#all_props = adapter_props_proxy.GetAll('(s)', adapter_interface)
#print(all_props)
#
#powered = adapter_props_proxy.Get('(ss)', adapter_interface, 'Powered')
#print(powered)
#
## power off
#adapter_props_proxy.Set('(ssv)', adapter_interface, 'Powered', GLib.Variant.new_boolean(False))
#powered = adapter_props_proxy.Get('(ss)', adapter_interface, 'Powered')
#print(powered)
#
#time.sleep(0.5)
#
## power on
#adapter_props_proxy.Set('(ssv)', adapter_interface, 'Powered', GLib.Variant.new_boolean(True))
#powered = adapter_props_proxy.Get('(ss)', adapter_interface, 'Powered')
#print(powered)

