import logging
import threading
from typing import List, Dict, Union

from gi.repository import Gio, GLib, GObject

# DBus Information
bus_type = Gio.BusType.SYSTEM
BLUEZ_NAME = 'org.bluez'
ADAPTER_PATH = '/org/bluez/hci0'
PROP_IFACE = 'org.freedesktop.DBus.Properties'
ADAPTER_IFACE = 'org.bluez.Adapter1'
DEVICE_IFACE = 'org.bluez.Device1'
# BlueZ DBus Advertising Manager Interface
LE_ADVERTISING_MANAGER_IFACE = 'org.bluez.LEAdvertisingManager1'
# BlueZ DBus Advertisement Interface
LE_ADVERTISEMENT_IFACE = 'org.bluez.LEAdvertisement1'

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('advert')

introspection_xml = """
    <!DOCTYPE node PUBLIC
    "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
    "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
    <node>
        <interface name="org.bluez.LEAdvertisement1">
            <method name="Release"/>
            <property name="Type" type="s" access="readwrite"/>
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


def _build_variant(name, py_data):
    """
    convert python native data types to D-Bus variant types by looking up
    their type expected for that key.
    """
    type_lookup = {'Address': 's',
                   'AddressType': 's',
                   'Name': 's',
                   'Icon': 's',
                   'Class': 'u',
                   'Appearance': 'q',
                   'Alias': 's',
                   'Paired': 'b',
                   'Trusted': 'b',
                   'Blocked': 'b',
                   'LegacyPairing': 'b',
                   'RSSI': 'n',
                   'Connected': 'b',
                   'UUIDs': 'as',
                   'Adapter': 'o',
                   'ManufacturerData': 'a{qay}',
                   'ServiceData': 'a{say}',
                   'TxPower': 'n',
                   'ServicesResolved': 'b',
                   'WakeAllowed': 'b',
                   'Modalias': 's',
                   'AdvertisingFlags': 'ay',
                   'AdvertisingData': 'a{yay}',
                   'Powered': 'b',
                   'Discoverable': 'b',
                   'Pairable': 'b',
                   'PairableTimeout': 'u',
                   'DiscoverableTimeout': 'u',
                   'Discovering': 'b',
                   'Roles': 'as',
                   'ExperimentalFeatures': 'as',
                   }
    logger.debug('Create variant(%s, %s)', name, py_data)
    return GLib.Variant(type_lookup[name], py_data)


def _build_variant2(name, py_value):
        s_data = GLib.VariantDict.new()
        for key, value in py_value.items():
            gvalue = GLib.Variant('ay', value)
            s_data.insert_value(key, gvalue)
        return s_data.end()


def bluez_proxy(object_path, interface):
    """Create a BlueZ proxy object"""
    return Gio.DBusProxy.new_for_bus_sync(
        bus_type=bus_type,
        flags=Gio.DBusProxyFlags.NONE,
        info=None,
        name=BLUEZ_NAME,
        object_path=object_path,
        interface_name=interface,
        cancellable=None)


class DbusService:

    def __init__(self, introspection_xml, publish_path,
                 own_name=None, sys_bus=True):
        self.node_info = Gio.DBusNodeInfo.new_for_xml(introspection_xml).interfaces[0]
        method_outargs = {}
        method_inargs = {}
        property_sig = {}
        for method in self.node_info.methods:
            method_outargs[method.name] = '(' + ''.join(
                [arg.signature
                 for arg in method.out_args]) + ')'
            method_inargs[method.name] = tuple(arg.signature
                                               for arg in method.in_args)
        self.method_inargs = method_inargs
        self.method_outargs = method_outargs
        if sys_bus:
            self.con = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        else:
            self.con = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        if own_name:
            Gio.bus_own_name_on_connection(connection=self.con,
                                           name=own_name,
                                           flags=Gio.BusNameOwnerFlags.NONE,
                                           name_acquired_closure=None,
                                           name_lost_closure=None)
        self.con.register_object(
            publish_path,
            self.node_info,
            self.handle_method_call,
            self.prop_getter,
            self.prop_setter)

    def handle_method_call(self,
                           connection: Gio.DBusConnection,
                           sender: str,
                           object_path: str,
                           interface_name: str,
                           method_name: str,
                           params: GLib.Variant,
                           invocation: Gio.DBusMethodInvocation
                           ):
        """
        This is the top-level function that handles method calls to
        the server.
        """
        args = list(params.unpack())
        for i, sig in enumerate(self.method_inargs[method_name]):
            # Check if there is a Unix file descriptor  in the signature
            if sig == 'h':
                msg = invocation.get_message()
                fd_list = msg.get_unix_fd_list()
                args[i] = fd_list.get(args[i])
        # Get the method from the Python class
        func = self.__getattribute__(method_name)
        result = func(*args)
        if result is None:
            result = ()
        else:
            result = (result,)
        outargs = ''.join([_.signature
                           for _ in invocation.get_method_info().out_args])
        send_result = GLib.Variant(f'({outargs})', result)
        logger.debug('Method Call result: %s', repr(send_result))
        invocation.return_value(send_result)

    def prop_getter(self,
                    connection: Gio.DBusConnection,
                    sender: str,
                    object: str,
                    iface: str,
                    name: str):
        """Mehtod for moving properties from Python Class to D-Bus"""
        logger.debug('prop_getter, %s, %s, %s, %s, %s',
                     connection, sender, object, iface, name)
        py_value = self.__getattribute__(name)
        signature = self.node_info.lookup_property(name).signature
        if 'v' in signature:
            print('py_value', py_value)
            dbus_value = _build_variant2(name, py_value)
            print('dbus_value', dbus_value)
            return dbus_value
        if py_value:
            return GLib.Variant(signature, py_value)
        return None

    def prop_setter(self,
                    connection: Gio.DBusConnection,
                    sender: str,
                    object: str,
                    iface: str,
                    name: str,
                    value: GLib.Variant):
        """Method for moving properties between D-Bus and Python Class"""
        logger.debug('prop_setter %s, %s, %s, %s, %s, %s',
                     connection, sender, object, iface, name, value)
        # x_value = GLib.Variant('as', ['test'])
        self.__setattr__(name, value.unpack())
        return True


class Advertisement(DbusService):
    """Advertisement data"""

    def __init__(self, advert_id, ad_type):
        # Setup D-Bus object paths
        self.path = '/org/bluez/advertisement{0:04d}'.format(advert_id)
        super().__init__(introspection_xml=introspection_xml,
                         publish_path=self.path)

        self.Type = ad_type
        self.ServiceUUIDs = []
        self.ManufacturerData = {}
        self.SolicitUUIDs = []
        self.ServiceData = {}
        self.Includes = []
        self.LocalName = None
        self.Appearance = None
        self.Duration = None
        self.Timeout = None

        self.mainloop = GLib.MainLoop()
        self._ad_thread = None

    def _publish(self):
        self.mainloop.run()

    def start(self):
        """Start GLib event loop"""
        self._ad_thread = threading.Thread(target=self._publish)
        self._ad_thread.daemon = True
        self._ad_thread.start()

    def stop(self):
        """Stop GLib event loop"""
        self.mainloop.quit()

    def Release(self):  # pylint: disable=invalid-name
        """
        This method gets called when the service daemon
        removes the Advertisement. A client can use it to do
        cleanup tasks. There is no need to call
        UnregisterAdvertisement because when this method gets
        called it has already been unregistered.
        :return:
        """
        pass

    @property
    def service_UUIDs(self):  # pylint: disable=invalid-name
        """List of UUIDs that represent available services."""
        return self.ServiceUUIDs.unpack()

    @service_UUIDs.setter
    def service_UUIDs(self, UUID):  # pylint: disable=invalid-name
        self.ServiceUUIDs = GLib.Variant('as', UUID)

    @property
    def manufacturer_data(self, company_id, data):
        """Manufacturer Data to be broadcast"""
        return self.ManufacturerData.unpack()

    @manufacturer_data.setter
    def manufacturer_data(self, manufacturer_data: Dict[int, List[int]]) -> None:
        """Manufacturer Data to be broadcast"""
        m_data = GLib.VariantBuilder(GLib.VariantType.new('a{qv}'))
        for key, value in manufacturer_data.items():
            g_key = GLib.Variant.new_uint16(key)
            g_value = GLib.Variant('ay', value)
            g_var = GLib.Variant.new_variant(g_value)
            g_dict = GLib.Variant.new_dict_entry(g_key, g_var)
            m_data.add_value(g_dict)
        self.ManufacturerData = m_data.end()

    @property
    def solicit_UUIDs(self):  # pylint: disable=invalid-name
        """UUIDs to include in "Service Solicitation" Advertisement Data"""
        return self.SolicitUUIDs.unpack()

    @solicit_UUIDs.setter
    def solicit_UUIDs(self, data: List[str]) -> None:
        self.SolicitUUIDs = GLib.Variant('as', data)

    @property
    def service_data(self):
        """Service Data to be broadcast"""
        return self.ServiceData.unpack()

    @service_data.setter
    def service_data(self, service_data):
        s_data = {}
        for key, value in service_data.items():
            gvalue = GLib.Variant('ay', value)
            s_data[key] = gvalue
        self.ServiceData = s_data

    @property
    def local_name(self) -> Union[str, None]:
        """Local name of the device included in Advertisement."""
        if self.LocalName:
            return self.LocalName.unpack()
        return None

    @local_name.setter
    def local_name(self, name: Union[str, None]):
        if name:
            self.LocalName = GLib.Variant.new_string(name)
        else:
            self.LocalName = None

    @property
    def appearance(self) -> int:
        """Appearance to be used in the advertising report."""
        return self.Appearance

    @appearance.setter
    def appearance(self, appearance: int) -> None:
        if appearance:
            self.Appearance = GLib.Variant.new_uint16(appearance)
        else:
            self.Appearance = None


def main():
    # Simple test
    beacon = Advertisement(1, 'peripheral')
    beacon.service_UUIDs = ['FEAA']
    beacon.service_data = {'FEAA': [0x10, 0x08, 0x03, 0x75, 0x6B,
                                    0x42, 0x61, 0x7A, 0x2e, 0x67,
                                    0x69, 0x74, 0x68, 0x75, 0x62,
                                    0x2E, 0x69, 0x6F]}
    beacon.start()
    #ad_manager = bluez_proxy(ADAPTER_PATH, LE_ADVERTISING_MANAGER_IFACE)
    #ad_manager.RegisterAdvertisement('(oa{sv})', beacon.path, {})
    mainloop = GLib.MainLoop()
    mainloop.run()


if __name__ == '__main__':
    main()