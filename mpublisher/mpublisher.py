# -*- coding: utf-8 -*-
#
# mpublisher.py - Avahi/mDNS name publisher.
#
# Copyright (c) 2014, SAPO
#


__all__ = ["AvahiPublisher"]


import logging
import dbus
import netifaces
import socket
import struct
from . import _avahi as avahi

log = logging.getLogger("mdns-publisher.%s" % __name__)


class AvahiPublisher(object):
    """Publish mDNS records to Avahi, using D-BUS."""

    def __init__(self, record_ttl=60):
        """Initialize the publisher with fixed record TTL value (in seconds)."""

        self.record_ttl = record_ttl
        self.published = {}

        self.bus = dbus.SystemBus(private=True)

        path_server_proxy = self.bus.get_object(avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER)
        self.server = dbus.Interface(path_server_proxy, avahi.DBUS_INTERFACE_SERVER)

        self.hostname = self.server.GetHostNameFqdn()

        log.debug("Avahi mDNS publisher for: %s", self.hostname)


    def __del__(self):
        """Remove all published records from mDNS."""

        try:
            for group in self.published.values():
                group.Reset()

            self.bus.close()
        except dbus.exceptions.DBusException:  # ...don't really care, cleaning up.
            pass


    def _fqdn_to_rdata(self, fqdn):
        """Convert an FQDN into the mDNS data record format."""

        data = []
        for part in fqdn.encode("ascii").split(b"."):
            if part:
                data.append(chr(len(part)).encode("ascii"))
                data.append(part)

        return b"".join(data) + b"\0"


    def count(self):
        """Return the number of records currently being published."""

        return len(self.published)


    def resolve(self, name):
        """Lookup the current owner for "name", using mDNS."""

        try:
            # TODO: Find out if it's possible to manipulate (shorten) the timeout...
            response = self.server.ResolveHostName(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC,
                                                   name.encode("ascii"), avahi.PROTO_UNSPEC,
                                                   dbus.UInt32(0))
            return response[2]
        except (NameError, dbus.exceptions.DBusException):
            return None


    def publish(self, name, force=False, dns_type='CNAME'):
        """Publish a record."""

        if not force:
            # Unfortunately, this takes a few seconds in the expected case...
            log.info("Checking for '%s' availability...", name)
            current_owner = self.resolve(name)

            if current_owner:
                if current_owner != self.hostname:
                    log.error("DNS entry '%s' is already owned by '%s'", name, current_owner)
                    return False

                # We may have discovered ourselves, but this is not a fatal problem...
                log.warning("DNS entry '%s' is already being published by this machine", name)

        entry_group_proxy = self.bus.get_object(avahi.DBUS_NAME, self.server.EntryGroupNew())
        group = dbus.Interface(entry_group_proxy, avahi.DBUS_INTERFACE_ENTRY_GROUP)

        if dns_type == 'CNAME':
            """Publish a CNAME record."""
            group.AddRecord(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, dbus.UInt32(0), name.encode("ascii"),
                            avahi.DNS_CLASS_IN, avahi.DNS_TYPE_CNAME, self.record_ttl,
                            self._fqdn_to_rdata(self.hostname))
        elif dns_type == 'A':
            """Publish an A record."""
            # We can't tell which interface is correct, but we can do the same thing avahi does,
            # which is add a record for _every_ interface!
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if not netifaces.AF_INET in addrs:
                    continue
                for addr_info in addrs[netifaces.AF_INET]:
                    ip_addr = addr_info.get('addr')
                    if ip_addr:
                        break
                else:
                    continue
                ifindex = socket.if_nametoindex(iface)
                log.debug(f"Found interface: {iface}, IP: {ip_addr}, index {ifindex}")
                parts = [int(x) for x in ip_addr.split('.')]
                raw_ip = struct.pack('BBBB', *parts)

                group.AddRecord(ifindex, avahi.PROTO_INET, dbus.UInt32(avahi.PUBLISH_ALLOW_MULTIPLE),
                                name.encode("ascii"), avahi.DNS_CLASS_IN, avahi.DNS_TYPE_A, self.record_ttl,
                                raw_ip)
        else:
            raise ValueError(f"Unexpected dns_type={dns_type}")

        group.Commit()
        self.published[name] = group

        return True

    def publish_cname(self, cname, force=False):
        return self.publish(cname, force, dns_type='CNAME')

    def publish_a(self, name, force=False):
        return self.publish(name, force, dns_type='A')

    def unpublish(self, name):
        """Remove a published record from mDNS."""

        self.published[name].Reset()
        del self.published[name]


    def available(self):
        """Check if the connection to Avahi is still available."""

        try:
            self.server.GetVersionString()
        except dbus.exceptions.DBusException as e:  # ...don't really care, just checking.
            log.debug("Avahi is unavailable: %s", e.get_dbus_name())
            return False

        return True


# vim: set expandtab ts=4 sw=4:
