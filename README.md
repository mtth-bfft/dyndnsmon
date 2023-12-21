# dyndnsmon

This standalone application for Microsoft Windows Server shows you live DNS dynamic update requests which failed. It was designed to assist system administrators with migrating Microsoft DNS zones from "non-secure" to "secure" mode.

If your DNS zone is still in non-secure mode (which allows everyone to update all records anonymously), you *definitely* want to restrict updates to authenticated and authorized users only, at least if they are your domain main DNS zone. Otherwise, all users can compromise your Active Directory forest with public tools.

![Properties of DNS zones, with dynamic update restriction highlighted](/screenshots/nonsecure_mode.png)

No "audit mode" exists before switching to secure-only updates: clients (including Windows and Windows Server) usually try an unauthenticated request first, and only try an authenticated one if that fails. Thus, an audit mode would constantly fire false warnings.

This tool will give you a real time view of failed dynamic updates as a best effort, so that you can build an inventory of DHCP clients that do not support secure dynamic updates. It hooks into trace logs built into the Microsoft DNS server, and, for each failed dynamic update, it will query all DNS servers for that zone and warn you if the record hasn't been updated anywhere.

## Usage

1. Download the latest release from [the Releases page](https://github.com/mtth-bfft/dyndnsmon/releases)
2. Push that executable and run it as administrator on each DNS server (this usually means all your domain controllers, if your DNS zones are AD-integrated). It does not need any installation, you can copy-paste the .exe and remove it when done. The output should not show any failing dynamic update at this point
3. Block insecure dynamic updates, zone by zone: in dnsmgmt.msc > right-click on the zone > Properties > General > Dynamic updates : Secure only
4. Watch failed updates as they arrive, if any. These are from Unix or insecure appliances which do not support secure dynamic updates

![Example of failed dynamic update](/screenshots/failed_update.png)

5. Fix failed updates by manually modifying DNS records, if they need to be fixed right away
6. The long-term fix is to migrate these endpoints so they support secure dynamic updates, or to move them to static addresses instead of DHCP

## Contributing

This tool is still in an early test phase. Should you find any bug, please open an issue describing what DNS record caused the failure (or ideally a PCAP network trace of the request).

If features are missing which would make migrating DNS zones to secure updates easier, you can also open an issue and I will work on them if the development cost is reasonable.

## License

This software is offered under the MIT License, without any warranty: it only gives you a best-effort help, and I do not take any responsibility if you break your information system by migrating DNS zones while using this tool. DNS parsing code is embedded under a specific license, see `dns/`.

This tool was heavily developped and tested using [Scapy](https://scapy.net/).
