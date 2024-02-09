import os
import re
import socket
import struct
import fcntl
import sys
import json

import base64
import requests

import xbmc
import xbmcaddon


__addon__      = xbmcaddon.Addon()
__setting__    = __addon__.getSetting
__addon_id__   = __addon__.getAddonInfo('id')
__addon_name__ = __addon__.getAddonInfo('name')
__localize__   = __addon__.getLocalizedString
__profile__    = __addon__.getAddonInfo('profile')


#system_idle = False


def read_value(item, default):
    try:
        value = int(__setting__(item))
    except ValueError:
        try:
            if __setting__(item).lower() == 'true' or __setting__(item).lower() == 'false':
                value = bool(__setting__(item).lower() == 'true')
            else:
                value = __setting__(item)
        except ValueError:
            value = default

    return value


def load_settings():
    global host_mac, host_ip, host_port
    global if_name, wait_time, wol_interval, wake_text
    global pvr_addon_id, pvr_addon_name
    global rpc_user, rpc_password, rpc_port, rpc_method, rpc_keepalive

    if_name        = read_value('interface', 'eth0')
    host_mac       = read_value('macaddress', '')
    host_ip        = read_value('ipaddress', '127.0.0.1')
    host_port      = read_value('port', 34890)
    wait_time      = read_value('wait', 30) * 1000
    wol_interval   = read_value('interval', 0) * 60
    pvr_addon_id   = read_value('addonid', 'pvr.vdr.vnsi')
    pvr_addon_name = xbmcaddon.Addon(pvr_addon_id).getAddonInfo('name')

    wake_text      = __localize__(30100)

    rpc_keepalive  = read_value('rpcwol', True)
    rpc_user       = read_value('rpcuser', 'kodi')
    rpc_password   = read_value('rpcpwd', '')
    rpc_port       = read_value('rpcport', 8080)
    rpc_method     = read_value('rpcmethod', 'VideoLibrary.Scan') # as long as InhibitIdleShutdown(true) is not supported


def isOpen(ip, port, timeout=3):
    if ip == '127.0.0.1':
       return False

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.connect((ip, int(port)))
        s.shutdown(socket.SHUT_RDWR)
        return True

    except:
        return False

    finally:
        s.close()


def get_ip_address(ifname='eth0'):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', bytes(ifname[:15], 'utf-8'))
            )[20:24])
        return ip

    except:
        raise RuntimeError(f"Couldn't determine ip address of interface {ifname}")

    finally:
        s.close()


def wake_on_lan(mac_address):
    pattern = '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})|([0-9A-Fa-f]{12})$'

    # Check mac address format
    found = re.fullmatch(pattern, mac_address)

    if not found:
        raise ValueError('Incorrect MAC address format')
    else:
        xbmc.log(f"[{__addon_id__}] MAC address format is valid.", level=xbmc.LOGDEBUG)

    # If the match is found, remove mac separator
    if len(mac_address) == 17:
        mac_address = mac_address.replace(mac_address[2], '')
    elif len(mac_address) == 14:
        mac_address = mac_address.replace(mac_address[4], '')

    # Pad the synchronization stream.
    data = ''.join(['FFFFFFFFFFFF', mac_address * 20])
    send_data = b''

    # Split up the hex values and pack.
    for j in range(0, len(data), 2):
        send_data = b''.join([
            send_data,
            struct.pack('B', int(data[j: j + 2], 16))
        ])

    # Broadcast it to the LAN.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    xbmc.log(f"[{__addon_id__}] Sending WoL packet {send_data} to broadcast address {broadcast_ip}.", level=xbmc.LOGDEBUG)
    #sock.sendto(send_data, ('255.255.255.255', 9))
    sock.sendto(send_data, (broadcast_ip, 7))


def wake_host(wait=False, unconditionally=False):
    if not unconditionally and isOpen(host_ip, host_port, 1):
        xbmc.log(f"[{__addon_id__}] Host {host_ip} is up. Skip sending WoL request.", level=xbmc.LOGINFO)
    else:
        if not host_mac:
            xbmc.log(f"[{__addon_id__}] No MAC addresss specified. Skip sending WoL request.", level=xbmc.LOGINFO)
            return

        xbmc.log(f"[{__addon_id__}] Sending WoL request to MAC address {host_mac} on interface {if_name}.", level=xbmc.LOGINFO)
        try:
            wake_on_lan(host_mac)
            xbmc.executebuiltin(f"Notification({__addon_id__}, {wake_text}, {wait_time})")
            if wait:
                xbmc.sleep(wait_time)
        except Exception as e:
            xbmc.log(f"[{__addon_id__}] Exception occured: {str(e)}.", level=xbmc.LOGINFO)


def rpc_request(method, params=None, host='localhost', port=8080, username=None, password=None):
    url = f"http://{host}:{port}/jsonrpc"
    headers = {'Content-Type': 'application/json'}

    xbmc.log(f"[{__addon_id__}] Initializing RPC request with method {method}.", level=xbmc.LOGDEBUG)

    jsondata = {
        'jsonrpc': '2.0',
        'method': method,
        'id': method}

    if params:
        jsondata['params'] = params

    if username and password:
        auth_str = f'{username}:{password}'
        try:
            base64str = base64.encodestring(auth_str)[:-1]
        except:
            base64str = base64.b64encode(auth_str.encode()).decode()
        headers['Authorization'] = f"Basic {base64str}"

    try:
        if host in ['localhost', '127.0.0.1']:
            response = xbmc.executeJSONRPC(json.dumps(jsondata))
            data = json.loads(response)

        else:
            response = requests.post(url, data=json.dumps(jsondata), headers=headers)
            if not response.ok:
                raise RuntimeError(f"Response status code: {response.status_code}")

            data = json.loads(response.text)

        if data['id'] == method and 'result' in data:
            xbmc.log(f"[{__addon_id__}] RPC request returned data: {data['result']}.", level=xbmc.LOGDEBUG)
            return data['result']

    except Exception as e:
        xbmc.log(f"[{__addon_id__}] RPC request failed with error: {str(e)}.", level=xbmc.LOGINFO)


def parse_notification(sender, method, data):
    if sender == 'xbmc' and  method == 'GUI.OnScreensaverActivated':
        #system_idle = True
        xbmc.log(f"[{__addon_id__}] Screen saver activated.", level=xbmc.LOGINFO)
        rpc_request('Addons.SetAddonEnabled', params={'addonid': pvr_addon_id, 'enabled': False})
        xbmc.log(f"[{__addon_id__}] {pvr_addon_name} addon temporarily disabled.", level=xbmc.LOGINFO)

    if sender == 'xbmc' and  method == 'GUI.OnScreensaverDeactivated':
        signal = json.loads(data)
        if signal and 'shuttingdown' in signal:
            if not signal['shuttingdown']:
                #system_idle = False
                xbmc.log(f"[{__addon_id__}] Screen saver deactivated.", level=xbmc.LOGINFO)
                wake_host()
                rpc_request('Addons.SetAddonEnabled', params={'addonid': pvr_addon_id, 'enabled': True})
                xbmc.log(f"[{__addon_id__}] {pvr_addon_name} addon enabled.", level=xbmc.LOGINFO)


class MyMonitor(xbmc.Monitor):
    #def onScreensaverActivated(self):
    #    xbmc.log(f"[{__addon_id__}] Screen saver activated.", level=xbmc.LOGINFO)

    #def onScreensaverDeactivated(self):
    #    xbmc.log(f"[{__addon_id__}] Screen saver deactivated.", level=xbmc.LOGINFO)

    def onNotification(self, sender, method, data):
        xbmc.log(f"[{__addon_id__}] OnNotification triggered (sender: {sender}, method: {method}, data: {data}).", level=xbmc.LOGDEBUG)
        parse_notification(sender, method, data)


if __name__ == "__main__":
    xbmc.log(f"[{__addon_id__}] Service started.", level=xbmc.LOGINFO)

    load_settings()
    xbmc.log(f"[{__addon_id__}] Settings loaded.", level=xbmc.LOGINFO)

    # Get broadcast ip dynamically
    try:
        #local_ip = socket.gethostbyname(socket.gethostname())
        local_ip = get_ip_address(if_name)
        xbmc.log(f"[{__addon_id__}] Local IP address of interface {if_name}: {local_ip}.", level=xbmc.LOGINFO)
        local_ip = local_ip.rsplit('.', 1)
        local_ip[1] = '255'

        broadcast_ip = '.'.join(local_ip)
    except:
        xbmc.log(f"[{__addon_id__}] Couldn't determine broadcast address for interface {if_name}.", level=xbmc.LOGINFO)
        sys.exit(1)

    try:
        screensaver = bool(rpc_request('Settings.GetSettingValue', {'setting': 'screensaver.mode'})['value'])
        xbmc.log(f"[{__addon_id__}] Sreensaver is {'enabled' if screensaver else 'disabled --> enabling ...'}.", level=xbmc.LOGINFO)
        if not screensaver:
            rpc_request('Settings.SetSettingValue', params={'setting': 'screensaver.mode', 'value': 'screensaver.xbmc.builtin.dim'})
            xbmc.log(f"[{__addon_id__}] Screensaver enabled with default value (Dim).", level=xbmc.LOGINFO)
    except:
        xbmc.log(f"[{__addon_id__}] Unable to determine/adapt current screensaver mode.", level=xbmc.LOGINFO)

    wake_host()

    monitor = MyMonitor()

    while not monitor.abortRequested():
        if monitor.waitForAbort(wol_interval or 1):
            xbmc.log(f"[{__addon_id__}] Abort requested.", level=xbmc.LOGINFO)
            break
        if wol_interval > 0:
            if not xbmc.getCondVisibility("System.ScreenSaverActive"): #if not system_idle
                if rpc_keepalive:
                    xbmc.log(f"[{__addon_id__}] Sending RPC request with method {rpc_method} to host {host_ip}.", level=xbmc.LOGINFO)
                    rpc_request(rpc_method, host=host_ip, port=rpc_port, username=rpc_user, password=rpc_password)
                else:
                    wake_host(unconditionally=True)

