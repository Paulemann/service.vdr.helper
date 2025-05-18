import os
import re
import socket
import struct
import fcntl
import sys
import json
import time

import base64
import requests

import xbmc
import xbmcaddon


# Addon ID to be used in logging
__addon_id__       = xbmcaddon.Addon().getAddonInfo('id')

# Notification shown while PVR host is waking up
__wake_text__      = xbmcaddon.Addon().getLocalizedString(30100)

# Flag if system is shutting down
# It will be set to 'True' when 'System.OnQuit' notification is processed
__sys_shutdown__   = False

# Flag if KODI's Wake on Access is set
# If set and host MAC configured in PVR addon setting it'll make internal wakeHost() redundant
__wake_on_access__ = False

# VDR VNSI Client addon ID
__pvr_addon_id__   = 'pvr.vdr.vnsi'
__pvr_addon_name__ = 'VDR VNSI Client'


def readValue(item, default, addonid=None):
    if addonid:
       addon = xbmcaddon.Addon(addonid)

    else:
       addon = xbmcaddon.Addon()

    try:
        value = int(addon.getSetting(item))

    except ValueError:
        try:
            if addon.getSetting(item).lower() == 'true' or addon.getSetting(item).lower() == 'false':
                value = bool(addon.getSetting(item).lower() == 'true')

            else:
                value = addon.getSetting(item)

        except ValueError:
            value = default

    return value


def loadSettings():
    global host_mac, host_ip, host_port
    global wait_time, wol_interval
    global rpc_user, rpc_password, rpc_port, rpc_method, rpc_params, kodi_rpc
    global broadcast_ip
    global __pvr_addon_name__
    global __wake_on_access__

    if_name      = readValue('interface', 'eth0')
    wait_time    = readValue('wait', 30)         # Seconds
    wol_interval = readValue('interval', 0) * 60 # Minutes -> Seconds

    host_mac     = readValue('macaddress', '')

    # KODI built-in Wake on Access will also wake up remote host.
    # However, this requires the host's MAC address configured in PVR addon settings
    response = callKODI('Settings.GetSettingValue', params={'setting': 'powermanagement.wakeonaccess'})
    if response and 'value' in response:
        __wake_on_access__ = response['value']
        xbmc.log(f"[{__addon_id__}] KODI Wake on Acesss: {__wake_on_access__}.", level=xbmc.LOGDEBUG)

    try:
        # Query current status of PVR addon
        response = callKODI('Addons.GetAddonDetails', params={'addonid': __pvr_addon_id__, 'properties': ['enabled']})

        if response and 'addon' in response:
            if not response['addon']['enabled']:
                # Enable PVR addon if disabled
                response = callKODI('Addons.SetAddonEnabled', params={'addonid': __pvr_addon_id__, 'enabled': True})
                xbmc.sleep(5000)

        __pvr_addon_name__ = xbmcaddon.Addon(__pvr_addon_id__).getAddonInfo('name')

        host_ip   = readValue('host', '127.0.0.1', addonid=__pvr_addon_id__)
        host_port = readValue('port', 34890, addonid=__pvr_addon_id__)

        #host_mac  = readValue('wol_mac', host_mac, addonid=__pvr_addon_id__)
        wol_mac   = readValue('wol_mac', '', addonid=__pvr_addon_id__)
        xbmc.log(f"[{__addon_id__}] wol_mac: {wol_mac}.", level=xbmc.LOGDEBUG)
        host_mac  = wol_mac or host_mac

        xbmc.log(f"[{__addon_id__}] {__pvr_addon_name__} addon settings: hostanme/IP: {host_ip}, MAC: {host_mac}, Port: {host_port}.", level=xbmc.LOGDEBUG)

        __wake_on_access__ = __wake_on_access__ and bool(wol_mac)
        xbmc.log(f"[{__addon_id__}] __wake_on_access__: {__wake_on_access__}.", level=xbmc.LOGDEBUG)

        xbmc.log(f"[{__addon_id__}] {__pvr_addon_name__} addon enabled.", level=xbmc.LOGINFO)

    except:
        xbmc.log(f"[{__addon_id__}] Failed to enable {__pvr_addon_name__} addon --> Abort.", level=xbmc.LOGINFO)
        sys.exit(1)

    # Query current screensaver mode and set to enable if not set
    try:
        response = callKODI('Settings.GetSettingValue', params={'setting': 'screensaver.mode'})
        screensaver = response['value']
        xbmc.log(f"[{__addon_id__}] Screensaver {'enabled' if bool(screensaver) else 'disabled --> enabling ...'}.", level=xbmc.LOGINFO)

        if not screensaver:
            response = callKODI('Settings.SetSettingValue', params={'setting': 'screensaver.mode', 'value': 'screensaver.xbmc.builtin.dim'})
            xbmc.log(f"[{__addon_id__}] Screensaver enabled with default value (Dim). Response: {response}", level=xbmc.LOGINFO)

    except:
        xbmc.log(f"[{__addon_id__}] Unable to determine/adapt current screensaver mode --> Abort.", level=xbmc.LOGINFO)
        sys.exit(1)

    kodi_rpc = readValue('rpcwol', True)
    if host_ip in ['localhost', '127.0.0.1']:
        kodi_rpc = False

    # In case a kodi instance is running on the same host as the PVR server,
    # we must keep kodi busy to prevent system shutdown when kodi is idle

    # We need rpc_user, rpc_passsowrd and rpc_port of the remote kodi instance
    rpc_user       = readValue('rpcuser', 'kodi')
    rpc_password   = readValue('rpcpwd', '')
    rpc_port       = readValue('rpcport', 8080)

    # As long as InhibitIdleShutdown(true) is not supported by kodi's JSON RPC,
    # we can either start a library scan or call a helper script on the remote kodi instance
    rpc_method     = readValue('rpcmethod', 'VideoLibrary.Scan')
    rpc_addon_id   = readValue('rpcaddonid', 'script.vdr.helper')

    if rpc_method == 'VideoLibrary.Scan':
        rpc_params = None

    elif rpc_method == 'Addons.ExecuteAddon':
        rpc_params = {'addonid': rpc_addon_id}

    # Get broadcast ip dynamically
    try:
        local_ip = getIPaddress(if_name)
        xbmc.log(f"[{__addon_id__}] Local IP address of interface {if_name}: {local_ip}.", level=xbmc.LOGINFO)
        local_ip = local_ip.rsplit('.', 1)
        local_ip[1] = '255'

        broadcast_ip = '.'.join(local_ip)
    except Exception as e:
        xbmc.log(f"[{__addon_id__}] Fatal error: {str(e)} --> Abort.", level=xbmc.LOGINFO)
        sys.exit(1)


def isOpen(host_ip, port, timeout=3):
    if host_ip in ['localhost', '127.0.0.1']:
        return True

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host_ip, int(port)))
        # or
        #if sock.connect_ex((host_ip, int(port))) == 0: # True if open, False if not
        sock.shutdown(socket.SHUT_RDWR)
        return True

    except:
        return False

    finally:
        sock.close()


def isUp(ifname):
    SIOCGIFFLAGS = 0x8913

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        flags, = struct.unpack('H', fcntl.ioctl(
            sock.fileno(),
            SIOCGIFFLAGS,
            struct.pack('256s', bytes(ifname[:15], 'utf-8'))
            )[16:18])
        up = flags & 1
        return bool(up)

    except:
        raise RuntimeError(f"Couldn't determine status of interface {ifname}")

    finally:
        sock.close()


def getIPaddress(ifname='eth0'):
    if not isUp(ifname):
        raise RuntimeError(f"Interface {ifname} is down")

    SIOCGIFADDR = 0x8915

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        ip = socket.inet_ntoa(fcntl.ioctl(
            sock.fileno(),
            SIOCGIFADDR,
            struct.pack('256s', bytes(ifname[:15], 'utf-8'))
            )[20:24])
        return ip

    except:
        raise RuntimeError(f"Couldn't determine ip address of interface {ifname}")

    finally:
        sock.close()


def isPlaybackPaused():
    # Player().isPlaying will return True if Player is in Playback or Pause Mode.
    # However, when ScreenSaver is activated it is safe to assume Player is paused.
    #return xbmc.Player().isPlaying
    return bool(xbmc.getCondVisibility("Player.Paused"))


def wakeOnLAN(mac_address):
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


def wakeHost(wait=False):
    if isOpen(host_ip, host_port, 1):
        xbmc.log(f"[{__addon_id__}] Host {host_ip} is up. Not sending WoL request.", level=xbmc.LOGINFO)
        return True

    try:
        if not __wake_on_access__:
            if not host_mac:
                xbmc.log(f"[{__addon_id__}] No MAC addresss specified. Unable to send WoL request.", level=xbmc.LOGINFO)
                return False

            xbmc.log(f"[{__addon_id__}] Sending WoL request to MAC address {host_mac} of host {host_ip}.", level=xbmc.LOGINFO)

            wakeOnLAN(host_mac)
            xbmc.executebuiltin(f"Notification({__addon_id__}, {__wake_text__}, {wait_time*1000})")

        if wait:
            start_time = time.time()
            while time.time() - start_time < wait_time:
                if isOpen(host_ip, host_port, 1):
                    return True
                else:
                    time.sleep(5)

            return False # Remove?

    except Exception as e:
        xbmc.log(f"[{__addon_id__}] Exception occured: {str(e)}.", level=xbmc.LOGINFO)

    return isOpen(host_ip, host_port, 1)


def callKODI(method, params=None, host='localhost', port=8080, username=None, password=None):
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
            response = requests.post(url, data=json.dumps(jsondata), headers=headers, timeout=5)
            if not response.ok:
                raise RuntimeError(f"Response status code: {response.status_code}")

            data = json.loads(response.text)

        if data and data.get('id') == method:
            xbmc.log(f"[{__addon_id__}] RPC request returned data: {data.get('result')}.", level=xbmc.LOGDEBUG)
            return data.get('result')

    except Exception as e:
        xbmc.log(f"[{__addon_id__}] RPC request failed with error: {str(e)}.", level=xbmc.LOGINFO)

    return None


def parseNotification(sender, method, data):
    global __sys_shutdown__

    if sender != 'xbmc':
        return

    # Capture 'System.OnQuit' notifcation as 'shuttingdown' property of 'GUI.OnScreensaverDeactivated' is not set to 'True' on shutdown
    if method == 'System.OnQuit':
        xbmc.log(f"[{__addon_id__}] 'System.OnQuit' notification received. Flagging system is shutting down.", level=xbmc.LOGDEBUG)
        __sys_shutdown__ = True
        return

    elif method not in ['GUI.OnScreensaverActivated', 'GUI.OnScreensaverDeactivated']:
       return

    action = method[17:].lower() # 'activated' or 'deactivated'
    xbmc.log(f"[{__addon_id__}] Screensaver {action}.", level=xbmc.LOGINFO)

    if action == 'activated':
        # Return if Playback is currently paused
        if isPlaybackPaused():
            xbmc.log(f"[{__addon_id__}] Playback paused. {__pvr_addon_name__} addon not disabled.", level=xbmc.LOGINFO)
            return

    elif action == 'deactivated':
        # Return if system is shutting down
        signal = json.loads(data)
        if __sys_shutdown__ or (signal and signal.get('shuttingdown')):
            xbmc.log(f"[{__addon_id__}] System is shutting down. Not sending WoL request.", level=xbmc.LOGINFO)
            return

        # Return if remote host is not awake
        if not wakeHost(wait=True):
            xbmc.log(f"[{__addon_id__}] Failed to wake up remote host with ip address {host_ip}.", level=xbmc.LOGINFO)
            return

    # Enable/Disable PVR addon
    response = callKODI('Addons.SetAddonEnabled', params={'addonid': __pvr_addon_id__, 'enabled': action == 'deactivated'})

    xbmc.sleep(15000)

    # Query current status of PVR addon
    response = callKODI('Addons.GetAddonDetails', params={'addonid': __pvr_addon_id__, 'properties': ['enabled']})

    if response and 'addon' in response:
        xbmc.log(f"[{__addon_id__}] {__pvr_addon_name__} addon {'enabled' if response['addon']['enabled'] else 'disabled'}.", level=xbmc.LOGINFO)

        # Refresh home window
        #if action == 'deactivated': xbmc.sleep(5000)
        response = callKODI('GUI.ActivateWindow', params={'window': 'home'})

    else:
        xbmc.log(f"[{__addon_id__}] Failed to {'enable' if action == 'deactivated' else 'disable'} {__pvr_addon_name__} addon.", level=xbmc.LOGINFO)


class MyMonitor(xbmc.Monitor):
    def onSettingsChanged(self):
        xbmc.log(f"[{__addon_id__}] Settings changed.", xbmc.LOGDEBUG)
        loadSettings()

    #def onScreensaverActivated(self):
    #    xbmc.log(f"[{__addon_id__}] Screensaver activated.", level=xbmc.LOGINFO)

    #def onScreensaverDeactivated(self):
    #    xbmc.log(f"[{__addon_id__}] Screensaver deactivated.", level=xbmc.LOGINFO)

    def onNotification(self, sender, method, data):
        xbmc.log(f"[{__addon_id__}] OnNotification triggered (sender: {sender}, method: {method}, data: {data}).", level=xbmc.LOGDEBUG)
        parseNotification(sender, method, data)


if __name__ == "__main__":
    xbmc.log(f"[{__addon_id__}] Service started.", level=xbmc.LOGINFO)

    loadSettings()
    xbmc.log(f"[{__addon_id__}] Settings loaded.", level=xbmc.LOGINFO)

    # Wake uo remote host
    wakeHost()

    monitor = MyMonitor()

    while not monitor.abortRequested():
        if monitor.waitForAbort(wol_interval or 1):
            xbmc.log(f"[{__addon_id__}] Abort requested.", level=xbmc.LOGINFO)
            break
        if wol_interval > 0:
            # Continue only if screensaver is not active and ...
            if not xbmc.getCondVisibility("System.ScreenSaverActive"):
                # ... if kodi_rpc is set to True and remote host is up
                if kodi_rpc and isOpen(host_ip, rpc_port, 1):
                    # This is required when kodi and VDR are running on the same host,
                    # to prevent kodi from shutting down the host while VDR is still serving clients
                    xbmc.log(f"[{__addon_id__}] Sending RPC request with method {rpc_method}, parameters {rpc_params} to host {host_ip}.", level=xbmc.LOGINFO)
                    response = callKODI(rpc_method, params=rpc_params, host=host_ip, port=rpc_port, username=rpc_user, password=rpc_password)
                    xbmc.log(f"[{__addon_id__}] RPC request response: {response}.", level=xbmc.LOGDEBUG)

