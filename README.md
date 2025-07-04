# service.vdr.helper

Service addon that temporarily deactivates the VDR VNSI Client addon when the client is idle to allow the VDR backend system to enter power save mode.

The low energy consumption of the Raspberry Pi makes it a perfect device for 24/7 operation. However, it is annoying that if you run kodi (libreelec) on a Raspberry Pi the always on mode may keep backend systems from powering down. In my case it is the VDR VNSI client addon which prevents the VDR backend system from entering or staying in power save mode even at times when nobody's watching Live or recorded TV and the client is supposed to be idle. This is due to timer and EPG updates that the client regularly requests from the VDR backend system,

Since the Raspberry Pi itself doesn't have an energy saving mode, there seems to be no easy way to prevent the client from permanently querying the backend system unless you accept to shutdown the system after a specified period of inactivity (to be set via the kodi system settings). In that case you'll either have to unplug/plug the power cable to restart the system or you invest in a power knob that is installed on the GPIO pins and attach it somehow to the case.

Now, there's a workaround. Instead of shutting down when the system has entered idle mode, the addon configures kodi to activate the screensaver (actually it the default setting). When connected to a TV which supports CEC you may also want to send the TV into standby upon activating the screen saver in kodi. This option can be configured in kodi's CEC settings.

This addon uses the screen saver activation/deactivation notification in kodi to detect if the client is idle and deactivates the PVR client addon during idle time. Additionally, if a MAC address in specified in the addon settings, a WoL "magic packet" is sent to the PVR backend system/remote host upon start and when the screen saver is deactivated. If the keepalive interval is configured with a value > 0, it will try to wake/keep up the remote system by periodically sending WoL packets. To check if the remote host is (already) up it requires its IP address and a port to be monitored configured in the addon settings.

Alternatively, the MAC address of the PVR backend system can be configured in the PVR client addon (pvr.vdr.vnsi). It'll send its own WoL signal when the addon needs to wake the PVR backend system.

If kodi runs on the same backend system as VDR, there's another annoying "feature" you have to deal with. As kodi only knows about its own, local VDR VNSI client it is completely agnostic to other, remote VDR VNSI clients streaming from the VDR VNSI server running on the same backend system as kodi. Thus, while you're watching Live or recorded TV on your Raspberry Pi, kodi's power management on the backend system may kick in (using kodi's own idle timer) and send the whole system into power save mode even though VDR's VNSI server is still streaming data to your client.

To mitigate this I added an alternative method leveraging kodi's remote control capabilites. Instead of repetetively sending WoL "magic packets" to the backend system, it sends Remote Procedure Call (RPC) requests to kodi running on the backend system. Kodi has a built-in command "InhibitIdleShutdown" to reset kodi's internal idle timer. Unfortunately, this command is not available in the current JSON-RPC API implementation (as af v13 (kodi Omega)). Hence, the next best option is to send an RPC request with a method like "VideoLibrary.Scan" (preset setting; starts an update of kodi's video library) that will implicitly reset kodi's idle timer. Just make sure, that the keepalive interval in the addon settings is set to a value smaller than the shutdown function timer in kodi's power saving settings on the backend system.

The addon was developed with the intention to use it with a VDR backend system and VDR VNSI Client addon on kodi. However, the addon is not VDR specific. If you configure an addon id other than the default pvr.vdr.vnsi you can use it with any other addon that you prefer to be disabled during system idle time.

Update:

You can install a script addon on the backend system. The script will reset kodi's shutdown timer. From the remote client you can use JSON-RPC method "Addons.ExecuteAddon" with Parameter {"addonid": "script.vdr.helper"} to call this script periodically instead of startting the video library scan. This has been added as an option in the settings of the service.vdr.helper addon.
