import xbmc
import xbmcaddon

__addon__      = xbmcaddon.Addon()
__addon_id__   = __addon__.getAddonInfo('id')

if __name__ == "__main__":
    xbmc.log(f"[{__addon_id__}] Reset kodi shutdwon timer.", level=xbmc.LOGINFO)

    xbmc.executebuiltin('InhibitIdleShutdown(true)')

