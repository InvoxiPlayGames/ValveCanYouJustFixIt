Linux eBPF traffic control filter to modify Source Engine server query packets
on egress to mark the server as password protected.

This is to work around the bug in Source 2 / Counter-Strike 2, where if your
dedi has a password enabled, it doesn't report in the server query so you can
only join via the developer console, rather than the Server Browser or via an
invite.

https://github.com/ValveSoftware/csgo-osx-linux/issues/3993

@Valve look at these document i found on bing website
https://partner.steamgames.com/doc/api/ISteamGameServer#SetPasswordProtected

Public domain to the extent of the code that doesn't use the DRM-restricted
kernel function, else GPLv2.

THIS CODE IS PROVIDED WITH NO WARRANTY, AND NO SECURITY OR STABILITY GUARANTEES!

I am also not responsible if this affects your Steam account's standing or
your server's ability to show up on Steam's Master Server, although if you're
password protected you probably don't want to show up there anyway...
