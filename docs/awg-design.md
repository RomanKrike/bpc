# AWG transport design

The RU node exposes independent transports on the same public host. Xray remains on TCP/443 and AWG2 uses UDP/443. The two services are health-checked independently, while a future client-side policy layer will decide which transport is active.
