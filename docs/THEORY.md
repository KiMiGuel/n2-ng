# Teoría de N2-NG

Este documento explica los conceptos de auditoría inalámbrica detrás de las funciones de N2-NG. Es material educativo de fondo, no un manual de instrucciones — consulta `USER_GUIDE.md` para la operación.

## Monitor Mode

Un adaptador inalámbrico en managed mode solo ve el tráfico dirigido a él. El monitor mode (`airmon-ng`, `iw`) pone la interfaz en recepción 802.11 promiscua: cada trama del canal actual se entrega al espacio de usuario, incluidos beacons, probe requests, tramas de datos e intercambios de autenticación de todas las redes cercanas. Todo lo que N2-NG muestra — puntos de acceso, clientes, handshakes — se analiza a partir de este flujo de tramas crudas (`airodump-ng`).

El channel hopping hace ciclar la interfaz por los canales para inspeccionar toda la banda; bloquear un objetivo detiene el salto para que la radio permanezca en el canal del objetivo y capture su tráfico de forma fiable.

## Aleatorización de MAC

Antes de entrar en monitor mode, N2-NG puede aleatorizar la dirección MAC de la interfaz (#4). La MAC de origen es visible en cada trama inyectada (deauthentications, inyecciones WEP), así que la aleatorización evita vincular el tráfico de auditoría con la dirección grabada de fábrica del adaptador. La dirección original se restaura cuando la interfaz vuelve a managed mode.

## Captura del Handshake WPA/WPA2

WPA2 deriva las claves de sesión de un handshake de 4 vías entre el punto de acceso y el cliente. El handshake contiene el ANonce, el SNonce, ambas direcciones MAC y un MIC — todo lo necesario para probar una contraseña candidata offline:

1. `PMK = PBKDF2(passphrase, ESSID, 4096, 256)`
2. `PTK = PRF(PMK, ANonce, SNonce, AP MAC, client MAC)`
3. Recalcular el MIC con el PTK y compararlo con el MIC capturado.

Una coincidencia prueba la contraseña. N2-NG detecta el handshake en el flujo de captura y lo guarda para el cracking offline con hashcat. La captura es oportunista: un handshake solo aparece cuando un cliente se (re)conecta. Un ataque de deauthentication fuerza a los clientes conectados a reconectarse, produciendo un handshake bajo demanda.

## Ataque PMKID

Algunos puntos de acceso incluyen un PMKID en el primer mensaje EAPOL de los intercambios de roaming (802.11r). El PMKID se deriva del PMK y de ambas direcciones MAC, así que permite la misma prueba offline de contraseña que un handshake completo — pero puede solicitarse directamente al AP sin cliente presente y sin deauthentication.

## Deauthentication

Las tramas de deauthentication 802.11 son tramas de gestión no autenticadas. Falsificar una desde la dirección del AP hacia un cliente (o broadcast) hace que el cliente se desconecte y se reconecte. Así es como se acelera la captura del handshake — y también por qué es una primitiva de denegación de servicio. N2-NG envía deauths mediante `aireplay-ng` y detiene todo el grupo de procesos con Stop (#5) para que no quede ningún inyector ejecutándose.

## Ataques WEP

La planificación de claves RC4 de WEP filtra material de clave a través de IVs débiles. Con suficientes IVs capturados, los ataques estadísticos (`aircrack-ng`) recuperan la clave. Como la recolección pasiva es lenta, los ataques activos generan tráfico:

- **Fake authentication** (`-1`): se asocia con el AP para que acepte nuestras tramas inyectadas. WEP requiere la MAC de origen; N2-NG la resuelve desde sysfs (#3).
- **ARP request replay** (`-3`): reinyecta las peticiones ARP capturadas; cada respuesta lleva un IV nuevo.
- **ChopChop** (`-4`) y **Fragmentation** (`-5`): descifran o falsifican un paquete byte a byte sin la clave, produciendo un keystream para la inyección.

## WPS

Wi-Fi Protected Setup intercambia un PIN de 8 dígitos dividido en dos mitades que se validan de forma independiente, reduciendo la fuerza bruta a ~11.000 intentos. El WPS scan de N2-NG lista los APs que anuncian WPS en sus beacons; los ataques PIN online (`reaver`/`bully`) y el ataque offline Pixie Dust se dirigen a esta debilidad.

## Cracking Offline

Los handshakes, PMKIDs e IVs WEP capturados se crackean offline — sin más tráfico de radio, sin limitación de velocidad. Modos de hashcat: 22000 (WPA-PBKDF2/PMKID/handshake), 2500/2501 (hccapx legacy). La seguridad de una red WPA2 se reduce por tanto a la entropía de la contraseña: el handshake expone material suficiente para probar candidatas a velocidad de GPU.

## Conclusiones Defensivas

- Usa WPA2/WPA3 con una contraseña larga y aleatoria — la captura del handshake es cuestión de cuándo, no de si.
- Deshabilita WPS.
- Prefiere WPA3-SAE, que reemplaza el intercambio PSK por Dragonfly y elimina los ataques de diccionario offline sobre el handshake.
- 802.11w (protección de tramas de gestión) autentica las tramas de deauth y frustra la reconexión forzada.
