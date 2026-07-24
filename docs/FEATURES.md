# Funciones de N2-NG (v1.1)

N2-NG es una GUI en Python 3 + Tkinter para auditoría WiFi en Kali Linux. Envuelve la suite aircrack-ng (`airmon-ng`, `airodump-ng`, `aireplay-ng`) y hcxtools (`hcxpcapngtool`, `hcxhash2cap`) en una sola ventana, y añade verificación de capturas y automatización encima.

## Lista de funciones

### Escaneo y monitor mode

- Monitor mode con un clic mediante `airmon-ng` (usa la interfaz directamente si ya está en monitor mode).
- Escaneo en vivo con channel hopping en 2.4 GHz, 5 GHz o ambas bandas mediante `airodump-ng`.
- Tabla de redes ordenable: BSSID, PWR, Beacons, #Data, CH, MB, ENC, CIPHER, AUTH, fabricante, ESSID. La visibilidad de columnas es configurable.
- Detección de fabricante (OUI) con `airodump-ng -M`.
- Filtro por cifrado (All / WEP / WPA-WPA2 / WPA3 / Open).
- Pestaña Raw View con la salida de terminal de `airodump-ng` en vivo, colores ANSI incluidos.
- Bloqueo de canal: al seleccionar un objetivo, el adaptador se fija en su canal y mantiene el canal del sistema alineado para que `aireplay-ng` no se queje de mismatches. Desbloqueo manual, o desbloqueo automático tras una captura exitosa.
- Aleatorización de MAC antes de entrar en monitor mode (opcional, activada por defecto en los ajustes).
- Restauración de managed mode al salir: las interfaces que N2-NG puso en monitor mode vuelven a managed mode al cerrar la aplicación; las interfaces en monitor mode preexistentes se dejan intactas.

### Captura de handshake WPA con puerta de verificación (nuevo en v1.1)

- Ataques de deauthentication (todos los clientes o un cliente específico) mediante `aireplay-ng -0`.
- Bucle de auto-deauth: lanza una ráfaga de deauth cada 10/30/60 s hasta capturar un handshake *verificado* o un PMKID, y luego se detiene solo.
- La captura se convierte continuamente al formato 22000 de hashcat en segundo plano mientras se captura, y cada registro WPA\*02 (EAPOL) se clasifica por su byte MESSAGEPAIR (los 3 bits bajos; los bits de flags como nonce-error-correction `0x80` se enmascaran):
  - **AUTHORIZED** (messagepair 1–5): el AP aceptó la prueba del cliente, así que el cliente conocía el PSK correcto. El handshake es crackeable. Es el único veredicto EAPOL que detiene el bucle de auto-deauth.
  - **CHALLENGE** (messagepair 0, solo M1+M2): se capturaron el M1 del AP y el M2 del cliente, pero el AP nunca confirmó al cliente. Esto ocurre típicamente cuando un cliente se autentica con una *contraseña incorrecta* — el MIC resultante se calcula con el PSK equivocado y jamás podrá crackearse. Tratarlo como "handshake capturado" es un falso positivo clásico del flujo de trabajo con aircrack-ng puro. N2-NG registra una advertencia ("Handshake UNVERIFIED … keep capturing") y sigue con el deauth.
  - **PMKID**: los registros WPA\*01 siempre son material de ataque válido (no hace falta interacción con el cliente en el momento de la captura), así que detienen el bucle como antes.
- La insignia de veredicto (verdict badge) en la barra de acciones de Capture Sessions muestra el veredicto de la sesión seleccionada: AUTHORIZED (verde), CHALLENGE (naranja), PMKID (verde), NO PAIR (gris/rojo) o "—" cuando aún no existe .22000. Los veredictos se cachean por ruta de archivo + mtime y se recalculan cada vez que se regenera el .22000.

### Pipeline automático de .22000 (nuevo en v1.1)

- Siempre se genera automáticamente un archivo .22000 actualizado para hashcat; el botón manual "Convert to 22000" fue eliminado. La conversión ocurre:
  - continuamente durante la captura (la puerta de verificación anterior),
  - después de que **Fix Capture** termine con éxito,
  - después de que **Merge** termine con éxito,
  - de forma perezosa (lazy) cuando se selecciona una sesión de captura sin .22000 (hilo en segundo plano, una vez por archivo, nunca bloquea la UI).
- La conversión usa `hcxpcapngtool` y valida que la salida realmente contenga registros PMKID/EAPOL.

### Gestión de sesiones de captura

- Lista de sesiones con todas las capturas y hashes bajo `~/hs/n2-ng/`, actualizada automáticamente cada 20 s.
- Inspect: metadatos del archivo, conteo y tipos de registros hashcat, .22000 relacionado.
- Fix Capture: repara capturas dañadas con `pcapfix`.
- Merge: combina 2+ capturas con `mergecap`; la salida fusionada se verifica para confirmar que sigue conteniendo registros WPA, y los originales pueden archivarse opcionalmente en `~/hs/n2-ng/.archive/<fecha>/` tras un merge exitoso.
- Normalización a PCAPNG con `editcap`.
- Reconstrucción de un .cap sintético a partir de un archivo de hashes .22000 con `hcxhash2cap` (con una advertencia explícita de que no es la captura original).
- Copiar al portapapeles el comando de hashcat o el contenido del .22000.
- Menú contextual con clic derecho con todo lo anterior.

### Ataques

- Deauthenticate All Clients / Deauthenticate Specific Client (`aireplay-ng -0`).
- Bucle de auto-deauth (ver arriba).
- WPS scan (`wash`, con `reaver --scan` como respaldo) con un diálogo de salida en vivo.
- Ataque Reaver WPS PIN contra el objetivo bloqueado.
- Ataques WEP legacy (tras el conmutador "Show Legacy WEP Attacks"): fake authentication, ARP replay, chopchop, fragmentation. La MAC de origen se resuelve desde sysfs para que funcionen con MACs aleatorizadas.
- Stop Attack mata todo el grupo de procesos del ataque — no quedan procesos `aireplay-ng`/`reaver` huérfanos.

### Integración con hashcat

- Diálogo de hashcat para cualquier sesión con un .22000 válido: ataque de diccionario (`-m 22000 -a 0`) con selector de wordlist, vista previa del comando en vivo, salida en streaming, Start/Stop, y una sesión con nombre (`n2ng-<timestamp>`) para poder reanudar las ejecuciones con `hashcat --session n2ng-<timestamp> --restore`.

### UI / calidad de vida

- Ordenación de tabla en dos niveles (nuevo en v1.1): al ordenar por PWR, los empates se resuelven por canal ascendente; al ordenar por CH, los empates se resuelven por potencia descendente. Las demás columnas conservan el comportamiento de clave única.
- Clic en las cabeceras de columna para ordenar; clic de nuevo para invertir la dirección.
- Soporte para pantallas pequeñas de hasta 800x480 (la ventana y los diálogos se ajustan a la pantalla, el panel derecho tiene scroll).
- Tema oscuro estilo terminal, tabla de escaneo monoespaciada, gráfica de intensidad de señal para el objetivo bloqueado.
- Comprobación de dependencias al inicio y por función: las herramientas opcionales que falten (hcxtools, reaver, mergecap, editcap, pcapfix, hashcat, tshark) producen una advertencia con el comando `apt` de instalación en lugar de un fallo.
- Los ajustes se guardan por usuario (incluido el usuario que invocó el comando cuando se ejecuta vía sudo).

## Comparación con las herramientas manuales

### vs. el flujo de trabajo con aircrack-ng puro (airmon-ng + airodump-ng + aireplay-ng + aircrack-ng)

El flujo clásico necesita al menos tres terminales: una con `airodump-ng` fijado en un canal, una lanzando ráfagas de `aireplay-ng -0`, y una para revisar la captura — donde "¿el handshake es bueno?" normalmente significa releer la nota `WPA handshake` de airodump, abrir la captura en Wireshark, o ejecutar `aircrack-ng`/`cowpatty` contra ella. Esa nota aparece con *cualquier* par M1+M2, incluidos los pares de clientes que usaron una contraseña incorrecta, que son imposibles de crackear.

N2-NG automatiza todo el bucle en una ventana: monitor mode, bloqueo de canal, ráfagas de deauth y — desde v1.1 — la *verificación* de lo capturado analizando el byte messagepair de cada registro EAPOL, de modo que el bucle de auto-deauth solo se detiene con material que realmente se puede crackear. Las capturas se convierten al formato de hashcat automáticamente en lugar de hacerlo a mano.

Lo que **no** reemplaza: el control fino de las herramientas individuales. No hay forma de crear invocaciones personalizadas de `aireplay-ng`, ajustar `airodump-ng` más allá de los ajustes expuestos, ni ejecutar `aircrack-ng` directamente para crackeo WEP — los ataques WEP legacy son envoltorios de conveniencia, no un kit WEP completo.

### vs. hcxtools (hcxdumptool + hcxpcapngtool)

`hcxdumptool` es un motor de ataque/captura dedicado: hace ataques PMKID sin AP (AP-less), sondeo EAPOL activo e interacción sin beacons que `airodump-ng` + `aireplay-ng` simplemente no hacen. N2-NG **no** reemplaza a hcxdumptool — su motor de captura sigue siendo `airodump-ng`, y los PMKID solo se recolectan pasivamente cuando un AP los ofrece.

Lo que N2-NG añade del lado de hcxtools es la automatización del post-procesado: cada captura pasa por `hcxpcapngtool` automáticamente (durante la captura, tras fix, tras merge y al seleccionar), la salida se valida, y el veredicto basado en messagepair te dice si el hash extraído vale la pena antes de gastar tiempo de GPU en él. Si quieres los modos de ataque activos de hcxdumptool, ejecútalo e importa el pcapng resultante en la lista de sesiones de N2-NG — el pipeline de .22000 y la insignia de veredicto también funcionan con esos archivos.
