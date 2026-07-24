# Changelog

## 1.1.0

### Añadido
- Puerta de verificación de handshake: los archivos .22000 se clasifican por el byte MESSAGEPAIR de EAPOL — AUTHORIZED (messagepair 1-5, el AP aceptó la prueba del cliente, crackeable) vs CHALLENGE (solo M1+M2, messagepair 0, posiblemente una autenticación fallida por contraseña incorrecta)
- Insignia de veredicto en la barra de acciones de Capture Sessions que muestra el veredicto de la sesión seleccionada (AUTHORIZED / CHALLENGE / PMKID / NO PAIR), cacheada por ruta+mtime
- Generación automática de .22000: las capturas se (re)convierten en segundo plano tras la puerta de captura, Fix Capture, Merge, y de forma perezosa (lazy) cuando se selecciona una sesión sin .22000

### Cambiado
- El bucle de auto-deauth ya no se detiene con handshakes no verificados (CHALLENGE solo registra una advertencia y sigue capturando)
- Ordenación de la tabla de redes en dos niveles: los empates de PWR se resuelven por CH ascendente, los empates de CH se resuelven por PWR descendente

### Eliminado
- Botón "Convert to 22000" y su entrada de menú contextual — la conversión ahora es automática

## 1.0.0

### Añadido
- Aleatorización de la dirección MAC antes de entrar en monitor mode (#4)
- Restauración de managed mode al salir, conservando las interfaces en monitor mode preexistentes (#7)
- Archivado de las fuentes de un merge tras un merge verificado (opcional) (#8)

### Corregido
- Stop Attack ahora mata todo el grupo de procesos del ataque en lugar de dejar procesos huérfanos (#5)
- Resolución de la MAC de origen desde sysfs para los ataques WEP ("cannot determine our mac address") (#3)
- Scroll con la rueda del ratón en los diálogos laterales (#9)
- La UI cabe en pantallas pequeñas de hasta 800x480 (#6)
