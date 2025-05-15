from flask import Flask, jsonify, send_from_directory, send_file, make_response, request


import subprocess
import re
import os

app = Flask(__name__, static_folder='.')

# Ruta para servir imagen de cámara IP
@app.route("/simulacion/camara/<ip>")
def simulacion_camara(ip):
    ruta = os.path.join(app.root_path, f"camara_{ip}.jpg")
    if not os.path.exists(ruta):
        ruta = os.path.join(app.root_path, "camarafablab.jpg")  # imagen por defecto
    response = make_response(send_file(ruta, mimetype='image/jpeg'))
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

# Asociación de puertos con tipos de dispositivos
PUERTOS_TIPO_DISPOSITIVO = {
    "21": "Servidor FTP",
    "22": "Servidor SSH o Raspberry Pi",
    "23": "Dispositivo Telnet antiguo",
    "25": "Servidor de correo SMTP",
    "53": "Servidor DNS",
    "80": "Servidor web o router",
    "110": "Servidor POP3",
    "123": "Servidor NTP",
    "135": "Windows RPC",
    "137": "NetBIOS",
    "138": "NetBIOS",
    "139": "PC con compartición de archivos",
    "143": "Servidor IMAP",
    "161": "Dispositivo SNMP",
    "389": "Servidor LDAP",
    "443": "Servidor HTTPS",
    "445": "Servidor SMB/Windows",
    "554": "Cámara IP (RTSP)",
    "631": "Impresora IPP",
    "8080": "Servidor web alternativo",
    "8443": "Servidor web seguro alternativo",
    "8888": "Interfaz API insegura",
    "9100": "Impresora de red",
    "3306": "Servidor MySQL",
    "3389": "Servidor de Escritorio Remoto",
    "5357": "Dispositivo IoT (UPnP)",
    "5555": "Android (depuración ADB)",
    "5000": "Flask API o impresora 3D (OctoPrint)",
    "5900": "Acceso remoto VNC",
    "1883": "Dispositivo IoT (MQTT)",
    "62078": "iPhone (usbmuxd/iTunes)",
    "5353": "Dispositivo Apple o mDNS",
    "1900": "Dispositivo UPnP (SSDP)",
    "3702": "Dispositivo compatible con WS-Discovery"
}

# Información detallada por puerto
PUERTOS_INFO = {
    "21": {
        "servicio": "FTP",
        "riesgos": [
            "FTP transmite archivos y credenciales sin cifrado.",
            "Es susceptible a ataques de fuerza bruta."
        ],
        "recomendaciones": [
            "Deshabilita FTP si no se usa.",
            "Reemplázalo por SFTP.",
            "Usa contraseñas fuertes."
        ],
        "comandos": [
            "sudo ufw deny 21",
            "sudo systemctl stop vsftpd && sudo systemctl disable vsftpd"
        ]
    },
    "22": {
        "servicio": "SSH",
        "riesgos": [
            "Puede ser objetivo de ataques de fuerza bruta si está abierto a Internet."
        ],
        "recomendaciones": [
            "Usa autenticación por clave.",
            "Cambia el puerto por defecto.",
            "Restringe IPs mediante firewall."
        ],
        "comandos": [
            "sudo ufw allow from 192.168.0.0/24 to any port 22",
            "sudo nano /etc/ssh/sshd_config"
        ]
    },
    "23": {
        "servicio": "Telnet",
        "riesgos": [
            "Transmite contraseñas en texto plano.",
            "Permite interceptación fácil de sesiones."
        ],
        "recomendaciones": [
            "Desactiva Telnet.",
            "Usa SSH como alternativa segura."
        ],
        "comandos": [
            "sudo ufw deny 23",
            "sudo systemctl stop telnet.socket",
            "sudo systemctl disable telnet.socket"
        ]
    },
    "80": {
        "servicio": "HTTP",
        "riesgos": [
            "No cifra datos sensibles.",
            "Expuesto a ataques Man-in-the-Middle."
        ],
        "recomendaciones": [
            "Redirige tráfico a HTTPS.",
            "Evita usar HTTP en redes abiertas."
        ],
        "comandos": [
            "sudo a2enmod rewrite",
            "Configurar redirección 80 → 443 en Apache/Nginx"
        ]
    },
    "443": {
        "servicio": "HTTPS",
        "riesgos": [
            "Certificados inválidos o expirados pueden ser explotados."
        ],
        "recomendaciones": [
            "Renueva certificados SSL válidos.",
            "Usa TLS actualizado (1.2 o superior)."
        ],
        "comandos": [
            "sudo certbot --nginx",
            "sudo openssl x509 -in cert.pem -text"
        ]
    },
    "445": {
        "servicio": "SMB",
        "riesgos": [
            "Vulnerable a exploits como EternalBlue.",
            "Objetivo común de ransomware."
        ],
        "recomendaciones": [
            "Desactiva SMBv1.",
            "Actualiza Windows.",
            "Bloquea el puerto 445 desde el exterior."
        ],
        "comandos": [
            "sudo ufw deny 445",
            "sudo systemctl stop smbd && sudo systemctl disable smbd"
        ]
    },
    "3306": {
        "servicio": "MySQL",
        "riesgos": [
            "Bases de datos expuestas a internet.",
            "Explotables por fuerza bruta o inyección SQL."
        ],
        "recomendaciones": [
            "Restringe acceso remoto.",
            "Configura bind-address = 127.0.0.1"
        ],
        "comandos": [
            "sudo ufw deny 3306",
            "sudo nano /etc/mysql/my.cnf"
        ]
    },
    "3389": {
        "servicio": "RDP",
        "riesgos": [
            "Puede permitir control remoto completo.",
            "Explotable con BlueKeep si no está parcheado."
        ],
        "recomendaciones": [
            "Limita el acceso a RDP.",
            "Usa VPN para encapsular RDP.",
            "Aplica autenticación multifactor."
        ],
        "comandos": [
            "sudo ufw deny 3389",
            "Configurar VPN o gateway RDP seguro"
        ]
    },
    "554": {
        "servicio": "RTSP",
        "riesgos": [
            "Transmite video en texto plano.",
            "Sin autenticación expone cámaras IP."
        ],
        "recomendaciones": [
            "Protege con credenciales.",
            "Evita exposición directa a Internet."
        ],
        "comandos": [
            "sudo ufw deny 554",
            "Desactiva RTSP desde panel de cámara"
        ]

    },

        "5000": {
        "servicio": "Flask API / OctoPrint",
        "riesgos": [
            "Servicios de desarrollo expuestos pueden tener fallos de seguridad.",
            "OctoPrint puede ser accedido sin autenticación si no se configura adecuadamente."
        ],
        "recomendaciones": [
            "Restringe el acceso a IPs locales.",
            "Configura autenticación y cifrado si es posible."
        ],
        "comandos": [
            "sudo ufw allow from 192.168.0.0/24 to any port 5000",
            "Verifica configuración de autenticación en OctoPrint"
        ]
    },
    "5900": {
        "servicio": "VNC",
        "riesgos": [
            "VNC sin cifrado permite interceptar sesiones gráficas.",
            "Accesos remotos pueden ser forzados si no hay contraseña robusta."
        ],
        "recomendaciones": [
            "Usa VNC sobre túneles SSH o VPN.",
            "Configura contraseñas seguras."
        ],
        "comandos": [
            "sudo ufw allow from 192.168.0.0/24 to any port 5900",
            "Configura VNC con cifrado si está disponible"
        ]
    },
    "1883": {
        "servicio": "MQTT",
        "riesgos": [
            "Protocolo sin cifrado, susceptible a ataques de sniffing.",
            "Publicaciones y suscripciones pueden ser manipuladas."
        ],
        "recomendaciones": [
            "Usa MQTT sobre TLS (puerto 8883).",
            "Autentica clientes con usuario y contraseña."
        ],
        "comandos": [
            "sudo ufw deny 1883",
            "Configura Mosquitto o similar con TLS"
        ]
    },
    "62078": {
        "servicio": "usbmuxd (iTunes/iPhone)",
        "riesgos": [
            "Servicios de sincronización pueden estar expuestos sin necesidad.",
            "Permite acceso a datos si no se restringe adecuadamente."
        ],
        "recomendaciones": [
            "Bloquea el puerto si no se usa.",
            "Restringe a conexiones USB físicas solamente."
        ],
        "comandos": [
            "sudo ufw deny 62078"
        ]
    },
    "5353": {
        "servicio": "mDNS (Bonjour)",
        "riesgos": [
            "Exposición de servicios de red automáticamente (como AirPrint, AirPlay).",
            "Puede filtrar nombres de host y servicios disponibles."
        ],
        "recomendaciones": [
            "Desactiva mDNS si no es necesario.",
            "Filtra tráfico multicast en el router si es posible."
        ],
        "comandos": [
            "sudo ufw deny 5353/udp"
        ]
    },
    "1900": {
        "servicio": "SSDP (UPnP)",
        "riesgos": [
            "Permite descubrimiento de dispositivos, usado en ataques DDoS y escaneos laterales.",
            "Puede exponer dispositivos vulnerables automáticamente."
        ],
        "recomendaciones": [
            "Desactiva UPnP si no es esencial.",
            "Filtra tráfico multicast."
        ],
        "comandos": [
            "sudo ufw deny 1900/udp"
        ]
    },
    "5357": {
    "servicio": "UPnP (Universal Plug and Play)",
    "riesgos": [
        "UPnP permite que dispositivos en la red abran puertos automáticamente, lo que puede exponer servicios a Internet sin intervención del usuario.",
        "Vulnerabilidades conocidas pueden permitir ejecución remota de código.",
        "Algunos dispositivos no verifican correctamente la procedencia de las solicitudes UPnP."
    ],
    "recomendaciones": [
        "Desactiva UPnP en el router si no se necesita.",
        "Actualiza el firmware del dispositivo IoT o del router.",
        "Asegúrate de que UPnP no esté accesible desde Internet."
    ],
    "comandos": [
        "Accede a la configuración de tu router → Desactiva UPnP.",
        "nmap --script upnp-info -p 1900 <IP>",
        "sudo apt install miniupnpd && sudo miniupnpd -d"
    ]
},
    "3702": {
        "servicio": "WS-Discovery",
        "riesgos": [
            "Usado en entornos Windows para descubrir dispositivos en red.",
            "Puede facilitar reconocimiento de red a atacantes internos."
        ],
        "recomendaciones": [
            "Restringe el uso de este protocolo si no es requerido.",
            "Monitorea el tráfico de descubrimiento."
        ],
        "comandos": [
            "sudo ufw deny 3702/udp"
        ]
    }
}

@app.route("/")
def home():
    return send_from_directory('.', 'Index.html')

@app.route("/scan")
def escanear_red():
    tipo_escaneo = request.args.get("tipo", "completo")

    PUERTOS_CRITICOS = ["21", "22", "23", "80", "443", "554", "8080", "135", "139"]

    if tipo_escaneo == "rapido":
        objetivo = [
            "192.168.0.1",
            "192.168.0.5",
            "192.168.0.7",
            "192.168.0.102",
            "192.168.0.103",
            "192.168.0.104",
            "192.168.0.108",
            "192.168.0.23"
        ]
        argumentos = ["nmap", "-sS", "-T4", "-p", ",".join(PUERTOS_CRITICOS)]
    else:
        objetivo = ["192.168.0.1-110"]
        argumentos = ["nmap", "-sT", "-sV", "-O", "-p", ",".join(PUERTOS_TIPO_DISPOSITIVO.keys())]

    argumentos += objetivo

    dispositivos = []
    try:
        resultado = subprocess.check_output(argumentos, text=True)
        bloques = resultado.split("Nmap scan report for")[1:]

        for bloque in bloques:
            lineas = bloque.strip().split("\n")
            ip = lineas[0].strip()
            puertos = [l for l in lineas if "/tcp" in l and "open" in l]

            if not puertos:
                continue

            sistema = "Desconocido"
            tipo = "Desconocido"
            riesgos, recomendaciones, comandos, puertos_texto = [], [], [], []

            for p in puertos:
                puertos_texto.append(p)
                match = re.match(r"(\d+)/tcp", p)
                if match:
                    port = match.group(1)
                    if port in PUERTOS_TIPO_DISPOSITIVO:
                        tipo = PUERTOS_TIPO_DISPOSITIVO[port]
                    if port in PUERTOS_INFO:
                        info = PUERTOS_INFO[port]
                        riesgos.extend(info.get("riesgos", []))
                        recomendaciones.extend(info.get("recomendaciones", []))
                        comandos.extend(info.get("comandos", []))

            for l in lineas:
                if "OS details:" in l:
                    sistema = l.split("OS details:")[1].strip()

            dispositivos.append({
                "ip": ip,
                "tipo": tipo,
                "sistema": sistema,
                "puertos": puertos_texto,
                "riesgos": list(set(riesgos)),
                "recomendaciones": list(set(recomendaciones)),
                "comandos": list(set(comandos))
            })

    except Exception as e:
        return jsonify({"error": str(e)})

    return jsonify(dispositivos)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
