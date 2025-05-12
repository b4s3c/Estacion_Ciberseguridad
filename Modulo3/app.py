from flask import Flask, jsonify, send_from_directory, send_file, make_response
import subprocess
import re
import os

app = Flask(__name__, static_folder='.')

# Ruta para servir imagen de cámara IP
@app.route("/simulacion/camara")
def simulacion_camara():
    ruta = os.path.join(app.root_path, "camarafablab.jpg")
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
    "5555": "Android (depuración ADB)"
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
    }
}

@app.route("/")
def home():
    return send_from_directory('.', 'Index.html')

@app.route("/scan")
def escanear_red():
    dispositivos = []
    try:
        resultado = subprocess.check_output([
            "nmap", "-sT", "-sV", "-O",
            "-p", ",".join(PUERTOS_TIPO_DISPOSITIVO.keys()),
            "192.168.0.0/24"
        ], text=True)

        print("\n===== RESULTADO NMAP =====\n")
        print(resultado)
        print("\n===========================\n")

        bloques = resultado.split("Nmap scan report for")[1:]

        for bloque in bloques:
            lineas = bloque.strip().split("\n")
            ip = lineas[0].strip()
            puertos = [l for l in lineas if "/tcp" in l and "open" in l]
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
