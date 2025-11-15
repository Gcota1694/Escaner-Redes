from flask import Flask, render_template_string, jsonify, request
import nmap
import socket
import ipaddress
import threading
import time
import os

app = Flask(__name__)


ASSUME_PREFIX = 24

NMAP_EXE_PATH = None  


# memoria en servidor: ip -> {'ip','mac','hostname','last_seen'}
seen = {}
seen_lock = threading.Lock()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def create_scanner():
    if NMAP_EXE_PATH:
        return nmap.PortScanner(nmap_search_path=(NMAP_EXE_PATH,))
    return nmap.PortScanner()


def scan_network(cidr):
    """Usa nmap -sn para descubrir hosts activos y devuelve lista de dicts."""
    scanner = create_scanner()
    scanner.scan(hosts=cidr, arguments='-sn')
    devices = []
    for host in scanner.all_hosts():
        addr = scanner[host].get('addresses', {})
        ip = addr.get('ipv4') or addr.get('ipv6') or host
        mac = addr.get('mac', 'Desconocida')
        hostname = scanner[host].hostname() or ''
        devices.append({'ip': ip, 'mac': mac, 'hostname': hostname})
    return devices


@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/scan", methods=["POST"])
def scan_endpoint():
    """
    POST JSON { "cidr": "192.168.0.0/24" }
    Responde JSON:
      { network: "...", devices: [...all seen...], new: [...], gone: [...] }
    """
    data = request.get_json(force=True, silent=True) or {}
    cidr = data.get("cidr")
    if not cidr:
        # detectar automaticamente
        local_ip = get_local_ip()
        cidr = f"{local_ip}/{ASSUME_PREFIX}"

    # validar cidr
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        cidr = str(net)
    except Exception as e:
        return jsonify({"error": f"CIDR inválido: {e}"}), 400

    try:
        devices = scan_network(cidr)
    except Exception as e:
        return jsonify({"error": f"Error ejecutando nmap: {e}. PATH: {os.environ.get('PATH','')}" }), 500

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    new = []
    gone = []

    with seen_lock:
        current_ips = set(d["ip"] for d in devices)
        previous_ips = set(seen.keys())

        # detectar nuevos
        for d in devices:
            ip = d["ip"]
            if ip not in seen:
                new.append(d)
            # actualizar/añadir
            seen[ip] = {'ip': ip, 'mac': d.get('mac',''), 'hostname': d.get('hostname',''), 'last_seen': now}

        # detectar gone (estaban antes y ya no)
        for ip in previous_ips - current_ips:
            gone.append(seen[ip])
            # mantener el registro en seen para mostrar gris en UI (no borramos automáticamente)

    # construir respuesta: combinar seen (para que frontend muestre todo)
    with seen_lock:
        combined = list(seen.values())

    return jsonify({
        "network": cidr,
        "devices": combined,
        "new": new,
        "gone": gone
    })



# HTML (plantilla única)

INDEX_HTML = r"""
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Escáner de Red (Nmap) - Web</title>
  <style>
    body{ font-family: Arial, Helvetica, sans-serif; padding:18px; background:#f5f6f8; }
    h1{ margin:0 0 12px 0; }
    .controls{ margin-bottom:12px; display:flex; gap:8px; align-items:center; }
    input[type=text]{ padding:6px 8px; width:260px; border:1px solid #ccc; border-radius:4px; }
    button{ padding:7px 12px; border-radius:6px; border:none; background:#007bff; color:white; cursor:pointer; }
    button:disabled{ opacity:0.6; cursor:not-allowed; }
    table{ width:100%; border-collapse:collapse; background:white; box-shadow:0 1px 3px rgba(0,0,0,0.08); }
    th, td{ padding:10px 8px; border-bottom:1px solid #eee; text-align:left; font-size:14px; }
    th{ background:#222; color:white; position:sticky; top:0; }
    td.statuscol{ width:80px; text-align:center; }
    .circle { width:14px; height:14px; border-radius:50%; display:inline-block; vertical-align:middle; box-shadow:0 0 0 1px rgba(0,0,0,0.05) inset;}
    .green{ background:#2ecc71; }
    .gray{ background:#bdbdbd; }
    .small{ color:#666; font-size:13px; }
    .newrow{ background:linear-gradient(90deg, rgba(46,204,113,0.07), transparent); }
  </style>
</head>
<body>
  <h1> Escáner de Red</h1>

  <div class="controls">
    <label for="cidr">Rango (CIDR):</label>
    <input id="cidr" type="text" placeholder="192.168.0.0/24" />
    <button id="scanBtn">Escanear ahora</button>
    <button id="clearBtn">Limpiar lista</button>
    <div style="margin-left:auto;"><span id="status" class="small">Listo</span></div>
  </div>

  <table id="tbl">
    <thead>
      <tr><th>IP</th><th>MAC</th><th>Hostname</th><th class="statuscol">Estado</th></tr>
    </thead>
    <tbody></tbody>
  </table>

<script>
const scanBtn = document.getElementById('scanBtn');
const statusEl = document.getElementById('status');
const cidrInput = document.getElementById('cidr');
const clearBtn = document.getElementById('clearBtn');
const tbody = document.querySelector('#tbl tbody');

// memoria cliente para comparar y marcar filas nuevas/desconectadas
let clientSeen = {}; // ip -> {ip,mac,hostname,last_seen}

function renderTable(devices, newList, goneList) {
  // devices: array de objetos desde servidor (seen combined)
  // newList: lista de dispositivos nuevos
  // goneList: lista de dispositivos desconectados (previos que no respondieron ahora)

  // actualizar clientSeen con lo que venga del servidor (preservar order)
  clientSeen = {}; 
  devices.forEach(d => clientSeen[d.ip] = d);

  tbody.innerHTML = '';

  // Primero mostrar activos (aquellos que fueron detectados recientemente: su ip está en newList OR su ip aparece en devices y no en gone)
  const goneIps = new Set(goneList.map(x=>x.ip));
  const newIps = new Set(newList.map(x=>x.ip));

  // mostrar activos (devices - those shown as gone)
  devices.forEach(d => {
    const isGone = goneIps.has(d.ip);
    const row = document.createElement('tr');
    if (newIps.has(d.ip)) row.classList.add('newrow');

    const ipTd = document.createElement('td'); ipTd.textContent = d.ip;
    const macTd = document.createElement('td'); macTd.textContent = d.mac || '';
    const hostTd = document.createElement('td'); hostTd.textContent = d.hostname || '';

    const stTd = document.createElement('td');
    stTd.className = 'statuscol';
    const circle = document.createElement('span');
    circle.className = 'circle ' + (isGone ? 'gray' : 'green');
    stTd.appendChild(circle);

    row.appendChild(ipTd);
    row.appendChild(macTd);
    row.appendChild(hostTd);
    row.appendChild(stTd);

    tbody.appendChild(row);
  });

  // Luego mostrar los gone (que estaban antes y no ahora) — el servidor ya dejó esos registros en seen
  goneList.forEach(d => {
    // si el gone ya está en devices arriba, se omitirá
    if (clientSeen[d.ip]) {
      // but if it's present in combined, and was gone, server already flagged it as gone; ensure visual grey:
      // find and update - but we already painted above; skip to avoid duplicates.
      return;
    }
    const row = document.createElement('tr');
    const ipTd = document.createElement('td'); ipTd.textContent = d.ip;
    const macTd = document.createElement('td'); macTd.textContent = d.mac || '';
    const hostTd = document.createElement('td'); hostTd.textContent = d.hostname || '';
    const stTd = document.createElement('td'); stTd.className = 'statuscol';
    const circle = document.createElement('span'); circle.className = 'circle gray';
    stTd.appendChild(circle);
    row.appendChild(ipTd); row.appendChild(macTd); row.appendChild(hostTd); row.appendChild(stTd);
    tbody.appendChild(row);
  });
}

async function doScan() {
  scanBtn.disabled = true;
  statusEl.textContent = 'Escaneando...';
  const cidr = cidrInput.value.trim();
  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ cidr: cidr || undefined })
    });
    const j = await res.json();
    if (j.error) {
      statusEl.textContent = 'Error: ' + j.error;
      scanBtn.disabled = false;
      return;
    }
    // j.devices: combined seen; j.new: nuevos; j.gone: desconectados
    renderTable(j.devices || [], j.new || [], j.gone || []);
    statusEl.textContent = `Red: ${j.network} — ${ (j.devices || []).length } registrados (últ: ${new Date().toLocaleTimeString()})`;
  } catch (err) {
    statusEl.textContent = 'Error: ' + err;
  } finally {
    scanBtn.disabled = false;
  }
}

scanBtn.addEventListener('click', doScan);
clearBtn.addEventListener('click', ()=> {
  tbody.innerHTML = '';
  clientSeen = {};
  statusEl.textContent = 'Lista limpiada';
});

// detectar ip local por defecto para el input (consulta al backend opcional)
window.addEventListener('load', async () => {
  // pedimos un scan vacío para que backend detecte la red si no pones cidr
  // pero no queremos escanear al cargar; solo llenar el campo con la red detectada.
  try {
    const auto = await fetch('/scan', { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({}) });
    const j = await auto.json();
    if (!j.error && j.network) {
      cidrInput.value = j.network;
      statusEl.textContent = `Red detectada: ${j.network}`;
    }
  } catch(e){
    // no hacemos nada
  }
});
</script>
</body>
</html>
"""

# -------------------------
if __name__ == "__main__":
    # advertencia informativa si nmap no disponible
    try:
        create_scanner()
    except Exception as e:
        print("Advertencia: no se pudo crear nmap.PortScanner. Asegúrate de que Nmap esté instalado y accesible.")
        print("Error:", e)
    app.run(host="127.0.0.1", port=5000, debug=True)
