// WebSocket falso: responde a cada tarea con datos ficticios (solo para capturas)
(() => {
  const F = (id, sev, title, rem, extra = {}) => ({id, category: 'demo', severity: sev, title, description: title, remediation: rem, evidence: '', auto_fix: false, ...extra});
  const DATA = {
    audit: [
      F('ssh_root_login','critical','Login SSH como root permitido','Establecer PermitRootLogin no',{auto_fix:true,category:'ssh'}),
      F('ssh_password_auth','high','Autenticación SSH por contraseña','PasswordAuthentication no',{auto_fix:true,category:'ssh'}),
      F('pending_security_updates','medium','12 actualizaciones de seguridad pendientes','Aplicar unattended-upgrades',{auto_fix:true,category:'updates'}),
      F('world_writable_files','medium','Ficheros con permisos 777 en /var/www','chmod 750 y revisar propietario',{category:'filesystem'}),
      F('auditd_missing','low','auditd no instalado','Instalar y habilitar auditd',{auto_fix:true,category:'logging'}),
      F('aslr','info','ASLR activado','—',{passed:true,category:'kernel'}),
    ],
    malware: [
      F('webshell_php','high','Posible webshell PHP','Poner en cuarentena y revisar accesos',{file_path:'/var/www/html/uploads/img.php'}),
      F('cron_suspicious','medium','Tarea cron que descarga y ejecuta un script','Revisar /etc/cron.d/update-cache',{file_path:'/etc/cron.d/update-cache'}),
    ],
    docker: [
      F('privileged_container','high','Contenedor en modo privilegiado: demo-app','Quitar privileged: true',{category:'docker'}),
      F('latest_image_tag','low','Imagen con tag :latest: nginx:latest','Fijar una versión concreta',{category:'docker'}),
      F('docker_socket_mount','critical','Socket de Docker montado en demo-ci','No montar /var/run/docker.sock',{category:'docker'}),
    ],
    code: [
      F('B105','medium','Contraseña hardcodeada','Mover a variable de entorno',{file_path:'demo-app/settings.py',line_number:12}),
      F('SC2086','low','Variable sin comillas','Entrecomillar "$VAR"',{file_path:'demo-app/deploy.sh',line_number:40}),
      F('secret_aws','critical','Clave de acceso AWS en el código','Revocar la clave y usar un gestor de secretos',{file_path:'demo-app/config/prod.env',line_number:3}),
    ],
    services: [F('redis_noauth','high','Redis sin contraseña','Configurar requirepass',{source_host:'10.10.0.11'}), F('nginx_tokens','low','nginx muestra su versión','server_tokens off',{source_host:'10.10.0.10'})],
    tls: [F('tls_expiring','medium','Certificado caduca en 12 días','Renovar el certificado',{source_host:'www.ejemplo-demo.es'}), F('tls10','high','TLS 1.0 habilitado','Deshabilitar TLS 1.0/1.1',{source_host:'correo.ejemplo-demo.es'})],
    web_headers: [F('no_csp','medium','Falta Content-Security-Policy','Definir una CSP',{source_host:'https://www.ejemplo-demo.es'}), F('no_hsts','medium','Falta HSTS','Strict-Transport-Security: max-age=31536000',{source_host:'https://www.ejemplo-demo.es'}), F('server_leak','low','Cabecera Server revela versión','Ocultar la versión',{source_host:'https://www.ejemplo-demo.es'})],
    web_exposure: [F('git_exposed','critical','Repositorio .git accesible públicamente','Bloquear /.git en el servidor web',{source_host:'https://www.ejemplo-demo.es'}), F('env_exposed','critical','Fichero .env accesible','Bloquear el acceso a ficheros ocultos',{source_host:'https://www.ejemplo-demo.es'})],
    api_security: [F('cors_wildcard','high','CORS permite cualquier origen con credenciales','Restringir Access-Control-Allow-Origin',{source_host:'https://api.ejemplo-demo.es'})],
    dns: [F('no_dmarc','medium','Sin registro DMARC','Publicar _dmarc con p=quarantine',{source_host:'ejemplo-demo.es'}), F('spf_softfail','low','SPF con ~all','Usar -all',{source_host:'ejemplo-demo.es'}), F('no_caa','info','Sin registro CAA','Añadir CAA',{source_host:'ejemplo-demo.es'})],
    subdomain_enum: [F('sub_dev','medium','Subdominio de desarrollo expuesto: dev.ejemplo-demo.es','Restringir el acceso',{source_host:'dev.ejemplo-demo.es'}), F('sub_mail','info','mail.ejemplo-demo.es','—',{source_host:'mail.ejemplo-demo.es'})],
    nuclei: [F('CVE-2021-41773','critical','Apache 2.4.49 path traversal (CVE-2021-41773)','Actualizar Apache',{source_host:'https://intranet.ejemplo-demo.es'})],
    network: [F('telnet_open','high','Telnet abierto','Deshabilitar telnet',{source_host:'10.10.0.23'}), F('ssh_root_login','critical','Login SSH como root permitido','PermitRootLogin no',{source_host:'10.10.0.10',auto_fix:true})],
  };
  const DEVICES = [
    {ip:'10.10.0.1',hostname:'router-demo',os_name:'Linux 5.x',open_ports:[22,53,80,443],risk_level:'low',mac:'02:00:00:aa:01:01',has_ssh:true,ssh_port:22,cves:[]},
    {ip:'10.10.0.10',hostname:'demo-web-01',os_name:'Ubuntu 24.04',open_ports:[22,80,443],risk_level:'medium',mac:'02:00:00:aa:01:0a',has_ssh:true,ssh_port:22,cves:[]},
    {ip:'10.10.0.11',hostname:'demo-db-01',os_name:'Debian 12',open_ports:[22,5432,6379],risk_level:'medium',mac:'02:00:00:aa:01:0b',has_ssh:true,ssh_port:22,cves:[]},
    {ip:'10.10.0.23',hostname:'impresora-demo',os_name:'Embedded',open_ports:[23,80,9100],risk_level:'high',mac:'02:00:00:aa:01:17',has_ssh:false,cves:['CVE-2023-0001']},
  ];
  class FakeWS {
    constructor() { setTimeout(() => this.onopen && this.onopen(), 10); }
    send(raw) {
      const {task} = JSON.parse(raw);
      const out = [];
      if (task === 'network') {
        out.push({type:'devices', data: DEVICES});
        DEVICES.filter(d => d.has_ssh).forEach(d => out.push({type:'host_result', data:{host:d.ip, status:'ok', count:1, os_info:d.os_name}}));
      }
      (DATA[task] || []).forEach(f => out.push({type:'finding', data:f}));
      out.push({type:'done', count:(DATA[task]||[]).length, scan_id: 99, score: 62});
      out.forEach((m, i) => setTimeout(() => this.onmessage && this.onmessage({data: JSON.stringify(m)}), 30 + i * 20));
    }
    close() {}
  }
  FakeWS.OPEN = 1;
  window.WebSocket = FakeWS;
})();
