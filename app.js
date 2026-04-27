const supabaseUrl = 'https://kcapmyovaigjntaqeqwn.supabase.co'
console.log("ASISTIA_BUILD_CHECK_2026_04_05_v1");
const supabaseKey = 'sb_publishable_oObf3s5mQ4sfmJ03JKQrnQ__8Rmb63F'

const supabaseClient = window.supabase?.createClient
    ? window.supabase.createClient(supabaseUrl, supabaseKey, {
        auth: {
            persistSession: true,
            autoRefreshToken: true,
            detectSessionInUrl: true,
            storageKey: "asistia-auth"
        }
    })
    : null

window.currentProfile = null;

const ROLE_PERMISSIONS = {
    superusuario: {
        usersView: true,
        usersManage: true,
        settingsView: true,
        settingsManage: true,
        attendanceView: true,
        attendanceManage: true,
        aspirantsView: true,
        aspirantsManage: true,
        reportsView: true,
        courseConfigView: true,
        courseConfigManage: true
    },
    administrador: {
        usersView: false,
        usersManage: false,
        settingsView: true,
        settingsManage: true,
        attendanceView: true,
        attendanceManage: true,
        aspirantsView: true,
        aspirantsManage: true,
        reportsView: true,
        courseConfigView: true,
        courseConfigManage: true
    },
    asistente: {
        usersView: false,
        usersManage: false,
        settingsView: false,
        settingsManage: false,
        attendanceView: true,
        attendanceManage: false,
        aspirantsView: true,
        aspirantsManage: false,
        reportsView: false,
        courseConfigView: false,
        courseConfigManage: false
    }
};

function can(permission) {
    const role = window.currentProfile?.role || 'asistente';
    return !!ROLE_PERMISSIONS[role]?.[permission];
}

async function loadCurrentProfile() {
    try {
        if (!supabaseClient) {
            window.currentProfile = null;
            return;
        }

        const { data: authData, error: authError } = await supabaseClient.auth.getUser();
        if (authError || !authData?.user?.id) {
            window.currentProfile = null;
            return;
        }

        const userId = authData.user.id;
        const { data: profileData, error: profileError } = await supabaseClient
            .from('profiles')
            .select('id, email, full_name, role, tenant_id, is_active')
            .eq('id', userId)
            .single();

        if (profileError || !profileData) {
            window.currentProfile = null;
            return;
        }

        if (profileData.is_active === false) {
            await supabaseClient.auth.signOut();
            window.currentProfile = null;
            throw new Error("Perfil inactivo.");
        }

        window.currentProfile = profileData;
    } catch (err) {
        console.error("Error cargando perfil:", err);
        window.currentProfile = null;
    }
}

function applyRolePermissions() {
    const elements = document.querySelectorAll('[data-permission]');
    elements.forEach(el => {
        const permission = el.getAttribute('data-permission');
        if (!can(permission)) {
            el.style.display = 'none';
        } else {
            el.style.display = '';
        }
    });
}

function toggleByPermission(permission, elementId, displayStyle = 'block') {
    const el = document.getElementById(elementId);
    if (!el) return;
    if (!can(permission)) {
        el.style.display = 'none';
    } else {
        el.style.display = displayStyle;
    }
}

function renderCurrentUserInfo() {
    const nameEl = document.getElementById('currentUserName');
    const roleEl = document.getElementById('currentUserRole');
    if (window.currentProfile) {
        if (nameEl) nameEl.textContent = window.currentProfile.full_name;
        if (roleEl) roleEl.textContent = window.currentProfile.role;
    } else {
        if (nameEl) nameEl.textContent = '';
        if (roleEl) roleEl.textContent = '';
    }
}

async function bootstrapAuthorizedApp() {
    await loadCurrentProfile();
    applyRolePermissions();
    renderCurrentUserInfo();
}

let adminAutenticado = false
let dniMovil = ""
let resizeTimer
let scanningActivo = false
let cursoConfigCache = null
let ubosSedeCache = []
let cursoSecciones = []
let cursoSedesUbo = []
let editSeccionCursoIndex = -1
let editSedeUboIndex = -1
let editUsuarioIndex = -1
let usuariosAdmin = []
let cacheReportes = []
let cacheDashboard = []
let cacheRiesgoUbo = []
let vistaAdminActual = "reportes"
let vistaLuizLabsActual = "instituciones"
const TUTORIAL_STORAGE_KEY = "asistia_tutorial_visto"
let tutorialActivo = false
let tutorialPasoActual = 0
let tutorialTargetResaltado = null
const VISTA_MODO_KEY = "vistaModoManual"
const ADMIN_SESSION_KEY = "asistia_admin_session_v1"
const LUIZLABS_STORE_KEY = "asistia_luizlabs_v1"
const ACTIVITY_LOGS_KEY = "asistia_activity_logs_v1"
const ACTIVITY_LOGS_MAX = 1200
const ACTIVITY_DEVICE_KEY = "asistia_device_id_v1"
const DEFAULT_INSTITUTION_LOGO = "/asistIA_logo.png"
const MULTITENANT_MODE = true
let tenantScopeBackendReady = false
const PROFILE_MODULES = Object.freeze([
    { id: "reportes", label: "Reportes" },
    { id: "dashboard", label: "Dashboard" },
    { id: "config", label: "Configuración" },
    { id: "usuarios", label: "Usuarios" },
    { id: "actividad", label: "Logs" }
])
const ROLES_ADMIN = Object.freeze({
    SUPERUSUARIO: "superusuario",
    ADMINISTRADOR: "administrador"
})
/** Registro de tenants (slug → config). Mutado en runtime al sincronizar con Luiz-Labs (nuevas instituciones). */
const TENANTS = {
    "esbas-24": {
        id: "esbas-24",
        nombre: "XXIV Comandancia Departamental Lima Sur",
        linea: "Incorporación y ESBAS",
        curso: "Instrucción ESBAS 2026",
        logo: "/24_logo.png",
        habilitado: true,
        usuariosSistema: []
    },
    "bomberos-lurin-129": {
        id: "bomberos-lurin-129",
        nombre: "Bomberos Lurín 129",
        linea: "Módulo institucional",
        curso: "Próximamente",
        logo: "/B129logo.png",
        habilitado: false,
        usuariosSistema: []
    }
}

function listaTenantsOrdenada() {
    return Object.values(TENANTS).sort((a, b) =>
        String(a.nombre || "").localeCompare(String(b.nombre || ""), "es")
    )
}

function primerTenantFallback() {
    const vals = Object.values(TENANTS)
    return vals.length ? vals[0] : null
}
let tenantActivoId = ""
let esModoStaff = true
let accesoDirectoInstitucion = false
let mostrarSelectorStaff = false
let sesionAdminActiva = crearSesionAdminVacia()
let institucionesLuiz = []
let usuariosAdminLuiz = []
let perfilesLuiz = []
let perfilesUsuariosLocales = {}
let editUsuarioLuizIndex = -1
let editUsuarioGlobalLuizIndex = -1
let editPerfilLuizIndex = -1
let soporteLuizLabsSupabase = null
let soporteActividadLogsSupabase = null
let soporteUsuariosLuizSupabase = null
let syncLuizLabsEnCurso = null
const SYSTEM_USERS = []
const tutorialSteps = [
    {
        target: "#vistaDesktop [data-account-btn]",
        titulo: "Cuenta",
        descripcion: `Aquí puedes ver tu sesión activa:

• Usuario con el que ingresaste
• Rol (Administrador o Superusuario)
• Institución en la que estás trabajando

Esto te ayuda a evitar errores y saber en qué entorno estás operando.`
    },
    {
        target: "#vistaReportes",
        vista: "reportes",
        titulo: "Reportes",
        descripcion: `Aquí puedes consultar asistencias registradas.

Puedes:
• Filtrar por UBO
• Seleccionar rango de fechas
• Aplicar o limpiar filtros
• Ver todos los registros
• Exportar resultados a Excel

También verás alertas de marcación en la parte inferior.`
    },
    {
        target: "#vistaDashboard",
        vista: "dashboard",
        titulo: "Dashboard",
        descripcion: `Aquí ves un resumen general del sistema.

Puedes analizar:
• Total de activos
• Asistencia e inasistencia
• Cobertura
• Alertas de dispositivo
• Semáforo de puntualidad
• Riesgo por UBO

El semáforo usa la primera marcación del último día y la compara con la hora de inicio/días de la sección.`
    },
    {
        target: "#vistaConfig",
        vista: "config",
        titulo: "Configuración",
        descripcion: `Aquí administras la operación del sistema.

Puedes:
• Cargar coordenadas GPS de UBO
• Cargar aspirantes desde Excel
• Retirar o reactivar aspirantes
• Configurar curso, secciones y sedes

Este módulo define cómo funciona todo el control de asistencia.`
    },
    {
        target: "#vistaUsuarios",
        vista: "usuarios",
        titulo: "Usuarios",
        descripcion: `Aquí gestionas accesos administrativos.

Puedes:
• Crear usuarios
• Editarlos
• Desactivarlos
• Asignar roles

Solo administras usuarios de esta institución.`
    }
]

// SECTION_TO_UBO_FIELD legacy definition removed

function enlazarIdsGlobales() {
    document.querySelectorAll("[id]").forEach(el => {
        if (!(el.id in window)) {
            window[el.id] = el
        }
    })
}

function haySupabase() {
    return !!supabaseClient
}

function mapearActividadSupabaseALocal(row) {
    let detalle = row?.detalle || {}
    if (typeof detalle === "string") {
        try {
            detalle = JSON.parse(detalle)
        } catch (_) {
            detalle = { valor: detalle }
        }
    }
    if (!detalle || typeof detalle !== "object") {
        detalle = {}
    }
    return {
        id: String(row?.id || `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`),
        fecha: row?.fecha || new Date().toISOString(),
        accion: String(row?.accion || ""),
        usuario: String(row?.usuario || "sistema"),
        rol: normalizarRolUsuario(row?.rol || ""),
        tenantId: String(row?.tenant_id || ""),
        tenantNombre: String(row?.tenant_nombre || ""),
        entorno: String(row?.entorno || ""),
        ruta: String(row?.ruta || ""),
        deviceId: String(row?.device_id || ""),
        deviceLabel: String(row?.device_label || ""),
        ip: String(row?.ip || "N/D"),
        deviceUa: String(row?.device_ua || ""),
        detalle
    }
}

async function cargarActividadLogsDesdeSupabase() {
    if (!haySupabase()) return null
    if (soporteActividadLogsSupabase === false) return null
    const { data, error } = await supabaseClient
        .from("actividad_logs")
        .select("id,fecha,accion,usuario,rol,tenant_id,tenant_nombre,entorno,ruta,device_label,device_id,ip,device_ua,detalle")
        .order("fecha", { ascending: false })
        .limit(ACTIVITY_LOGS_MAX)

    if (error) {
        if (esTablaNoExiste(error)) {
            soporteActividadLogsSupabase = false
            return null
        }
        console.warn("No se pudo cargar actividad_logs:", error.message)
        return null
    }

    soporteActividadLogsSupabase = true
    return (data || []).map(mapearActividadSupabaseALocal)
}

async function insertarActividadLogEnSupabase(entry) {
    if (!haySupabase()) return
    if (soporteActividadLogsSupabase === false) return
    if (!esModoStaff) {
        return
    }

    const payload = {
        fecha: entry.fecha || new Date().toISOString(),
        accion: String(entry.accion || ""),
        usuario: String(entry.usuario || "sistema"),
        rol: normalizarRolUsuario(entry.rol || ""),
        tenant_id: String(entry.tenantId || "") || null,
        tenant_nombre: String(entry.tenantNombre || ""),
        entorno: String(entry.entorno || ""),
        ruta: String(entry.ruta || ""),
        device_label: String(entry.deviceLabel || ""),
        device_id: String(entry.deviceId || ""),
        ip: String(entry.ip || "N/D"),
        device_ua: String(entry.deviceUa || ""),
        detalle: (entry.detalle && typeof entry.detalle === "object") ? entry.detalle : {}
    }
    const { error } = await supabaseClient.from("actividad_logs").insert([payload])
    if (error) {
        if (esTablaNoExiste(error)) {
            soporteActividadLogsSupabase = false
            return
        }
        console.warn("No se pudo insertar actividad log:", error.message)
    } else {
        soporteActividadLogsSupabase = true
    }
}

async function hidratarActividadLogsInicial() {
    const logsLocales = leerActividadLogs()
    const logsSupabase = await cargarActividadLogsDesdeSupabase()
    if (!Array.isArray(logsSupabase)) {
        return
    }
    if (logsSupabase.length) {
        guardarActividadLogs(logsSupabase)
        return
    }
    if (logsLocales.length) {
        for (const entry of logsLocales.slice(0, 200).reverse()) {
            await insertarActividadLogEnSupabase(entry)
        }
    }
}

function leerActividadLogs() {
    try {
        const raw = localStorage.getItem(ACTIVITY_LOGS_KEY)
        if (!raw) return []
        const data = JSON.parse(raw)
        return Array.isArray(data) ? data : []
    } catch (e) {
        console.warn("No se pudo leer logs de actividad:", e)
        return []
    }
}

function guardarActividadLogs(logs) {
    try {
        localStorage.setItem(ACTIVITY_LOGS_KEY, JSON.stringify(logs || []))
    } catch (e) {
        console.warn("No se pudo guardar logs de actividad:", e)
    }
}

function obtenerIdDispositivoActividad() {
    try {
        let id = String(localStorage.getItem(ACTIVITY_DEVICE_KEY) || "").trim()
        if (!id) {
            id = `dev_${Math.random().toString(36).slice(2, 10)}`
            localStorage.setItem(ACTIVITY_DEVICE_KEY, id)
        }
        return id
    } catch (e) {
        return "dev_na"
    }
}

function obtenerEtiquetaDispositivoActividad() {
    const ua = String(navigator.userAgent || "")
    if (/iPhone/i.test(ua)) return "iPhone"
    if (/iPad/i.test(ua)) return "iPad"
    if (/Android/i.test(ua)) return "Android"
    if (/Windows/i.test(ua)) return "Windows"
    if (/Macintosh|Mac OS X/i.test(ua)) return "Mac"
    if (/Linux/i.test(ua)) return "Linux"
    return "Desconocido"
}

function obtenerContextoActividad() {
    const sesion = sesionAdminActiva || crearSesionAdminVacia()
    const tenantId = String(sesion.tenantId || tenantActivoId || "").trim()
    return {
        usuario: String(sesion.usuario || "sistema").trim().toLowerCase() || "sistema",
        rol: normalizarRolUsuario(sesion.rol || ""),
        tenantId,
        tenantNombre: obtenerNombreTenantUI(tenantId),
        entorno: esModoStaff ? "staff_root" : "tenant_route",
        ruta: String(window.location.pathname || "/"),
        deviceId: obtenerIdDispositivoActividad(),
        deviceLabel: obtenerEtiquetaDispositivoActividad(),
        ip: "N/D navegador",
        deviceUa: String(navigator.userAgent || "")
    }
}

function registrarActividad(accion, detalle = {}, opts = {}) {
    const nombreAccion = String(accion || "").trim()
    if (!nombreAccion) return
    const now = new Date()
    const contexto = obtenerContextoActividad()
    const overrideTenantId = String(opts.tenantId || "").trim()
    const tenantIdFinal = overrideTenantId || contexto.tenantId

    const entry = {
        id: `${now.getTime()}_${Math.random().toString(36).slice(2, 8)}`,
        fecha: now.toISOString(),
        accion: nombreAccion,
        usuario: String(opts.usuario || contexto.usuario || "sistema").toLowerCase(),
        rol: normalizarRolUsuario(opts.rol || contexto.rol || ""),
        tenantId: tenantIdFinal,
        tenantNombre: obtenerNombreTenantUI(tenantIdFinal),
        entorno: String(opts.entorno || contexto.entorno || ""),
        ruta: String(opts.ruta || contexto.ruta || "/"),
        deviceId: String(opts.deviceId || contexto.deviceId || "dev_na"),
        deviceLabel: String(opts.deviceLabel || contexto.deviceLabel || "Desconocido"),
        ip: String(opts.ip || contexto.ip || "N/D"),
        deviceUa: String(opts.deviceUa || contexto.deviceUa || ""),
        detalle: (detalle && typeof detalle === "object") ? detalle : { valor: String(detalle || "") }
    }

    const logs = leerActividadLogs()
    logs.unshift(entry)
    if (logs.length > ACTIVITY_LOGS_MAX) {
        logs.length = ACTIVITY_LOGS_MAX
    }
    guardarActividadLogs(logs)
    void insertarActividadLogEnSupabase(entry)
}

function obtenerActividadPorScope(scope = "actual") {
    const logs = leerActividadLogs()
    if (scope === "global") {
        return logs
    }
    if (scope === "tenant") {
        const tenant = String(tenantActivoId || "").trim()
        return logs.filter(x => String(x?.tenantId || "").trim() === tenant)
    }
    if (scope === "sesion") {
        const sesion = obtenerSesionAdminActiva()
        if (esModoStaff && esSuperusuarioActivo()) {
            return logs
        }
        const tenant = String(sesion.tenantId || tenantActivoId || "").trim()
        return logs.filter(x => String(x?.tenantId || "").trim() === tenant)
    }
    return logs
}

function formatearFechaActividad(value) {
    const raw = String(value || "").trim()
    if (!raw) return "-"
    const d = new Date(raw)
    if (Number.isNaN(d.getTime())) return raw
    return d.toLocaleString("es-PE", { hour12: false })
}

function humanizarAccionActividad(accion) {
    const mapa = {
        login_admin: "Login admin",
        login_admin_institucional: "Login admin institucional",
        logout_admin: "Logout admin",
        institucion_creada: "Institución creada",
        institucion_editada: "Institución editada",
        institucion_estado_actualizado: "Estado institución actualizado",
        institucion_eliminada: "Institución eliminada",
        institucion_ingresar_desde_luizlabs: "Ingreso a institución",
        institucion_enlace_copiado: "Enlace institución copiado",
        usuario_global_creado: "Usuario global creado",
        usuario_global_editado: "Usuario global editado",
        usuario_global_estado_actualizado: "Estado usuario global actualizado",
        usuario_global_eliminado: "Usuario global eliminado",
        usuario_admin_luiz_creado: "Usuario admin institucional creado",
        usuario_admin_luiz_editado: "Usuario admin institucional editado",
        usuario_admin_institucional_creado: "Usuario admin local creado",
        usuario_admin_institucional_editado: "Usuario admin local editado",
        usuario_admin_institucional_desactivado: "Usuario admin local desactivado",
        usuario_estado_actualizado: "Estado usuario actualizado",
        usuario_eliminado: "Usuario eliminado",
        usuario_clave_regenerada: "Clave regenerada",
        aspirantes_carga_excel: "Carga de aspirantes",
        gps_carga_coordenadas: "Carga de coordenadas GPS",
        configuracion_curso_guardada: "Configuración de curso guardada",
        seccion_curso_creada: "Sección creada",
        seccion_curso_editada: "Sección editada",
        seccion_curso_eliminada: "Sección eliminada",
        sede_ubo_creada: "Sede UBO creada",
        sede_ubo_editada: "Sede UBO editada",
        sede_ubo_eliminada: "Sede UBO eliminada",
        aspirante_retirado: "Aspirante retirado",
        aspirante_reactivado: "Aspirante reactivado",
        perfil_creado: "Perfil creado",
        perfil_editado: "Perfil editado",
        perfil_estado_actualizado: "Estado de perfil actualizado",
        perfil_eliminado: "Perfil eliminado"
    }
    return mapa[String(accion || "")] || String(accion || "-")
}

function resumirDetalleActividad(detalle) {
    if (!detalle || typeof detalle !== "object") return "-"
    const keys = Object.keys(detalle).slice(0, 4)
    if (!keys.length) return "-"
    return keys.map(k => {
        const v = detalle[k]
        if (Array.isArray(v)) return `${k}: ${v.join(", ")}`
        if (v && typeof v === "object") return `${k}: [objeto]`
        return `${k}: ${String(v)}`
    }).join(" | ")
}

function filtrarLogsActividad(logs = [], opts = {}) {
    const texto = String(opts.texto || "").trim().toLowerCase()
    const desde = String(opts.desde || "").trim()
    const hasta = String(opts.hasta || "").trim()
    const tenant = String(opts.tenantId || "").trim()

    return (logs || []).filter(item => {
        const fechaIso = String(item?.fecha || "")
        const fechaDia = fechaIso.slice(0, 10)
        if (desde && fechaDia < desde) return false
        if (hasta && fechaDia > hasta) return false
        if (tenant && String(item?.tenantId || "") !== tenant) return false

        if (!texto) return true
        const blob = [
            item?.accion,
            item?.usuario,
            item?.rol,
            item?.deviceLabel,
            item?.deviceId,
            item?.ip,
            item?.tenantNombre,
            item?.ruta,
            JSON.stringify(item?.detalle || {})
        ].join(" ").toLowerCase()
        return blob.includes(texto)
    })
}

function poblarFiltroTenantLogsGlobal() {
    const el = document.getElementById("filtroActividadGlobalTenant")
    if (!el) return
    const prev = el.value || ""
    let html = `<option value="">Todas las instituciones</option>`
    listaTenantsOrdenada().forEach(t => {
        html += `<option value="${t.id}">${t.nombre}</option>`
    })
    el.innerHTML = html
    if (prev && TENANTS[prev]) {
        el.value = prev
    }
}

function renderTablaActividadTenant(rows = []) {
    const tbody = document.getElementById("tablaActividadTenant")
    if (!tbody) return
    if (!rows.length) {
        tbody.innerHTML = `<tr><td colspan="6">Sin actividad en este tenant.</td></tr>`
        return
    }
    let html = ""
    rows.slice(0, 500).forEach(item => {
        html += `
      <tr>
        <td>${formatearFechaActividad(item.fecha)}</td>
        <td>${humanizarAccionActividad(item.accion)}</td>
        <td>${item.usuario || "-"}</td>
        <td>${item.deviceLabel || "Desconocido"}<br><span class="hint">${item.deviceId || "-"}</span></td>
        <td>${obtenerNombreRolUI(item.rol)}</td>
        <td>${resumirDetalleActividad(item.detalle)}</td>
      </tr>
    `
    })
    tbody.innerHTML = html
}

function renderTablaActividadGlobal(rows = []) {
    const tbody = document.getElementById("tablaActividadGlobal")
    if (!tbody) return
    if (!rows.length) {
        tbody.innerHTML = `<tr><td colspan="7">Sin actividad registrada.</td></tr>`
        return
    }
    let html = ""
    rows.slice(0, 700).forEach(item => {
        html += `
      <tr>
        <td>${formatearFechaActividad(item.fecha)}</td>
        <td>${humanizarAccionActividad(item.accion)}</td>
        <td>${item.usuario || "-"}</td>
        <td>${item.deviceLabel || "Desconocido"}<br><span class="hint">${item.deviceId || "-"}</span></td>
        <td>${obtenerNombreRolUI(item.rol)}</td>
        <td>${item.tenantNombre || "Plataforma asistIA"}</td>
        <td>${resumirDetalleActividad(item.detalle)}</td>
      </tr>
    `
    })
    tbody.innerHTML = html
}

function actualizarEtiquetaRangoLogs() {
    const tenantDesde = document.getElementById("filtroActividadTenantDesde")?.value || ""
    const tenantHasta = document.getElementById("filtroActividadTenantHasta")?.value || ""
    const globalDesde = document.getElementById("filtroActividadGlobalDesde")?.value || ""
    const globalHasta = document.getElementById("filtroActividadGlobalHasta")?.value || ""
    const elTenant = document.getElementById("logsTenantRangeLabel")
    const elGlobal = document.getElementById("logsGlobalRangeLabel")
    if (elTenant) {
        elTenant.innerText = `Mostrando rango: ${tenantDesde || "-"} a ${tenantHasta || "-"}`
    }
    if (elGlobal) {
        elGlobal.innerText = `Mostrando rango: ${globalDesde || "-"} a ${globalHasta || "-"}`
    }
}

function aplicarRangoMesActualEnLogs() {
    const { from, to } = obtenerRangoMesActual()
    const elTenantDesde = document.getElementById("filtroActividadTenantDesde")
    const elTenantHasta = document.getElementById("filtroActividadTenantHasta")
    const elGlobalDesde = document.getElementById("filtroActividadGlobalDesde")
    const elGlobalHasta = document.getElementById("filtroActividadGlobalHasta")
    if (elTenantDesde && !elTenantDesde.value) elTenantDesde.value = from
    if (elTenantHasta && !elTenantHasta.value) elTenantHasta.value = to
    if (elGlobalDesde && !elGlobalDesde.value) elGlobalDesde.value = from
    if (elGlobalHasta && !elGlobalHasta.value) elGlobalHasta.value = to
    actualizarEtiquetaRangoLogs()
}

function cargarActividadTenant() {
    const base = obtenerActividadPorScope("tenant")
    const texto = document.getElementById("filtroActividadTenantTexto")?.value || ""
    const desde = document.getElementById("filtroActividadTenantDesde")?.value || ""
    const hasta = document.getElementById("filtroActividadTenantHasta")?.value || ""
    const filtrada = filtrarLogsActividad(base, { texto, desde, hasta })
    renderTablaActividadTenant(filtrada)
    actualizarEtiquetaRangoLogs()
}

function limpiarActividadTenant() {
    const elTexto = document.getElementById("filtroActividadTenantTexto")
    const elDesde = document.getElementById("filtroActividadTenantDesde")
    const elHasta = document.getElementById("filtroActividadTenantHasta")
    const { from, to } = obtenerRangoMesActual()
    if (elTexto) elTexto.value = ""
    if (elDesde) elDesde.value = from
    if (elHasta) elHasta.value = to
    cargarActividadTenant()
}

function cargarActividadGlobal() {
    const base = obtenerActividadPorScope("global")
    const texto = document.getElementById("filtroActividadGlobalTexto")?.value || ""
    const desde = document.getElementById("filtroActividadGlobalDesde")?.value || ""
    const hasta = document.getElementById("filtroActividadGlobalHasta")?.value || ""
    const tenantId = document.getElementById("filtroActividadGlobalTenant")?.value || ""
    const filtrada = filtrarLogsActividad(base, { texto, desde, hasta, tenantId })
    renderTablaActividadGlobal(filtrada)
    actualizarEtiquetaRangoLogs()
}

function limpiarActividadGlobal() {
    const elTexto = document.getElementById("filtroActividadGlobalTexto")
    const elDesde = document.getElementById("filtroActividadGlobalDesde")
    const elHasta = document.getElementById("filtroActividadGlobalHasta")
    const elTenant = document.getElementById("filtroActividadGlobalTenant")
    const { from, to } = obtenerRangoMesActual()
    if (elTexto) elTexto.value = ""
    if (elDesde) elDesde.value = from
    if (elHasta) elHasta.value = to
    if (elTenant) elTenant.value = ""
    cargarActividadGlobal()
}

function exportarActividadCSV(scope = "tenant") {
    const esGlobal = scope === "global"
    const base = obtenerActividadPorScope(esGlobal ? "global" : "tenant")
    const texto = document.getElementById(esGlobal ? "filtroActividadGlobalTexto" : "filtroActividadTenantTexto")?.value || ""
    const desde = document.getElementById(esGlobal ? "filtroActividadGlobalDesde" : "filtroActividadTenantDesde")?.value || ""
    const hasta = document.getElementById(esGlobal ? "filtroActividadGlobalHasta" : "filtroActividadTenantHasta")?.value || ""
    const tenantId = esGlobal ? (document.getElementById("filtroActividadGlobalTenant")?.value || "") : ""
    const rows = filtrarLogsActividad(base, { texto, desde, hasta, tenantId })

    if (!rows.length) {
        alert("No hay logs para exportar.")
        return
    }

    const escape = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`
    const headers = esGlobal
        ? ["fecha", "accion", "usuario", "rol", "device_label", "device_id", "ip", "tenant_id", "tenant_nombre", "ruta", "detalle"]
        : ["fecha", "accion", "usuario", "rol", "device_label", "device_id", "ip", "tenant_id", "ruta", "detalle"]
    const lines = [headers.join(",")]
    rows.forEach(item => {
        const values = esGlobal
            ? [item.fecha, item.accion, item.usuario, item.rol, item.deviceLabel, item.deviceId, item.ip, item.tenantId, item.tenantNombre, item.ruta, JSON.stringify(item.detalle || {})]
            : [item.fecha, item.accion, item.usuario, item.rol, item.deviceLabel, item.deviceId, item.ip, item.tenantId, item.ruta, JSON.stringify(item.detalle || {})]
        lines.push(values.map(escape).join(","))
    })

    const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    const sufijo = esGlobal ? "global" : (tenantActivoId || "tenant")
    a.href = url
    a.download = `asistia_logs_${sufijo}_${new Date().toISOString().slice(0, 10)}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
}

function normalizarRolUsuario(rol) {
    const raw = String(rol || "").trim().toLowerCase()
    if (raw === "super_admin" || raw === "superusuario") return ROLES_ADMIN.SUPERUSUARIO
    return ROLES_ADMIN.ADMINISTRADOR
}

function crearSesionAdminVacia() {
    return {
        autenticado: false,
        usuario: "",
        rol: "",
        tenantId: "",
        origen: "",
        perfilId: ""
    }
}

function normalizarSesionAdmin(raw) {
    const base = crearSesionAdminVacia()
    if (!raw || typeof raw !== "object") return base
    const autenticado = !!raw.autenticado
    const usuario = String(raw.usuario || "").trim().toLowerCase()
    const rol = normalizarRolUsuario(raw.rol || "")
    const tenantId = String(raw.tenantId || "").trim()
    const origen = String(raw.origen || "").trim()
    const perfilId = String(raw.perfilId || "").trim()

    if (!autenticado || !usuario) {
        return base
    }

    return {
        autenticado: true,
        usuario,
        rol,
        tenantId,
        origen,
        perfilId
    }
}

function guardarSesionAdminEnStorage() {
    try {
        if (sesionAdminActiva?.autenticado) {
            sessionStorage.setItem(ADMIN_SESSION_KEY, JSON.stringify(sesionAdminActiva))
        } else {
            sessionStorage.removeItem(ADMIN_SESSION_KEY)
        }
    } catch (e) {
        console.warn("No se pudo guardar sesión admin:", e)
    }
}

function cargarSesionAdminDesdeStorage() {
    try {
        const raw = sessionStorage.getItem(ADMIN_SESSION_KEY)
        if (!raw) {
            sesionAdminActiva = crearSesionAdminVacia()
            sincronizarEstadoLegacyAdmin()
            return sesionAdminActiva
        }
        sesionAdminActiva = normalizarSesionAdmin(JSON.parse(raw))
    } catch (e) {
        console.warn("No se pudo leer sesión admin:", e)
        sesionAdminActiva = crearSesionAdminVacia()
    }
    sincronizarEstadoLegacyAdmin()
    return sesionAdminActiva
}

function sincronizarEstadoLegacyAdmin() {
    adminAutenticado = !!sesionAdminActiva?.autenticado
}

function setSesionAdminActiva(sesion) {
    sesionAdminActiva = normalizarSesionAdmin(sesion)
    guardarSesionAdminEnStorage()
    sincronizarEstadoLegacyAdmin()
    actualizarInfoSesionHeader()
    return sesionAdminActiva
}

function actualizarSesionAdmin(parcial) {
    const next = Object.assign({}, sesionAdminActiva || crearSesionAdminVacia(), parcial || {})
    return setSesionAdminActiva(next)
}

function limpiarSesionAdminActiva() {
    sesionAdminActiva = crearSesionAdminVacia()
    guardarSesionAdminEnStorage()
    sincronizarEstadoLegacyAdmin()
    actualizarInfoSesionHeader()
}

function obtenerSesionAdminActiva() {
    return Object.assign({}, sesionAdminActiva)
}

function haySesionAdminActiva() {
    return !!sesionAdminActiva?.autenticado
}

function rolAdminActivo() {
    return sesionAdminActiva?.rol || ""
}

function esSuperusuarioActivo() {
    return rolAdminActivo() === ROLES_ADMIN.SUPERUSUARIO
}

function esAdministradorActivo() {
    return rolAdminActivo() === ROLES_ADMIN.ADMINISTRADOR
}

function tenantSesionActiva() {
    return String(sesionAdminActiva?.tenantId || "")
}

function obtenerNombreRolUI(rol) {
    const normalizado = normalizarRolUsuario(rol || "")
    if (normalizado === ROLES_ADMIN.SUPERUSUARIO) return "Superusuario"
    return "Administrador"
}

function obtenerNombreTenantUI(tenantId) {
    const id = String(tenantId || "").trim()
    if (!id) return "Plataforma asistIA"
    const instLuiz = (institucionesLuiz || []).find(x => String(x.slug || "") === id)
    if (instLuiz?.nombre) return instLuiz.nombre
    const tenant = TENANTS[id]
    return tenant?.nombre || id
}

function permisosPerfilFull() {
    const out = {}
    PROFILE_MODULES.forEach(m => { out[m.id] = true })
    return out
}

function normalizarPermisosPerfil(permisos) {
    const out = {}
    PROFILE_MODULES.forEach(m => {
        out[m.id] = !!(permisos && permisos[m.id])
    })
    return out
}

function perfilesBaseLuiz() {
    return [
        {
            id: "administrador",
            nombre: "Administrador",
            estado: "activo",
            permisos: permisosPerfilFull(),
            system: true,
            fecha_creacion: new Date().toISOString()
        },
        {
            id: "staff",
            nombre: "Staff",
            estado: "activo",
            permisos: normalizarPermisosPerfil({
                reportes: true,
                dashboard: true,
                config: false,
                usuarios: false,
                actividad: true
            }),
            system: true,
            fecha_creacion: new Date().toISOString()
        }
    ]
}

function normalizarPerfilId(id) {
    const raw = String(id || "").trim().toLowerCase()
    if (!raw) return ""
    return raw
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .replace(/[^a-z0-9_-]+/g, "-")
        .replace(/^-+|-+$/g, "")
}

function obtenerPerfilPorId(perfilId) {
    const id = String(perfilId || "").trim().toLowerCase()
    if (!id) return null
    return (perfilesLuiz || []).find(p => String(p.id || "").toLowerCase() === id) || null
}

function obtenerPerfilUsuarioActivo() {
    if (!haySesionAdminActiva()) return null
    if (esSuperusuarioActivo()) return null
    const sesion = obtenerSesionAdminActiva()
    const perfilSesion = obtenerPerfilPorId(sesion.perfilId)
    if (perfilSesion) return perfilSesion

    const userLuiz = (usuariosAdminLuiz || []).find(u => String(u.usuario || "").toLowerCase() === String(sesion.usuario || "").toLowerCase())
    if (userLuiz?.perfilId) {
        return obtenerPerfilPorId(userLuiz.perfilId) || null
    }
    return obtenerPerfilPorId("administrador")
}

function usuarioPuedeVerVista(vista) {
    const key = String(vista || "").trim()
    if (!key) return true
    if (esSuperusuarioActivo()) return true
    const perfil = obtenerPerfilUsuarioActivo()
    if (!perfil || String(perfil.estado || "activo") !== "activo") return key === "dashboard"
    const permisos = normalizarPermisosPerfil(perfil.permisos || {})
    if (!(key in permisos)) return true
    return !!permisos[key]
}

function aplicarPermisosVistasPorPerfil(vista) {
    if (usuarioPuedeVerVista(vista)) return vista
    const ordenFallback = ["dashboard", "reportes", "actividad", "config", "usuarios"]
    const alternativa = ordenFallback.find(v => usuarioPuedeVerVista(v))
    return alternativa || "dashboard"
}

function renderPerfilPermisosEditor(perfil = null) {
    const cont = document.getElementById("luizPerfilPermisos")
    if (!cont) return
    const permisos = normalizarPermisosPerfil(perfil?.permisos || permisosPerfilFull())
    let html = ""
    PROFILE_MODULES.forEach(m => {
        html += `
      <label>
        <input type="checkbox" data-perfil-permiso="${m.id}" ${permisos[m.id] ? "checked" : ""}>
        ${m.label}
      </label>
    `
    })
    cont.innerHTML = html
}

function leerPermisosPerfilDesdeUI() {
    const out = {}
    PROFILE_MODULES.forEach(m => {
        const el = document.querySelector(`#luizPerfilPermisos input[data-perfil-permiso="${m.id}"]`)
        out[m.id] = !!el?.checked
    })
    return out
}

function limpiarPerfilLuizForm() {
    editPerfilLuizIndex = -1
    if (luizPerfilNombre) luizPerfilNombre.value = ""
    if (luizPerfilEstado) luizPerfilEstado.value = "activo"
    renderPerfilPermisosEditor()
}

function cancelarEdicionPerfilLuiz() {
    limpiarPerfilLuizForm()
}

function editarPerfilLuiz(idx) {
    if (!puedeEntrarPanelLuizLabs()) return
    const perfil = perfilesLuiz[idx]
    if (!perfil) return
    editPerfilLuizIndex = idx
    if (luizPerfilNombre) luizPerfilNombre.value = perfil.nombre || ""
    if (luizPerfilEstado) luizPerfilEstado.value = perfil.estado || "activo"
    renderPerfilPermisosEditor(perfil)
}

function guardarPerfilLuiz() {
    if (!puedeEntrarPanelLuizLabs()) return
    const nombre = String(luizPerfilNombre?.value || "").trim()
    const estado = String(luizPerfilEstado?.value || "activo") === "inactivo" ? "inactivo" : "activo"
    if (!nombre) {
        alert("Ingresa el nombre del perfil.")
        return
    }
    const permisos = leerPermisosPerfilDesdeUI()
    const idBase = normalizarPerfilId(nombre)
    if (!idBase) {
        alert("Nombre de perfil no válido.")
        return
    }

    let accion = "perfil_creado"
    if (editPerfilLuizIndex >= 0) {
        const actual = perfilesLuiz[editPerfilLuizIndex]
        if (!actual) return limpiarPerfilLuizForm()
        const idFinal = actual.system ? actual.id : idBase
        const duplicado = perfilesLuiz.some((p, i) => i !== editPerfilLuizIndex && p.id === idFinal)
        if (duplicado) {
            alert("Ya existe un perfil con ese nombre.")
            return
        }
        actual.id = idFinal
        actual.nombre = nombre
        actual.estado = estado
        actual.permisos = normalizarPermisosPerfil(permisos)
        accion = "perfil_editado"
    } else {
        if (perfilesLuiz.some(p => p.id === idBase)) {
            alert("Ya existe un perfil con ese nombre.")
            return
        }
        perfilesLuiz.push({
            id: idBase,
            nombre,
            estado,
            permisos: normalizarPermisosPerfil(permisos),
            system: false,
            fecha_creacion: new Date().toISOString()
        })
    }

    guardarLuizLabsEnStorage()
    renderPanelLuizLabs()
    limpiarPerfilLuizForm()
    registrarActividad(accion, { perfil: nombre, estado, permisos })
}

function toggleEstadoPerfilLuiz(idx) {
    if (!puedeEntrarPanelLuizLabs()) return
    const perfil = perfilesLuiz[idx]
    if (!perfil) return
    perfil.estado = perfil.estado === "activo" ? "inactivo" : "activo"
    guardarLuizLabsEnStorage()
    renderPanelLuizLabs()
    registrarActividad("perfil_estado_actualizado", {
        perfil: perfil.nombre,
        estado: perfil.estado
    })
}

function eliminarPerfilLuiz(idx) {
    if (!puedeEntrarPanelLuizLabs()) return
    const perfil = perfilesLuiz[idx]
    if (!perfil) return
    if (perfil.system) {
        alert("El perfil base no puede eliminarse.")
        return
    }
    const enUso = (usuariosAdminLuiz || []).some(u => String(u.perfilId || "") === String(perfil.id || ""))
    if (enUso) {
        alert("El perfil está asignado a usuarios. Reasigna antes de eliminar.")
        return
    }
    const ok = confirm(`¿Eliminar perfil "${perfil.nombre}"?`)
    if (!ok) return
    perfilesLuiz.splice(idx, 1)
    guardarLuizLabsEnStorage()
    renderPanelLuizLabs()
    limpiarPerfilLuizForm()
    registrarActividad("perfil_eliminado", { perfil: perfil.nombre })
}

function poblarPerfilesInstitucionales() {
    const el = document.getElementById("userPerfil")
    if (!el) return
    const prev = el.value || ""
    let html = `<option value="administrador">Administrador</option>`
        ; (perfilesLuiz || [])
            .filter(p => p.estado === "activo")
            .sort((a, b) => String(a.nombre || "").localeCompare(String(b.nombre || "")))
            .forEach(p => {
                html += `<option value="${p.id}">${p.nombre}</option>`
            })
    el.innerHTML = html
    el.value = (perfilesLuiz || []).some(p => p.id === prev && p.estado === "activo") ? prev : "administrador"
}

function actualizarBotonCuentaSidebar() {
    const mostrar = haySesionAdminActiva()
    document.querySelectorAll("[data-account-btn]").forEach(el => {
        el.style.display = mostrar ? "inline-flex" : "none"
    })
}

function renderCuentaModalDetalle() {
    if (!cuentaModalBody) return
    if (!haySesionAdminActiva()) {
        cuentaModalBody.innerHTML = `<p class="hint">Sin sesión activa.</p>`
        return
    }

    const sesion = obtenerSesionAdminActiva()
    const usuario = String(sesion.usuario || "").trim() || "-"
    const rolUI = obtenerNombreRolUI(sesion.rol)
    const tenantUI = obtenerNombreTenantUI(sesion.tenantId)
    const perfilUI = esSuperusuarioActivo()
        ? "Acceso total"
        : (obtenerPerfilUsuarioActivo()?.nombre || "Administrador")

    cuentaModalBody.innerHTML = `
    <div class="cuenta-row">
      <span class="cuenta-key">👤 Usuario</span>
      <span class="cuenta-value">${usuario}</span>
    </div>
    <div class="cuenta-row">
      <span class="cuenta-key">🔐 Rol</span>
      <span class="cuenta-value">${rolUI}</span>
    </div>
    <div class="cuenta-row">
      <span class="cuenta-key">🛡️ Perfil</span>
      <span class="cuenta-value">${perfilUI}</span>
    </div>
    <div class="cuenta-row">
      <span class="cuenta-key">🏢 Entorno</span>
      <span class="cuenta-value">${tenantUI}</span>
    </div>
  `
}

function abrirCuentaModal() {
    if (!haySesionAdminActiva()) return
    renderCuentaModalDetalle()
    if (!cuentaModal) return
    cuentaModal.style.display = "flex"
    cuentaModal.setAttribute("aria-hidden", "false")
}

function cerrarCuentaModal() {
    if (!cuentaModal) return
    cuentaModal.style.display = "none"
    cuentaModal.setAttribute("aria-hidden", "true")
}

function cerrarCuentaModalPorBackdrop(e) {
    if (e?.target?.id === "cuentaModal") {
        cerrarCuentaModal()
    }
}

function renderInfoSesionHeader() {
    actualizarBotonCuentaSidebar()
    if (cuentaModal?.style?.display === "flex") {
        renderCuentaModalDetalle()
    }
}

function actualizarInfoSesionHeader() {
    renderInfoSesionHeader()
}

function esTutorialModoMovil() {
    return window.innerWidth <= 760 || getVistaActiva() === "mobile"
}

function limpiarResalteTutorial() {
    if (tutorialTargetResaltado) {
        tutorialTargetResaltado.classList.remove("tutorial-spotlight-target")
        tutorialTargetResaltado = null
    }
}

function obtenerTargetTutorial(step) {
    if (!step?.target) return null
    return document.querySelector(step.target)
}

function puedeIniciarTutorial() {
    return !esModoStaff &&
        haySesionAdminActiva() &&
        puedeEntrarPanelAdmin() &&
        usuarioPuedeVerVista("reportes") &&
        usuarioPuedeVerVista("dashboard") &&
        usuarioPuedeVerVista("config") &&
        usuarioPuedeVerVista("usuarios")
}

function renderTooltipTutorial(step, index) {
    const tooltip = document.getElementById("tutorialTooltip")
    if (!tooltip) return

    tooltip.innerHTML = `
    <div class="tutorial-tooltip-title">${step.titulo}</div>
    <div class="tutorial-tooltip-desc">${step.descripcion}</div>
    <div class="tutorial-tooltip-foot">
      <span class="tutorial-tooltip-step">Paso ${index + 1} de ${tutorialSteps.length}</span>
      <div class="tutorial-tooltip-actions">
        <button class="secondary" data-tutorial-prev ${index === 0 ? "disabled" : ""}>Anterior</button>
        <button class="secondary" data-tutorial-skip>Omitir</button>
        <button data-tutorial-next>${index === tutorialSteps.length - 1 ? "Finalizar" : "Siguiente"}</button>
      </div>
    </div>
  `

    tooltip.querySelector("[data-tutorial-prev]")?.addEventListener("click", anteriorPaso)
    tooltip.querySelector("[data-tutorial-next]")?.addEventListener("click", siguientePaso)
    tooltip.querySelector("[data-tutorial-skip]")?.addEventListener("click", finalizarTutorial)
}

function posicionarTooltipTutorial(target) {
    const tooltip = document.getElementById("tutorialTooltip")
    if (!tooltip) return

    const margin = 12
    const isMovil = esTutorialModoMovil()
    const tw = tooltip.offsetWidth || 340
    const th = tooltip.offsetHeight || 220

    if (isMovil || !target) {
        const top = Math.max(margin, (window.innerHeight - th) / 2)
        const left = Math.max(margin, (window.innerWidth - tw) / 2)
        tooltip.style.top = `${top}px`
        tooltip.style.left = `${left}px`
        return
    }

    const rect = target.getBoundingClientRect()
    const preferTop = rect.bottom + margin + th > window.innerHeight
    let top = preferTop ? rect.top - th - margin : rect.bottom + margin
    let left = rect.left + (rect.width / 2) - (tw / 2)

    top = Math.max(margin, Math.min(top, window.innerHeight - th - margin))
    left = Math.max(margin, Math.min(left, window.innerWidth - tw - margin))

    tooltip.style.top = `${top}px`
    tooltip.style.left = `${left}px`
}

function mostrarPaso(index) {
    if (!tutorialActivo) return

    if (index < 0) index = 0
    if (index >= tutorialSteps.length) {
        finalizarTutorial()
        return
    }

    tutorialPasoActual = index
    const step = tutorialSteps[index]

    if (step?.vista) {
        mostrarVista(step.vista)
    }

    window.setTimeout(() => {
        if (!tutorialActivo) return
        const overlay = document.getElementById("tutorialOverlay")
        const tooltip = document.getElementById("tutorialTooltip")
        if (!overlay || !tooltip) return

        const target = obtenerTargetTutorial(step)
        const isMovil = esTutorialModoMovil()

        limpiarResalteTutorial()
        if (target && !isMovil) {
            target.scrollIntoView({ behavior: "smooth", block: "center" })
            target.classList.add("tutorial-spotlight-target")
            tutorialTargetResaltado = target
        }

        renderTooltipTutorial(step, index)
        overlay.style.display = "block"
        overlay.setAttribute("aria-hidden", "false")
        tooltip.style.display = "block"
        tooltip.setAttribute("aria-hidden", "false")
        posicionarTooltipTutorial(target)
    }, 180)
}

function iniciarTutorial(forzado = false) {
    if (tutorialActivo) return
    if (!puedeIniciarTutorial()) {
        if (forzado) {
            alert("El tutorial está disponible dentro del panel administrativo institucional.")
        }
        return
    }
    if (!forzado && localStorage.getItem(TUTORIAL_STORAGE_KEY) === "true") {
        return
    }
    tutorialActivo = true
    tutorialPasoActual = 0
    mostrarPaso(0)
}

function siguientePaso() {
    mostrarPaso(tutorialPasoActual + 1)
}

function anteriorPaso() {
    mostrarPaso(tutorialPasoActual - 1)
}

function cerrarTutorial() {
    tutorialActivo = false
    limpiarResalteTutorial()
    const overlay = document.getElementById("tutorialOverlay")
    const tooltip = document.getElementById("tutorialTooltip")
    if (overlay) {
        overlay.style.display = "none"
        overlay.setAttribute("aria-hidden", "true")
    }
    if (tooltip) {
        tooltip.style.display = "none"
        tooltip.setAttribute("aria-hidden", "true")
        tooltip.innerHTML = ""
    }
}

function finalizarTutorial() {
    localStorage.setItem(TUTORIAL_STORAGE_KEY, "true")
    cerrarTutorial()
}

function evaluarInicioTutorialAutomatico() {
    if (tutorialActivo) return
    if (localStorage.getItem(TUTORIAL_STORAGE_KEY) === "true") return
    if (!puedeIniciarTutorial()) return
    iniciarTutorial(false)
}

function esTenantConDatosLegacy(tenantId) {
    return String(tenantId || "") === "esbas-24"
}

function puedeEntrarPanelAdmin(tenantId = tenantActivoId) {
    if (!haySesionAdminActiva()) return false
    if (esModoStaff) return false
    if (esSuperusuarioActivo()) return true
    return tenantSesionActiva() === String(tenantId || "")
}

function puedeEntrarPanelLuizLabs() {
    return esModoStaff && haySesionAdminActiva() && esSuperusuarioActivo()
}

function slugDesdeNombre(nombre) {
    return String(nombre || "")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
}

function generarSlugInstitucionUnico(nombre) {
    const base = slugDesdeNombre(nombre) || "institucion"
    let slug = base
    let n = 2
    while (institucionesLuiz.some(x => x.slug === slug)) {
        slug = `${base}-${n}`
        n++
    }
    return slug
}

function generarClaveTemporal(len = 8) {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    let out = ""
    for (let i = 0; i < len; i++) {
        out += chars[Math.floor(Math.random() * chars.length)]
    }
    return out
}

function generarIdInstitucion() {
    return `inst_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
}

function normalizarLogoInstitucion(logo) {
    return String(logo || "").trim()
}

function obtenerLogoInstitucion(entidad) {
    const logo = normalizarLogoInstitucion(entidad?.logo || entidad?.logoUrl || "")
    return logo || DEFAULT_INSTITUTION_LOGO
}

function leerLogoInstitucionalArchivo(file) {
    return new Promise((resolve, reject) => {
        if (!file) {
            resolve("")
            return
        }
        const tipo = String(file.type || "").toLowerCase()
        if (!/^image\/(png|jpe?g)$/.test(tipo)) {
            reject(new Error("Formato no permitido. Usa PNG, JPG o JPEG."))
            return
        }
        const maxBytes = 2 * 1024 * 1024
        if (file.size > maxBytes) {
            reject(new Error("El archivo de logo supera 2MB."))
            return
        }
        const fr = new FileReader()
        fr.onload = () => resolve(String(fr.result || ""))
        fr.onerror = () => reject(new Error("No se pudo leer el archivo de logo."))
        fr.readAsDataURL(file)
    })
}

function migrarLogosInstitucionalesBase() {
    institucionesLuiz.forEach(inst => {
        const tenantBase = TENANTS[inst.slug]
        if (!tenantBase) return
        const logoInst = normalizarLogoInstitucion(inst.logo)
        const logoBase = normalizarLogoInstitucion(tenantBase.logo)
        if (!logoInst) {
            inst.logo = logoBase
            return
        }
        // Migración incremental: reemplaza logo departamental legado por el logo base actualizado.
        if (logoInst === "/logo.png" && logoBase && logoBase !== "/logo.png") {
            inst.logo = logoBase
        }
    })
}

function guardarLuizLabsEnStorage() {
    try {
        const payload = {
            instituciones: institucionesLuiz,
            usuarios_admin: usuariosAdminLuiz,
            perfiles: perfilesLuiz,
            user_profiles: perfilesUsuariosLocales
        }
        localStorage.setItem(LUIZLABS_STORE_KEY, JSON.stringify(payload))
    } catch (e) {
        console.warn("No se pudo guardar Luiz Labs en storage:", e)
    }
    void sincronizarLuizLabsASupabase()
}

function normalizarInstitucionesSupabase(items = []) {
    return (items || []).map(inst => ({
        id: String(inst.id || generarIdInstitucion()),
        nombre: String(inst.nombre || "").trim(),
        slug: String(inst.slug || "").trim(),
        logo: normalizarLogoInstitucion(inst.logo || ""),
        estado: String(inst.estado || "activo") === "inactivo" ? "inactivo" : "activo",
        fecha_creacion: inst.fecha_creacion || new Date().toISOString()
    })).filter(inst => inst.slug && inst.nombre)
}

function normalizarPerfilesSupabase(items = []) {
    return (items || []).map(p => ({
        id: normalizarPerfilId(p.id || p.nombre || ""),
        nombre: String(p.nombre || "").trim(),
        estado: String(p.estado || "activo") === "inactivo" ? "inactivo" : "activo",
        permisos: normalizarPermisosPerfil(p.permisos || {}),
        system: !!p.system,
        fecha_creacion: p.fecha_creacion || new Date().toISOString()
    })).filter(p => p.id && p.nombre)
}

async function cargarLuizLabsDesdeSupabase() {
    if (!haySupabase()) return null
    if (soporteLuizLabsSupabase === false) return null

    const [instRes, perfRes, mapRes] = await Promise.all([
        supabaseClient
            .from("instituciones_luiz")
            .select("id,nombre,slug,estado,logo,fecha_creacion")
            .order("fecha_creacion", { ascending: true }),
        supabaseClient
            .from("perfiles_luiz")
            .select("id,nombre,estado,permisos,system,fecha_creacion")
            .order("fecha_creacion", { ascending: true }),
        supabaseClient
            .from("usuarios_perfiles_luiz")
            .select("usuario,perfil_id")
    ])

    const errores = [instRes.error, perfRes.error, mapRes.error].filter(Boolean)
    if (errores.length) {
        if (errores.some(esTablaNoExiste)) {
            soporteLuizLabsSupabase = false
            return null
        }
        console.warn("No se pudo cargar Luiz Labs desde Supabase:", errores.map(e => e.message).join(" | "))
        return null
    }

    soporteLuizLabsSupabase = true
    const instituciones = normalizarInstitucionesSupabase(instRes.data || [])
    const perfiles = normalizarPerfilesSupabase(perfRes.data || [])
    const userProfiles = {}
        ; (mapRes.data || []).forEach(row => {
            const usuario = String(row?.usuario || "").trim().toLowerCase()
            const perfilId = normalizarPerfilId(row?.perfil_id || "")
            if (usuario && perfilId) userProfiles[usuario] = perfilId
        })
    return { instituciones, perfiles, userProfiles }
}

async function sincronizarLuizLabsASupabase() {
    if (!haySupabase()) return
    if (soporteLuizLabsSupabase === false) return
    if (syncLuizLabsEnCurso) {
        return syncLuizLabsEnCurso
    }
    const institucionesPayload = (institucionesLuiz || []).map(inst => ({
        id: String(inst.id || generarIdInstitucion()),
        nombre: String(inst.nombre || "").trim(),
        slug: String(inst.slug || "").trim(),
        estado: String(inst.estado || "activo") === "inactivo" ? "inactivo" : "activo",
        logo: normalizarLogoInstitucion(inst.logo || ""),
        fecha_creacion: inst.fecha_creacion || new Date().toISOString()
    })).filter(inst => inst.slug && inst.nombre)
    const perfilesPayload = (perfilesLuiz || []).map(p => ({
        id: normalizarPerfilId(p.id || p.nombre || ""),
        nombre: String(p.nombre || "").trim(),
        estado: String(p.estado || "activo") === "inactivo" ? "inactivo" : "activo",
        permisos: normalizarPermisosPerfil(p.permisos || {}),
        system: !!p.system,
        fecha_creacion: p.fecha_creacion || new Date().toISOString()
    })).filter(p => p.id && p.nombre)
    const userProfilesPayload = Object.entries(perfilesUsuariosLocales || {})
        .map(([usuario, perfilId]) => ({
            usuario: String(usuario || "").trim().toLowerCase(),
            perfil_id: normalizarPerfilId(perfilId || "administrador")
        }))
        .filter(x => x.usuario && x.perfil_id)

    syncLuizLabsEnCurso = (async () => {
        if (institucionesPayload.length) {
            const { error } = await supabaseClient
                .from("instituciones_luiz")
                .upsert(institucionesPayload, { onConflict: "id" })
            if (error) {
                if (esTablaNoExiste(error)) {
                    soporteLuizLabsSupabase = false
                    return
                }
                console.warn("No se pudo sync instituciones_luiz:", error.message)
            } else {
                soporteLuizLabsSupabase = true
            }
        }
        if (perfilesPayload.length) {
            const { error } = await supabaseClient
                .from("perfiles_luiz")
                .upsert(perfilesPayload, { onConflict: "id" })
            if (error) {
                if (esTablaNoExiste(error)) {
                    soporteLuizLabsSupabase = false
                    return
                }
                console.warn("No se pudo sync perfiles_luiz:", error.message)
            } else {
                soporteLuizLabsSupabase = true
            }
        }
        if (userProfilesPayload.length) {
            const { error } = await supabaseClient
                .from("usuarios_perfiles_luiz")
                .upsert(userProfilesPayload, { onConflict: "usuario" })
            if (error) {
                if (esTablaNoExiste(error)) {
                    soporteLuizLabsSupabase = false
                    return
                }
                console.warn("No se pudo sync usuarios_perfiles_luiz:", error.message)
            } else {
                soporteLuizLabsSupabase = true
            }
        }
    })()
        .catch(e => {
            console.warn("Error sincronizando Luiz Labs:", e)
        })
        .finally(() => {
            syncLuizLabsEnCurso = null
        })
    return syncLuizLabsEnCurso
}

function mapearInstitucionesBaseDesdeTenants() {
    return Object.values(TENANTS).map(t => ({
        id: t.id,
        nombre: t.nombre,
        slug: t.id,
        logo: normalizarLogoInstitucion(t.logo),
        estado: t.habilitado ? "activo" : "inactivo",
        fecha_creacion: new Date().toISOString()
    }))
}

function mapearUsuariosBaseDesdeTenants() {
    const items = []
    Object.values(TENANTS).forEach(t => {
        const user = (t.usuariosSistema || [])[0]
        if (!user) return
        items.push({
            usuario: String(user).toLowerCase(),
            password: "",
            rol: ROLES_ADMIN.ADMINISTRADOR,
            tenantId: t.id,
            perfilId: "administrador",
            estado: "activo",
            fecha_creacion: new Date().toISOString()
        })
    })
    return items
}

function rolUsuarioSupabaseDesdeApp(rol) {
    return normalizarRolUsuario(rol) === ROLES_ADMIN.SUPERUSUARIO ? "super_admin" : "administrador"
}

function mapearUsuarioLuizDesdeSupabase(u) {
    const nombreRaw = String(u?.nombre || "").trim()
    const nombres = String(u?.nombres || "").trim() || nombreRaw.split(" ").slice(0, 1).join(" ")
    const apellidos = String(u?.apellidos || "").trim() || nombreRaw.split(" ").slice(1).join(" ")
    return {
        nombres,
        apellidos,
        dni: String(u?.dni || "").replace(/\D/g, ""),
        correo: String(u?.correo || "").trim().toLowerCase(),
        celular: String(u?.celular || "").replace(/\D/g, ""),
        usuario: String(u?.usuario || "").trim().toLowerCase(),
        password: String(u?.clave || ""),
        rol: normalizarRolUsuario(u?.rol || ROLES_ADMIN.ADMINISTRADOR),
        tenantId: String(u?.tenant_id || "").trim().toLowerCase(),
        estado: u?.activo === false ? "inactivo" : "activo",
        fecha_creacion: String(u?.created_at || u?.fecha_creacion || new Date().toISOString()),
        perfilId: ""
    }
}

async function cargarUsuariosLuizDesdeSupabase() {
    if (!haySupabase()) return null
    if (soporteUsuariosLuizSupabase === false) return null
    let data = []
    let error = null

        ; ({ data, error } = await supabaseClient
            .from("usuarios_admin")
            .select("id,nombre,nombres,apellidos,dni,correo,celular,usuario,clave,rol,activo,tenant_id")
            .order("id", { ascending: true }))

    if (error && /(nombres|apellidos|dni|correo|celular)/i.test(String(error.message || ""))) {
        // Fallback intermedio: conserva tenant_id para no perder aislamiento multi-tenant.
        const fallbackTenant = await supabaseClient
            .from("usuarios_admin")
            .select("id,nombre,usuario,clave,rol,activo,tenant_id")
            .order("id", { ascending: true })
        data = (fallbackTenant.data || []).map(u => Object.assign({}, u, {
            nombres: "",
            apellidos: "",
            dni: "",
            correo: "",
            celular: ""
        }))
        error = fallbackTenant.error
    }

    if (error && /tenant_id/i.test(String(error.message || ""))) {
        // Fallback legacy extremo: esquemas sin tenant_id (solo compatibilidad temporal).
        const fallback = await supabaseClient
            .from("usuarios_admin")
            .select("id,nombre,usuario,clave,rol,activo")
            .order("id", { ascending: true })
        data = (fallback.data || []).map(u => Object.assign({}, u, {
            nombres: "",
            apellidos: "",
            dni: "",
            correo: "",
            celular: "",
            tenant_id: null
        }))
        error = fallback.error
    }

    if (error) {
        if (esTablaNoExiste(error)) {
            soporteUsuariosLuizSupabase = false
            return null
        }
        console.warn("No se pudo cargar usuarios Luiz desde Supabase:", error.message)
        return null
    }

    soporteUsuariosLuizSupabase = true
    return (data || []).map(mapearUsuarioLuizDesdeSupabase)
}

async function guardarUsuarioLuizEnSupabase(user) {
    if (!haySupabase()) return true
    if (soporteUsuariosLuizSupabase === false) return false
    const usuario = String(user?.usuario || "").trim().toLowerCase()
    if (!usuario) return false
    const payload = {
        nombre: `${String(user.nombres || "").trim()} ${String(user.apellidos || "").trim()}`.trim() || usuario,
        nombres: String(user.nombres || "").trim(),
        apellidos: String(user.apellidos || "").trim(),
        dni: String(user.dni || "").replace(/\D/g, ""),
        correo: String(user.correo || "").trim().toLowerCase(),
        celular: String(user.celular || "").replace(/\D/g, ""),
        usuario,
        clave: String(user.password || user.clave || ""),
        rol: rolUsuarioSupabaseDesdeApp(user.rol || ""),
        activo: String(user.estado || "activo") !== "inactivo",
        tenant_id: String(user.tenantId || "").trim().toLowerCase() || null
    }
    let { data: existe, error: findError } = await supabaseClient
        .from("usuarios_admin")
        .select("id")
        .eq("usuario", usuario)
        .limit(1)

    if (findError) {
        console.warn("No se pudo verificar usuario Luiz en Supabase:", findError.message)
        return false
    }

    if ((existe || []).length) {
        let { error } = await supabaseClient
            .from("usuarios_admin")
            .update(payload)
            .eq("usuario", usuario)
        if (error && /(tenant_id|nombres|apellidos|dni|correo|celular)/i.test(String(error.message || ""))) {
            const fallback = await supabaseClient
                .from("usuarios_admin")
                .update({
                    nombre: payload.nombre,
                    usuario: payload.usuario,
                    clave: payload.clave,
                    rol: payload.rol,
                    activo: payload.activo
                })
                .eq("usuario", usuario)
            error = fallback.error
        }
        if (error) {
            if (esTablaNoExiste(error)) soporteUsuariosLuizSupabase = false
            console.warn("No se pudo actualizar usuario Luiz en Supabase:", error.message)
            return false
        }
        soporteUsuariosLuizSupabase = true
        return true
    }

    let { error: insertError } = await supabaseClient
        .from("usuarios_admin")
        .insert([payload])
    if (insertError && /(tenant_id|nombres|apellidos|dni|correo|celular)/i.test(String(insertError.message || ""))) {
        const fallback = await supabaseClient
            .from("usuarios_admin")
            .insert([{
                nombre: payload.nombre,
                usuario: payload.usuario,
                clave: payload.clave,
                rol: payload.rol,
                activo: payload.activo
            }])
        insertError = fallback.error
    }
    if (insertError) {
        if (esTablaNoExiste(insertError)) soporteUsuariosLuizSupabase = false
        console.warn("No se pudo insertar usuario Luiz en Supabase:", insertError.message)
        return false
    }
    soporteUsuariosLuizSupabase = true
    return true
}

async function eliminarUsuarioLuizEnSupabase(usuario) {
    if (!haySupabase()) return true
    if (soporteUsuariosLuizSupabase === false) return false
    const user = String(usuario || "").trim().toLowerCase()
    if (!user) return false
    const { error } = await supabaseClient
        .from("usuarios_admin")
        .delete()
        .eq("usuario", user)
    if (error) {
        if (esTablaNoExiste(error)) {
            soporteUsuariosLuizSupabase = false
            return false
        }
        console.warn("No se pudo eliminar usuario Luiz en Supabase:", error.message)
        return false
    }
    soporteUsuariosLuizSupabase = true
    return true
}

function esTenantProtegido(slug) {
    return slug === "esbas-24" || slug === "bomberos-lurin-129"
}

function esUsuarioProtegidoLuiz(usuario) {
    const user = String(usuario || "").trim().toLowerCase()
    return user === "llecarosd"
}

function puedeEditarDatosUsuarioProtegido(user) {
    const usuario = String(user?.usuario || "").trim().toLowerCase()
    return usuario === "llecarosd"
}

function esUsuarioGlobalAsistIA(user) {
    if (!user) return false
    const rol = normalizarRolUsuario(user.rol || "")
    if (rol === ROLES_ADMIN.SUPERUSUARIO) return true
    return !String(user.tenantId || "").trim()
}

function esUsuarioInstitucionalLuiz(user) {
    if (!user) return false
    const rol = normalizarRolUsuario(user.rol || "")
    return rol === ROLES_ADMIN.ADMINISTRADOR && !!String(user.tenantId || "").trim()
}

function asegurarUsuariosGlobalesLegacy() {
    // Legacy desactivado: los superusuarios deben existir en Supabase (usuarios_admin).
    return
}

function obtenerTenantAsignadoUsuario(usuario) {
    const user = String(usuario || "").trim().toLowerCase()
    const match = (usuariosAdminLuiz || []).find(u => String(u.usuario || "").toLowerCase() === user)
    return String(match?.tenantId || "")
}

async function cargarLuizLabsDesdeStorage() {
    let parsedLocal = null
    try {
        const raw = localStorage.getItem(LUIZLABS_STORE_KEY)
        if (raw) {
            parsedLocal = JSON.parse(raw)
        }
    } catch (e) {
        console.warn("No se pudo leer storage de Luiz Labs:", e)
    }

    // Fallback local: se usa solo si no está disponible Supabase.
    usuariosAdminLuiz = Array.isArray(parsedLocal?.usuarios_admin) ? parsedLocal.usuarios_admin : []

    let institucionesFuente = Array.isArray(parsedLocal?.instituciones) ? parsedLocal.instituciones : []
    let perfilesFuente = Array.isArray(parsedLocal?.perfiles) ? parsedLocal.perfiles : []
    let userProfilesFuente = (parsedLocal?.user_profiles && typeof parsedLocal.user_profiles === "object")
        ? parsedLocal.user_profiles
        : {}

    const remoto = await cargarLuizLabsDesdeSupabase()
    const usuariosRemotos = await cargarUsuariosLuizDesdeSupabase()
    const remotoDisponible = !!remoto
    if (remotoDisponible) {
        institucionesFuente = remoto.instituciones || []
        perfilesFuente = remoto.perfiles || []
        userProfilesFuente = remoto.userProfiles || {}
    }
    if (Array.isArray(usuariosRemotos)) {
        usuariosAdminLuiz = usuariosRemotos
    }

    institucionesLuiz = institucionesFuente
    perfilesLuiz = perfilesFuente
    perfilesUsuariosLocales = userProfilesFuente

    if (!institucionesLuiz.length) {
        institucionesLuiz = mapearInstitucionesBaseDesdeTenants()
    }
    if (!usuariosAdminLuiz.length) {
        usuariosAdminLuiz = mapearUsuariosBaseDesdeTenants()
    }

    usuariosAdminLuiz = usuariosAdminLuiz.map(u => {
        const rolNormalizado = normalizarRolUsuario(u.rol || ROLES_ADMIN.ADMINISTRADOR)
        return {
            nombres: String(u.nombres || "").trim(),
            apellidos: String(u.apellidos || "").trim(),
            dni: String(u.dni || "").replace(/\D/g, ""),
            correo: String(u.correo || "").trim().toLowerCase(),
            celular: String(u.celular || "").replace(/\D/g, ""),
            usuario: String(u.usuario || "").toLowerCase(),
            // Compatibilidad: acepta ambos formatos históricos de clave (password/clave).
            password: String(u.password || u.clave || ""),
            rol: rolNormalizado,
            tenantId: String(u.tenantId || ""),
            estado: String(u.estado || "activo") === "inactivo" ? "inactivo" : "activo",
            fecha_creacion: u.fecha_creacion || new Date().toISOString(),
            perfilId: normalizarPerfilId(u.perfilId || "")
        }
    })

    perfilesLuiz = (perfilesLuiz || []).map(p => ({
        id: normalizarPerfilId(p.id || p.nombre || ""),
        nombre: String(p.nombre || "").trim(),
        estado: String(p.estado || "activo") === "inactivo" ? "inactivo" : "activo",
        permisos: normalizarPermisosPerfil(p.permisos || {}),
        system: !!p.system,
        fecha_creacion: p.fecha_creacion || new Date().toISOString()
    })).filter(p => p.id && p.nombre)

    if (!perfilesLuiz.length) {
        perfilesLuiz = perfilesBaseLuiz()
    } else {
        perfilesBaseLuiz().forEach(base => {
            const existe = perfilesLuiz.some(p => p.id === base.id)
            if (!existe) perfilesLuiz.push(base)
        })
    }

    institucionesLuiz = institucionesLuiz.map(inst => ({
        id: String(inst.id || generarIdInstitucion()),
        nombre: String(inst.nombre || "").trim(),
        slug: String(inst.slug || "").trim(),
        logo: normalizarLogoInstitucion(inst.logo || inst.logoUrl || ""),
        estado: String(inst.estado || "activo") === "inactivo" ? "inactivo" : "activo",
        fecha_creacion: inst.fecha_creacion || new Date().toISOString()
    })).filter(inst => inst.slug && inst.nombre)

    asegurarUsuariosGlobalesLegacy()
    usuariosAdminLuiz = usuariosAdminLuiz.map(u => {
        if (normalizarRolUsuario(u.rol) !== ROLES_ADMIN.ADMINISTRADOR) return u
        const perfil = normalizarPerfilId(u.perfilId || "")
        if (perfil && obtenerPerfilPorId(perfil)) return u
        return Object.assign({}, u, { perfilId: "administrador" })
    })
    migrarLogosInstitucionalesBase()
    sincronizarTenantsDesdeInstituciones()
    guardarLuizLabsEnStorage()
}

function sincronizarTenantsDesdeInstituciones() {
    const bySlug = {}
    institucionesLuiz.forEach(inst => {
        bySlug[inst.slug] = inst
    })

    Object.values(TENANTS).forEach(t => {
        const inst = bySlug[t.id]
        if (inst) {
            t.nombre = inst.nombre
            t.logo = obtenerLogoInstitucion(inst)
            t.habilitado = inst.estado === "activo"
        }
    })

    institucionesLuiz.forEach(inst => {
        if (TENANTS[inst.slug]) return
        TENANTS[inst.slug] = {
            id: inst.slug,
            nombre: inst.nombre,
            linea: "Módulo institucional",
            curso: "Instrucción asistIA",
            logo: obtenerLogoInstitucion(inst),
            habilitado: inst.estado === "activo",
            usuariosSistema: []
        }
    })
}

function obtenerInstitucionLuiz(tenantId) {
    return institucionesLuiz.find(x => x.slug === String(tenantId || ""))
}

function mostrarVistaLuizLabs(vista) {
    let next = "instituciones"
    if (vista === "usuarios") next = "usuarios"
    if (vista === "perfiles") next = "perfiles"
    if (vista === "logs") next = "logs"
    vistaLuizLabsActual = next

    const navInst = document.getElementById("luizNavInstituciones")
    const navUsers = document.getElementById("luizNavUsuarios")
    const navPerfiles = document.getElementById("luizNavPerfiles")
    const navLogs = document.getElementById("luizNavLogs")
    if (navInst) navInst.classList.toggle("active", next === "instituciones")
    if (navUsers) navUsers.classList.toggle("active", next === "usuarios")
    if (navPerfiles) navPerfiles.classList.toggle("active", next === "perfiles")
    if (navLogs) navLogs.classList.toggle("active", next === "logs")

    const bloqueInst = document.getElementById("luizBloqueInstituciones")
    const bloqueUsers = document.getElementById("luizBloqueUsuarios")
    const bloquePerfiles = document.getElementById("luizBloquePerfiles")
    const bloqueLogs = document.getElementById("luizBloqueLogs")
    if (bloqueInst) bloqueInst.style.display = next === "instituciones" ? "block" : "none"
    if (bloqueUsers) bloqueUsers.style.display = next === "usuarios" ? "block" : "none"
    if (bloquePerfiles) bloquePerfiles.style.display = next === "perfiles" ? "block" : "none"
    if (bloqueLogs) bloqueLogs.style.display = next === "logs" ? "block" : "none"
    if (next === "perfiles") {
        renderPerfilPermisosEditor()
    }
    if (next === "logs") {
        poblarFiltroTenantLogsGlobal()
        cargarActividadGlobal()
    }
}

function renderPanelLuizLabs() {
    const tablaInst = document.getElementById("tablaInstitucionesLuiz")
    const tablaGlobal = document.getElementById("tablaUsuariosGlobalLuiz")
    const tablaUsers = document.getElementById("tablaUsuariosAdminLuiz")
    const tablaPerfiles = document.getElementById("tablaPerfilesLuiz")
    const elTenant = document.getElementById("luizUserTenant")
    const elPerfil = document.getElementById("luizUserPerfil")
    const tenantPrevio = elTenant?.value || ""
    const perfilPrevio = elPerfil?.value || ""
    if (!tablaInst || !tablaUsers || !tablaGlobal) return
    mostrarVistaLuizLabs(vistaLuizLabsActual)
    poblarFiltroTenantLogsGlobal()

    if (elTenant) {
        const institucionesActivas = institucionesLuiz.filter(i => i.estado === "activo")
        let tenantHtml = `<option value="">Seleccionar institución</option>`
        institucionesActivas.forEach(inst => {
            tenantHtml += `<option value="${inst.slug}">${inst.nombre}</option>`
        })
        elTenant.innerHTML = tenantHtml
        if (tenantPrevio && institucionesActivas.some(i => i.slug === tenantPrevio)) {
            elTenant.value = tenantPrevio
        }
    }

    if (elPerfil) {
        let perfilHtml = `<option value="">Seleccionar perfil</option>`
            ; (perfilesLuiz || [])
                .filter(p => p.estado === "activo")
                .sort((a, b) => String(a.nombre || "").localeCompare(String(b.nombre || "")))
                .forEach(p => {
                    perfilHtml += `<option value="${p.id}">${p.nombre}</option>`
                })
        elPerfil.innerHTML = perfilHtml
        if (perfilPrevio && (perfilesLuiz || []).some(p => p.id === perfilPrevio && p.estado === "activo")) {
            elPerfil.value = perfilPrevio
        }
    }

    if (!institucionesLuiz.length) {
        tablaInst.innerHTML = `<tr><td colspan="5">Sin instituciones.</td></tr>`
    } else {
        let html = ""
        institucionesLuiz
            .slice()
            .sort((a, b) => String(a.nombre).localeCompare(String(b.nombre)))
            .forEach(inst => {
                const activo = inst.estado === "activo"
                const fecha = String(inst.fecha_creacion || "").slice(0, 10)
                html += `
          <tr>
            <td class="name-col" title="${inst.nombre}">${inst.nombre}</td>
            <td class="slug-col" title="${inst.slug}">${inst.slug}</td>
            <td class="status-col">${activo ? "Activo" : "Inactivo"}</td>
            <td class="date-col">${fecha}</td>
            <td class="actions-col">
              <div class="table-actions luiz-actions">
                <button onclick="ingresarInstitucionLuizLabs('${inst.slug}')">Ingresar</button>
                <button class="icon-btn" onclick="copiarEnlaceInstitucionLuizLabs('${inst.slug}')" title="Copiar enlace" aria-label="Copiar enlace">
                  <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <rect x="9" y="3" width="11" height="14" rx="2" stroke="currentColor" stroke-width="1.8"></rect>
                    <rect x="4" y="8" width="11" height="13" rx="2" stroke="currentColor" stroke-width="1.8"></rect>
                  </svg>
                </button>
                <button onclick="editarInstitucionLuizLabs('${inst.id}')">Editar</button>
                <button
                  class="state-toggle ${activo ? "active" : ""}"
                  onclick="toggleEstadoInstitucionLuizLabs('${inst.id}')"
                  title="${activo ? "Desactivar institución" : "Activar institución"}"
                  aria-label="${activo ? "Desactivar institución" : "Activar institución"}">
                  <span class="dot"></span>
                </button>
                <button class="secondary" onclick="eliminarInstitucionLuizLabs('${inst.id}')">Eliminar</button>
              </div>
            </td>
          </tr>
        `
            })
        tablaInst.innerHTML = html
    }

    const usuariosGlobalesLocales = (usuariosAdminLuiz || [])
        .map((u, idx) => ({ u, idx, source: "local" }))
        .filter(({ u }) => esUsuarioGlobalAsistIA(u))

    const usuariosGlobalesSupabase = (usuariosAdmin || [])
        .filter(u => normalizarRolUsuario(u.rol) === ROLES_ADMIN.SUPERUSUARIO)
        .filter(u => !(usuariosAdminLuiz || []).some(l => String(l.usuario || "").toLowerCase() === String(u.usuario || "").toLowerCase()))
        .map(u => ({
            u: {
                nombres: u.nombres || "",
                apellidos: u.apellidos || "",
                dni: u.dni || "",
                correo: u.correo || "",
                celular: u.celular || "",
                usuario: u.usuario || "",
                rol: normalizarRolUsuario(u.rol),
                estado: "activo",
                fecha_creacion: "",
                system: true
            },
            idx: -1,
            source: "supabase"
        }))

    const usuariosGlobales = usuariosGlobalesLocales.concat(usuariosGlobalesSupabase)

    if (!usuariosGlobales.length) {
        tablaGlobal.innerHTML = `<tr><td colspan="10">Sin usuarios globales.</td></tr>`
    } else {
        let globalHtml = ""
        usuariosGlobales.forEach(({ u, idx, source }) => {
            const estadoUser = u.estado === "activo"
            const fechaUser = String(u.fecha_creacion || "").slice(0, 10)
            const protegido = esUsuarioProtegidoLuiz(u.usuario)
            const esSupabase = source === "supabase"
            globalHtml += `
        <tr>
          <td>${u.nombres || "-"}</td>
          <td>${u.apellidos || "-"}</td>
          <td>${u.dni || "-"}</td>
          <td>${u.correo || "-"}</td>
          <td>${u.celular || "-"}</td>
          <td>${u.usuario || ""}${protegido ? ` <span class="tag-system">PROTEGIDO</span>` : ""}${esSupabase ? ` <span class="tag-system">SUPABASE</span>` : ""}</td>
          <td>${normalizarRolUsuario(u.rol)}</td>
          <td>${estadoUser ? "Activo" : "Inactivo"}</td>
          <td>${fechaUser || "-"}</td>
          <td class="actions-col">
            <div class="table-actions luiz-actions">
              ${protegido
                    ? `
                  <button onclick="editarUsuarioGlobalLuiz(${idx})">Editar</button>
                  <span class="hint">Protegido</span>
                `
                    : esSupabase
                        ? `<span class="hint">Gestionado por Supabase</span>`
                        : `
                  <button onclick="editarUsuarioGlobalLuiz(${idx})">Editar</button>
                  <button class="secondary" onclick="regenerarClaveUsuarioAdminLuiz(${idx})" title="Regenerar clave temporal">Reset</button>
                  <button
                    class="state-toggle ${estadoUser ? "active" : ""}"
                    onclick="toggleEstadoUsuarioGlobalLuiz(${idx})"
                    title="${estadoUser ? "Desactivar usuario" : "Activar usuario"}"
                    aria-label="${estadoUser ? "Desactivar usuario" : "Activar usuario"}">
                    <span class="dot"></span>
                  </button>
                  <button class="secondary" onclick="eliminarUsuarioGlobalLuiz(${idx})">Eliminar</button>
                `
                }
            </div>
          </td>
        </tr>
      `
        })
        tablaGlobal.innerHTML = globalHtml
    }

    const usuariosInstitucionales = (usuariosAdminLuiz || [])
        .map((u, idx) => ({ u, idx }))
        .filter(({ u }) => esUsuarioInstitucionalLuiz(u))

    if (!usuariosInstitucionales.length) {
        tablaUsers.innerHTML = `<tr><td colspan="12">Sin usuarios admin.</td></tr>`
    } else {
        let usersHtml = ""
        usuariosInstitucionales.forEach(({ u, idx }) => {
            const inst = obtenerInstitucionLuiz(u.tenantId)
            const estado = inst?.estado === "activo" ? "Activa" : "Inactiva"
            const estadoUser = u.estado === "activo"
            const fechaUser = String(u.fecha_creacion || "").slice(0, 10)
            const protegido = esUsuarioProtegidoLuiz(u.usuario)
            const perfilNombre = obtenerPerfilPorId(u.perfilId)?.nombre || "Administrador"
            usersHtml += `
        <tr>
          <td>${u.nombres || "-"}</td>
          <td>${u.apellidos || "-"}</td>
          <td>${u.dni || "-"}</td>
          <td>${u.correo || "-"}</td>
          <td>${u.celular || "-"}</td>
          <td>${u.usuario || ""}${protegido ? ` <span class="tag-system">PROTEGIDO</span>` : ""}</td>
          <td>${u.rol || ""}</td>
          <td>${perfilNombre}</td>
          <td>${inst?.nombre || u.tenantId || ""}</td>
          <td>${estado}</td>
          <td>${fechaUser}</td>
          <td class="actions-col">
            <div class="table-actions luiz-actions">
              ${protegido
                    ? `<span class="hint">Protegido</span>`
                    : `
                  <button onclick="editarUsuarioAdminLuiz(${idx})">Editar</button>
                  <button class="secondary" onclick="regenerarClaveUsuarioAdminLuiz(${idx})" title="Regenerar clave temporal">Reset</button>
                  <button
                    class="state-toggle ${estadoUser ? "active" : ""}"
                    onclick="toggleEstadoUsuarioAdminLuiz(${idx})"
                    title="${estadoUser ? "Desactivar usuario" : "Activar usuario"}"
                    aria-label="${estadoUser ? "Desactivar usuario" : "Activar usuario"}">
                    <span class="dot"></span>
                  </button>
                  <button class="secondary" onclick="eliminarUsuarioAdminLuiz(${idx})">Eliminar</button>
                `
                }
            </div>
          </td>
        </tr>
      `
        })
        tablaUsers.innerHTML = usersHtml
    }

    if (tablaPerfiles) {
        const perfilesOrdenados = (perfilesLuiz || [])
            .map((perfil, idx) => ({ perfil, idx }))
            .sort((a, b) => String(a.perfil.nombre || "").localeCompare(String(b.perfil.nombre || "")))
        if (!perfilesOrdenados.length) {
            tablaPerfiles.innerHTML = `<tr><td colspan="5">Sin perfiles.</td></tr>`
        } else {
            let perfilesHtml = ""
            perfilesOrdenados.forEach(({ perfil: p, idx }) => {
                const permisosTxt = PROFILE_MODULES.filter(m => p.permisos?.[m.id]).map(m => m.label).join(", ") || "Sin permisos"
                const estado = p.estado === "activo" ? "Activo" : "Inactivo"
                const fecha = String(p.fecha_creacion || "").slice(0, 10)
                perfilesHtml += `
          <tr>
            <td>${p.nombre}${p.system ? ` <span class="tag-system">BASE</span>` : ""}</td>
            <td>${estado}</td>
            <td>${permisosTxt}</td>
            <td>${fecha}</td>
            <td class="actions-col">
              <div class="table-actions luiz-actions">
                <button onclick="editarPerfilLuiz(${idx})">Editar</button>
                <button
                  class="state-toggle ${p.estado === "activo" ? "active" : ""}"
                  onclick="toggleEstadoPerfilLuiz(${idx})"
                  title="${p.estado === "activo" ? "Desactivar perfil" : "Activar perfil"}"
                  aria-label="${p.estado === "activo" ? "Desactivar perfil" : "Activar perfil"}">
                  <span class="dot"></span>
                </button>
                ${p.system
                        ? `<span class="hint">Protegido</span>`
                        : `<button class="secondary" onclick="eliminarPerfilLuiz(${idx})">Eliminar</button>`
                    }
              </div>
            </td>
          </tr>
        `
            })
            tablaPerfiles.innerHTML = perfilesHtml
        }
    }
}

function esRutaInstitucionalValidaActiva() {
    if (esModoStaff) return false
    const tenant = obtenerTenantActivo()
    return !!tenant && !!tenant.habilitado
}

function puedeMostrarAccesoAdminInstitucional() {
    const formularioVisible = document.getElementById("formulario")?.style?.display === "block"
    return esRutaInstitucionalValidaActiva() &&
        !haySesionAdminActiva() &&
        !formularioVisible &&
        getVistaActiva() === "mobile"
}

function setMensajeAccesoAdminInstitucional(msg = "") {
    const el = document.getElementById("tenantAdminMsg")
    if (!el) return
    if (msg) {
        el.innerText = msg
        el.style.display = "block"
    } else {
        el.innerText = ""
        el.style.display = "none"
    }
}

function abrirAccesoAdminInstitucional() {
    if (!puedeMostrarAccesoAdminInstitucional()) return
    const modal = document.getElementById("tenantAdminAccessModal")
    if (!modal) return
    setMensajeAccesoAdminInstitucional("")
    if (tenantAdminUser) tenantAdminUser.value = ""
    if (tenantAdminPass) tenantAdminPass.value = ""
    modal.style.display = "flex"
    modal.setAttribute("aria-hidden", "false")
    tenantAdminUser?.focus()
}

function cerrarAccesoAdminInstitucional() {
    const modal = document.getElementById("tenantAdminAccessModal")
    if (!modal) return
    modal.style.display = "none"
    modal.setAttribute("aria-hidden", "true")
    setMensajeAccesoAdminInstitucional("")
}

function aplicarVisibilidadAccesoAdminInstitucional() {
    const btn = document.getElementById("btnAccesoAdminInstitucional")
    if (!btn) return
    btn.style.display = puedeMostrarAccesoAdminInstitucional() ? "inline-flex" : "none"
    if (btn.style.display === "none") {
        cerrarAccesoAdminInstitucional()
    }
}

async function crearInstitucionLuizLabs() {
    if (!puedeEntrarPanelLuizLabs()) return
    const input = document.getElementById("luizInstNombre")
    const inputLogo = document.getElementById("luizInstLogoFile")
    const nombre = String(input?.value || "").trim()
    if (!nombre) {
        alert("Ingresa el nombre de la institución.")
        return
    }

    const slug = generarSlugInstitucionUnico(nombre)
    let logoCargado = ""
    try {
        logoCargado = await leerLogoInstitucionalArchivo(inputLogo?.files?.[0] || null)
    } catch (e) {
        alert(e.message || "No se pudo procesar el logo institucional.")
        return
    }
    const inst = {
        id: generarIdInstitucion(),
        nombre,
        slug,
        logo: normalizarLogoInstitucion(logoCargado),
        estado: "activo",
        fecha_creacion: new Date().toISOString()
    }
    institucionesLuiz.push(inst)

    const usuario = `admin@${slug}`
    const password = generarClaveTemporal(8)
    const nuevoAdmin = {
        usuario,
        password,
        rol: ROLES_ADMIN.ADMINISTRADOR,
        tenantId: slug,
        perfilId: "administrador",
        estado: "activo",
        fecha_creacion: new Date().toISOString()
    }
    usuariosAdminLuiz.push(nuevoAdmin)
    await guardarUsuarioLuizEnSupabase(nuevoAdmin)

    sincronizarTenantsDesdeInstituciones()
    guardarLuizLabsEnStorage()
    renderTenantSelector()
    renderPanelLuizLabs()
    if (input) input.value = ""
    if (inputLogo) inputLogo.value = ""
    limpiarUsuarioAdminLuizForm()

    alert(
        `Institución creada correctamente.\n\n` +
        `Usuario admin: ${usuario}\n` +
        `Contraseña temporal: ${password}`
    )
    registrarActividad("institucion_creada", {
        institucion: nombre,
        slug,
        adminGenerado: usuario
    }, { tenantId: slug })
}

function editarInstitucionLuizLabs(id) {
    if (!puedeEntrarPanelLuizLabs()) return
    const inst = institucionesLuiz.find(x => x.id === id)
    if (!inst) return
    const nombreAnterior = inst.nombre || ""
    const nuevoNombre = prompt("Nuevo nombre de institución:", inst.nombre || "")
    if (nuevoNombre == null) return
    const limpio = String(nuevoNombre).trim()
    if (!limpio) {
        alert("Nombre no válido.")
        return
    }
    inst.nombre = limpio
    sincronizarTenantsDesdeInstituciones()
    guardarLuizLabsEnStorage()
    renderTenantSelector()
    aplicarTenantEnUI()
    renderPanelLuizLabs()
    registrarActividad("institucion_editada", {
        slug: inst.slug,
        nombreAnterior,
        nombreNuevo: limpio
    }, { tenantId: inst.slug })
}

function toggleEstadoInstitucionLuizLabs(id) {
    if (!puedeEntrarPanelLuizLabs()) return
    const inst = institucionesLuiz.find(x => x.id === id)
    if (!inst) return
    inst.estado = inst.estado === "activo" ? "inactivo" : "activo"
    sincronizarTenantsDesdeInstituciones()
    guardarLuizLabsEnStorage()
    renderTenantSelector()
    renderPanelLuizLabs()
    registrarActividad("institucion_estado_actualizado", {
        slug: inst.slug,
        estado: inst.estado
    }, { tenantId: inst.slug })
}

function ingresarInstitucionLuizLabs(slug) {
    if (!puedeEntrarPanelLuizLabs()) return
    const inst = institucionesLuiz.find(x => x.slug === slug)
    if (!inst) {
        alert("Institución no encontrada.")
        return
    }
    if (inst.estado !== "activo") {
        alert("La institución está inactiva. Actívala antes de ingresar.")
        return
    }
    registrarActividad("institucion_ingresar_desde_luizlabs", {
        slug,
        nombre: inst.nombre
    }, { tenantId: slug })
    window.location.href = obtenerRutaTenant(slug)
}

async function copiarEnlaceInstitucionLuizLabs(slug) {
    if (!puedeEntrarPanelLuizLabs()) return
    const ruta = obtenerRutaTenant(slug)
    const url = `${window.location.origin}${ruta}`

    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(url)
            alert(`Enlace copiado:\n${url}`)
            registrarActividad("institucion_enlace_copiado", { slug, url }, { tenantId: slug })
            return
        }
    } catch (e) {
        console.warn("No se pudo copiar usando clipboard API:", e)
    }

    const soporte = window.prompt("Copia este enlace:", url)
    if (soporte !== null) {
        alert("Enlace listo para copiar.")
        registrarActividad("institucion_enlace_copiado", { slug, url }, { tenantId: slug })
    }
}

async function eliminarInstitucionLuizLabs(id) {
    if (!puedeEntrarPanelLuizLabs()) return
    const idx = institucionesLuiz.findIndex(x => x.id === id)
    if (idx < 0) return
    const inst = institucionesLuiz[idx]

    if (esTenantProtegido(inst.slug)) {
        alert("Esta institución está protegida y no puede eliminarse.")
        return
    }

    if (inst.estado !== "inactivo") {
        alert("Primero desactiva la institución para poder eliminarla.")
        return
    }

    const ok = confirm(
        `¿Eliminar definitivamente la institución "${inst.nombre}"?\n` +
        `Esta acción también eliminará su usuario admin asociado.`
    )
    if (!ok) return

    if (haySupabase()) {
        const { error } = await supabaseClient
            .from('instituciones_luiz')
            .delete()
            .eq('id', id);

        if (error) {
            console.error("Error al eliminar institución:", error);
            alert("No se pudo eliminar la institución de la base de datos.");
            return;
        }
    }

    const slugEliminado = inst.slug
    const nombreEliminado = inst.nombre

    institucionesLuiz.splice(idx, 1)
    const usuariosEliminar = usuariosAdminLuiz.filter(u => u.tenantId === inst.slug)
    for (const u of usuariosEliminar) {
        await eliminarUsuarioLuizEnSupabase(u.usuario)
    }
    usuariosAdminLuiz = usuariosAdminLuiz.filter(u => u.tenantId !== inst.slug)

    if (TENANTS[inst.slug]) {
        delete TENANTS[inst.slug]
    }

    guardarLuizLabsEnStorage()
    renderTenantSelector()
    renderPanelLuizLabs()
    registrarActividad("institucion_eliminada", {
        slug: slugEliminado,
        nombre: nombreEliminado
    }, { tenantId: slugEliminado })
}

async function regenerarClaveUsuarioAdminLuiz(idx) {
    if (!puedeEntrarPanelLuizLabs()) return
    const user = usuariosAdminLuiz[idx]
    if (!user) return
    if (!esUsuarioInstitucionalLuiz(user) && !esUsuarioGlobalAsistIA(user)) return
    if (esUsuarioProtegidoLuiz(user.usuario)) {
        alert("El usuario legacy está protegido y no se puede modificar aquí.")
        return
    }
    const nuevaClave = generarClaveTemporal(8)
    user.password = nuevaClave
    await guardarUsuarioLuizEnSupabase(user)
    guardarLuizLabsEnStorage()
    renderPanelLuizLabs()
    registrarActividad("usuario_clave_regenerada", {
        usuario: user.usuario,
        tipo: esUsuarioGlobalAsistIA(user) ? "global" : "institucional"
    }, { tenantId: user.tenantId || "" })
    alert(
        `Credencial actualizada.\n\n` +
        `Usuario: ${user.usuario}\n` +
        `Nueva clave temporal: ${nuevaClave}`
    )
}

async function toggleEstadoUsuarioAdminLuiz(idx) {
    if (!puedeEntrarPanelLuizLabs()) return
    const user = usuariosAdminLuiz[idx]
    if (!user) return
    if (!esUsuarioInstitucionalLuiz(user)) return
    if (esUsuarioProtegidoLuiz(user.usuario)) {
        alert("El usuario legacy está protegido y no se puede modificar aquí.")
        return
    }
    user.estado = user.estado === "activo" ? "inactivo" : "activo"
    await guardarUsuarioLuizEnSupabase(user)
    guardarLuizLabsEnStorage()
    renderPanelLuizLabs()
    registrarActividad("usuario_estado_actualizado", {
        usuario: user.usuario,
        estado: user.estado,
        tipo: "institucional"
    }, { tenantId: user.tenantId || "" })
}

async function eliminarUsuarioAdminLuiz(idx) {
    if (!puedeEntrarPanelLuizLabs()) return
    const user = usuariosAdminLuiz[idx]
    if (!user) return
    if (!esUsuarioInstitucionalLuiz(user)) return
    if (esUsuarioProtegidoLuiz(user.usuario)) {
        alert("El usuario legacy está protegido y no se puede eliminar.")
        return
    }
    const ok = confirm(`¿Eliminar usuario admin "${user.usuario}"?`)
    if (!ok) return
    const userEliminado = user.usuario
    const tenantUser = user.tenantId || ""
    await eliminarUsuarioLuizEnSupabase(userEliminado)
    usuariosAdminLuiz.splice(idx, 1)
    guardarLuizLabsEnStorage()
    renderPanelLuizLabs()
    registrarActividad("usuario_eliminado", {
        usuario: userEliminado,
        tipo: "institucional"
    }, { tenantId: tenantUser })
}

function limpiarUsuarioGlobalLuizForm() {
    editUsuarioGlobalLuizIndex = -1
    if (luizGlobalNombres) luizGlobalNombres.value = ""
    if (luizGlobalApellidos) luizGlobalApellidos.value = ""
    if (luizGlobalDni) luizGlobalDni.value = ""
    if (luizGlobalCorreo) luizGlobalCorreo.value = ""
    if (luizGlobalCelular) luizGlobalCelular.value = ""
    if (luizGlobalUserNombre) luizGlobalUserNombre.value = ""
    if (luizGlobalUserRol) luizGlobalUserRol.value = ROLES_ADMIN.SUPERUSUARIO
    if (luizGlobalUserPass) luizGlobalUserPass.value = ""
}

function cancelarEdicionUsuarioGlobalLuiz() {
    limpiarUsuarioGlobalLuizForm()
}

function generarClaveUsuarioGlobalLuiz() {
    if (!luizGlobalUserPass) return
    luizGlobalUserPass.value = generarClaveTemporal(8)
}

async function copiarClaveUsuarioGlobalLuiz() {
    const clave = String(luizGlobalUserPass?.value || "").trim()
    if (!clave) {
        alert("No hay clave global para copiar.")
        return
    }
    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(clave)
            alert("Clave global copiada.")
            return
        }
    } catch (e) {
        console.warn("No se pudo copiar clave global:", e)
    }
    const soporte = window.prompt("Copia esta clave:", clave)
    if (soporte !== null) {
        alert("Clave lista para copiar.")
    }
}

function editarUsuarioGlobalLuiz(idx) {
    if (!puedeEntrarPanelLuizLabs()) return
    const user = usuariosAdminLuiz[idx]
    if (!user || !esUsuarioGlobalAsistIA(user)) return
    const protegidoEditable = esUsuarioProtegidoLuiz(user.usuario) && puedeEditarDatosUsuarioProtegido(user)
    if (esUsuarioProtegidoLuiz(user.usuario) && !protegidoEditable) {
        alert("Usuario protegido.")
        return
    }

    editUsuarioGlobalLuizIndex = idx
    if (luizGlobalNombres) luizGlobalNombres.value = user.nombres || ""
    if (luizGlobalApellidos) luizGlobalApellidos.value = user.apellidos || ""
    if (luizGlobalDni) luizGlobalDni.value = user.dni || ""
    if (luizGlobalCorreo) luizGlobalCorreo.value = user.correo || ""
    if (luizGlobalCelular) luizGlobalCelular.value = user.celular || ""
    if (luizGlobalUserNombre) luizGlobalUserNombre.value = user.usuario || ""
    if (luizGlobalUserRol) luizGlobalUserRol.value = ROLES_ADMIN.SUPERUSUARIO
    if (luizGlobalUserPass) luizGlobalUserPass.value = user.password || ""
}

async function toggleEstadoUsuarioGlobalLuiz(idx) {
    if (!puedeEntrarPanelLuizLabs()) return
    const user = usuariosAdminLuiz[idx]
    if (!user || !esUsuarioGlobalAsistIA(user)) return
    if (esUsuarioProtegidoLuiz(user.usuario)) {
        alert("El usuario legacy está protegido y no se puede modificar aquí.")
        return
    }
    user.estado = user.estado === "activo" ? "inactivo" : "activo"
    await guardarUsuarioLuizEnSupabase(user)
    guardarLuizLabsEnStorage()
    renderPanelLuizLabs()
    registrarActividad("usuario_global_estado_actualizado", {
        usuario: user.usuario,
        estado: user.estado
    })
}

async function eliminarUsuarioGlobalLuiz(idx) {
    if (!puedeEntrarPanelLuizLabs()) return
    const user = usuariosAdminLuiz[idx]
    if (!user || !esUsuarioGlobalAsistIA(user)) return
    if (esUsuarioProtegidoLuiz(user.usuario)) {
        alert("El usuario legacy está protegido y no se puede eliminar.")
        return
    }
    const ok = confirm(`¿Eliminar usuario global "${user.usuario}"?`)
    if (!ok) return
    const usuarioEliminado = user.usuario
    await eliminarUsuarioLuizEnSupabase(usuarioEliminado)
    usuariosAdminLuiz.splice(idx, 1)
    guardarLuizLabsEnStorage()
    renderPanelLuizLabs()
    registrarActividad("usuario_global_eliminado", { usuario: usuarioEliminado })
}

async function guardarUsuarioGlobalLuiz() {
    if (!puedeEntrarPanelLuizLabs()) return
    const nombres = String(luizGlobalNombres?.value || "").trim()
    const apellidos = String(luizGlobalApellidos?.value || "").trim()
    const dni = String(luizGlobalDni?.value || "").replace(/\D/g, "")
    const correo = String(luizGlobalCorreo?.value || "").trim().toLowerCase()
    const celular = String(luizGlobalCelular?.value || "").replace(/\D/g, "")
    const usuario = String(luizGlobalUserNombre?.value || "").trim().toLowerCase()
    const rol = normalizarRolUsuario(luizGlobalUserRol?.value || ROLES_ADMIN.SUPERUSUARIO)
    const password = String(luizGlobalUserPass?.value || "").trim()

    if (!nombres || !apellidos || !dni || !usuario || !password) {
        alert("Completa nombres, apellidos, DNI, usuario y clave global.")
        return
    }
    if (dni.length !== 8) {
        alert("El DNI debe tener 8 dígitos.")
        return
    }
    if (correo && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo)) {
        alert("Correo no válido.")
        return
    }
    if (celular && celular.length < 9) {
        alert("Celular no válido.")
        return
    }
    if (rol !== ROLES_ADMIN.SUPERUSUARIO) {
        alert("En esta sección solo se gestionan superusuarios globales.")
        return
    }
    const usuarioActualEdicion = editUsuarioGlobalLuizIndex >= 0
        ? String(usuariosAdminLuiz?.[editUsuarioGlobalLuizIndex]?.usuario || "").toLowerCase()
        : ""
    const usuarioSupabase = (usuariosAdmin || []).some(u => {
        const userDb = String(u.usuario || "").toLowerCase()
        if (editUsuarioGlobalLuizIndex >= 0 && userDb === usuarioActualEdicion) {
            return false
        }
        return userDb === usuario
    })
    if (usuarioSupabase) {
        alert("Ese usuario ya existe en el panel de usuarios.")
        return
    }

    let accion = "usuario_global_creado"
    if (editUsuarioGlobalLuizIndex >= 0) {
        const actual = usuariosAdminLuiz[editUsuarioGlobalLuizIndex]
        if (!actual || !esUsuarioGlobalAsistIA(actual)) {
            limpiarUsuarioGlobalLuizForm()
            return
        }
        if (esUsuarioProtegidoLuiz(actual.usuario) && !puedeEditarDatosUsuarioProtegido(actual)) {
            alert("Usuario protegido.")
            return
        }
        if (esUsuarioProtegidoLuiz(actual.usuario) && String(usuario || "").toLowerCase() !== String(actual.usuario || "").toLowerCase()) {
            alert("No puedes cambiar el usuario de esta cuenta protegida.")
            return
        }
        const duplicado = usuariosAdminLuiz.some((u, i) => i !== editUsuarioGlobalLuizIndex && String(u.usuario || "").toLowerCase() === usuario)
        if (duplicado) {
            alert("Ya existe un usuario con ese nombre.")
            return
        }
        actual.usuario = usuario
        actual.nombres = nombres
        actual.apellidos = apellidos
        actual.dni = dni
        actual.correo = correo
        actual.celular = celular
        actual.password = password
        actual.rol = ROLES_ADMIN.SUPERUSUARIO
        actual.tenantId = ""
        actual.perfilId = ""
        if (!actual.fecha_creacion) actual.fecha_creacion = new Date().toISOString()
        if (!actual.estado) actual.estado = "activo"
        accion = "usuario_global_editado"
    } else {
        if (esUsuarioProtegidoLuiz(usuario)) {
            alert("Ese usuario está reservado por el sistema.")
            return
        }
        const existe = usuariosAdminLuiz.some(u => String(u.usuario || "").toLowerCase() === usuario)
        if (existe) {
            alert("Ese usuario ya existe.")
            return
        }
        usuariosAdminLuiz.push({
            nombres,
            apellidos,
            dni,
            correo,
            celular,
            usuario,
            password,
            rol: ROLES_ADMIN.SUPERUSUARIO,
            tenantId: "",
            perfilId: "",
            estado: "activo",
            fecha_creacion: new Date().toISOString()
        })
    }

    guardarLuizLabsEnStorage()
    const userGuardado = usuariosAdminLuiz.find(u => String(u.usuario || "").toLowerCase() === usuario)
    if (userGuardado) await guardarUsuarioLuizEnSupabase(userGuardado)
    renderPanelLuizLabs()
    limpiarUsuarioGlobalLuizForm()
    registrarActividad(accion, { usuario, rol, dni })
}

function limpiarUsuarioAdminLuizForm() {
    editUsuarioLuizIndex = -1
    if (luizUserNombres) luizUserNombres.value = ""
    if (luizUserApellidos) luizUserApellidos.value = ""
    if (luizUserDni) luizUserDni.value = ""
    if (luizUserCorreo) luizUserCorreo.value = ""
    if (luizUserCelular) luizUserCelular.value = ""
    if (luizUserNombre) luizUserNombre.value = ""
    if (luizUserRol) luizUserRol.value = ROLES_ADMIN.ADMINISTRADOR
    if (luizUserTenant) luizUserTenant.value = ""
    if (luizUserPass) luizUserPass.value = ""
    if (luizUserPerfil) luizUserPerfil.value = "administrador"
}

function cancelarEdicionUsuarioAdminLuiz() {
    limpiarUsuarioAdminLuizForm()
}

function generarClaveUsuarioLuiz() {
    if (!luizUserPass) return
    luizUserPass.value = generarClaveTemporal(8)
}

async function copiarClaveUsuarioLuiz() {
    const clave = String(luizUserPass?.value || "").trim()
    if (!clave) {
        alert("No hay clave para copiar. Genera o ingresa una primero.")
        return
    }
    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(clave)
            alert("Clave copiada.")
            return
        }
    } catch (e) {
        console.warn("No se pudo copiar clave:", e)
    }
    const soporte = window.prompt("Copia esta clave:", clave)
    if (soporte !== null) {
        alert("Clave lista para copiar.")
    }
}

function editarUsuarioAdminLuiz(idx) {
    if (!puedeEntrarPanelLuizLabs()) return
    const user = usuariosAdminLuiz[idx]
    if (!user) return
    if (!esUsuarioInstitucionalLuiz(user)) return
    if (esUsuarioProtegidoLuiz(user.usuario)) {
        alert("El usuario legacy está protegido y no se edita desde este módulo.")
        return
    }

    editUsuarioLuizIndex = idx
    if (luizUserNombres) luizUserNombres.value = user.nombres || ""
    if (luizUserApellidos) luizUserApellidos.value = user.apellidos || ""
    if (luizUserDni) luizUserDni.value = user.dni || ""
    if (luizUserCorreo) luizUserCorreo.value = user.correo || ""
    if (luizUserCelular) luizUserCelular.value = user.celular || ""
    if (luizUserNombre) luizUserNombre.value = user.usuario || ""
    if (luizUserRol) luizUserRol.value = normalizarRolUsuario(user.rol)
    if (luizUserTenant) luizUserTenant.value = user.tenantId || ""
    if (luizUserPass) luizUserPass.value = user.password || ""
    if (luizUserPerfil) luizUserPerfil.value = user.perfilId || "administrador"
}

async function guardarUsuarioAdminLuiz() {
    if (!puedeEntrarPanelLuizLabs()) return
    const nombres = String(luizUserNombres?.value || "").trim()
    const apellidos = String(luizUserApellidos?.value || "").trim()
    const dni = String(luizUserDni?.value || "").replace(/\D/g, "")
    const correo = String(luizUserCorreo?.value || "").trim().toLowerCase()
    const celular = String(luizUserCelular?.value || "").replace(/\D/g, "")
    const usuario = String(luizUserNombre?.value || "").trim().toLowerCase()
    const rol = normalizarRolUsuario(luizUserRol?.value || ROLES_ADMIN.ADMINISTRADOR)
    const tenantId = String(luizUserTenant?.value || "").trim()
    const password = String(luizUserPass?.value || "").trim()
    const perfilId = normalizarPerfilId(luizUserPerfil?.value || "administrador") || "administrador"

    if (!nombres || !apellidos || !dni || !usuario || !tenantId || !password) {
        alert("Completa nombres, apellidos, DNI, usuario, institución y clave.")
        return
    }
    if (dni.length !== 8) {
        alert("El DNI debe tener 8 dígitos.")
        return
    }
    if (correo && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo)) {
        alert("Correo no válido.")
        return
    }
    if (celular && celular.length < 9) {
        alert("Celular no válido.")
        return
    }
    if (rol === ROLES_ADMIN.SUPERUSUARIO) {
        alert("El rol superusuario es global y no se gestiona como usuario institucional.")
        return
    }
    if (esUsuarioProtegidoLuiz(usuario)) {
        alert("El usuario legacy está protegido y no se gestiona desde aquí.")
        return
    }
    const usuarioReservadoSistema = SYSTEM_USERS.some(u => String(u.usuario || "").toLowerCase() === usuario)
    if (usuarioReservadoSistema) {
        alert("Ese usuario ya existe como usuario del sistema.")
        return
    }
    const usuarioSupabase = (usuariosAdmin || []).some(u => String(u.usuario || "").toLowerCase() === usuario)
    if (usuarioSupabase) {
        alert("Ese usuario ya existe en el panel de usuarios.")
        return
    }
    const inst = obtenerInstitucionLuiz(tenantId)
    if (!inst || inst.estado !== "activo") {
        alert("Selecciona una institución activa.")
        return
    }
    const perfil = obtenerPerfilPorId(perfilId)
    if (!perfil || perfil.estado !== "activo") {
        alert("Selecciona un perfil activo.")
        return
    }

    let accion = "usuario_admin_luiz_creado"
    if (editUsuarioLuizIndex >= 0) {
        const actual = usuariosAdminLuiz[editUsuarioLuizIndex]
        if (!actual) {
            limpiarUsuarioAdminLuizForm()
            return
        }
        if (esUsuarioProtegidoLuiz(actual.usuario)) {
            alert("El usuario legacy está protegido.")
            limpiarUsuarioAdminLuizForm()
            return
        }

        const duplicado = usuariosAdminLuiz.some((u, i) => i !== editUsuarioLuizIndex && u.usuario === usuario)
        if (duplicado) {
            alert("Ya existe un usuario con ese nombre.")
            return
        }

        actual.usuario = usuario
        actual.nombres = nombres
        actual.apellidos = apellidos
        actual.dni = dni
        actual.correo = correo
        actual.celular = celular
        actual.rol = rol
        actual.tenantId = tenantId
        actual.password = password
        actual.perfilId = perfilId
        if (!actual.fecha_creacion) actual.fecha_creacion = new Date().toISOString()
        if (!actual.estado) actual.estado = "activo"
        accion = "usuario_admin_luiz_editado"
    } else {
        const existe = usuariosAdminLuiz.some(u => u.usuario === usuario)
        if (existe) {
            alert("Ese usuario ya existe.")
            return
        }
        usuariosAdminLuiz.push({
            nombres,
            apellidos,
            dni,
            correo,
            celular,
            usuario,
            password,
            rol,
            tenantId,
            perfilId,
            estado: "activo",
            fecha_creacion: new Date().toISOString()
        })
    }

    guardarLuizLabsEnStorage()
    const userGuardado = usuariosAdminLuiz.find(u => String(u.usuario || "").toLowerCase() === usuario)
    if (userGuardado) await guardarUsuarioLuizEnSupabase(userGuardado)
    renderPanelLuizLabs()
    limpiarUsuarioAdminLuizForm()
    registrarActividad(accion, {
        usuario,
        dni,
        rol,
        tenantId,
        perfilId
    }, { tenantId })
}

function esModoAdminMovilLimitado() {
    if (!haySesionAdminActiva()) return false
    if (!puedeEntrarPanelAdmin()) return false
    return getVistaActiva() === "mobile"
}

function esVistaPermitidaEnAdminMovil(vista) {
    return vista === "dashboard" || vista === "reportes"
}

function marcarNavActiva(vista) {
    document.querySelectorAll(".nav-item[data-view]").forEach(el => {
        el.classList.toggle("active", el.dataset.view === vista)
    })
}

function aplicarRestriccionesPanelPorContexto() {
    const limitado = esModoAdminMovilLimitado()
    const puedeReportes = usuarioPuedeVerVista("reportes")
    const puedeDashboard = usuarioPuedeVerVista("dashboard")
    const puedeConfig = usuarioPuedeVerVista("config")
    const puedeUsuarios = usuarioPuedeVerVista("usuarios")
    const puedeActividad = usuarioPuedeVerVista("actividad")
    const navReportes = document.getElementById("navReportes")
    const navDashboard = document.getElementById("navDashboard")
    const navConfig = document.getElementById("navConfig")
    const navUsuarios = document.getElementById("navUsuarios")
    const navActividad = document.getElementById("navActividad")
    const adminMobileNotice = document.getElementById("adminMobileNotice")
    const btnInstitucion = document.getElementById("btnInstitucion")
    const btnVolverLuizLabs = document.getElementById("btnVolverLuizLabs")

    if (navReportes) navReportes.style.display = puedeReportes ? "" : "none"
    if (navDashboard) navDashboard.style.display = puedeDashboard ? "" : "none"
    if (navConfig) navConfig.style.display = (!limitado && puedeConfig) ? "" : "none"
    if (navUsuarios) navUsuarios.style.display = (!limitado && puedeUsuarios) ? "" : "none"
    if (navActividad) navActividad.style.display = (!limitado && puedeActividad) ? "" : "none"
    if (adminMobileNotice) adminMobileNotice.style.display = limitado ? "block" : "none"

    if (btnInstitucion) {
        if (limitado) {
            btnInstitucion.style.display = "none"
        } else {
            btnInstitucion.style.display = accesoDirectoInstitucion ? "none" : "inline-flex"
        }
    }

    if (btnVolverLuizLabs) {
        const mostrar = !esModoStaff && haySesionAdminActiva() && esSuperusuarioActivo()
        btnVolverLuizLabs.style.display = mostrar ? "inline-flex" : "none"
    }

    const vistaPermitidaPorPerfil = usuarioPuedeVerVista(vistaAdminActual)
    if ((limitado && !esVistaPermitidaEnAdminMovil(vistaAdminActual)) || !vistaPermitidaPorPerfil) {
        mostrarVista("dashboard")
    }
}

function irPanelPrincipalLuizLabs() {
    if (!haySesionAdminActiva() || !esSuperusuarioActivo()) return
    window.location.href = "/"
}

enlazarIdsGlobales()

function normalizarPathname(pathname) {
    let path = String(pathname || "/").trim()
    if (!path.startsWith("/")) {
        path = "/" + path
    }
    path = path.replace(/\/{2,}/g, "/")
    // /esbas-24/index.html → /esbas-24/ (mismo documento SPA)
    path = path.replace(/\/index\.html$/i, "/")
    if (path === "/") {
        return "/"
    }
    if (path !== "/" && !path.endsWith("/")) {
        path += "/"
    }
    return path
}

function obtenerRutaTenant(id) {
    const clean = String(id || "").trim().replace(/^\/+|\/+$/g, "")
    return clean ? `/${clean}/` : "/"
}

function resolverAccesoDesdeRuta() {
    const path = normalizarPathname(window.location.pathname)
    if (path !== "/") {
        const slug = path.replace(/^\/|\/$/g, "")
        const tenant = TENANTS[slug]
        if (tenant) {
            return { staff: false, tenantId: tenant.id }
        }
    }
    return { staff: true, tenantId: "" }
}

function aplicarAccesoDesdeRuta() {
    const acceso = resolverAccesoDesdeRuta()
    esModoStaff = acceso.staff
    accesoDirectoInstitucion = !acceso.staff
    asignarTenantActivo(acceso.tenantId)

    if (!acceso.staff) {
        const tenant = obtenerTenantActivo()
        if (tenant && !tenant.habilitado) {
            limpiarSesionAdminActiva()
            alert("Esta institución está inactiva. Contacta a Luiz Labs.")
            window.location.href = "/"
            return
        }
    }

    if (esModoStaff) {
        if (haySesionAdminActiva()) {
            actualizarSesionAdmin({ tenantId: "" })
            mostrarSelectorStaff = !esSuperusuarioActivo()
        } else {
            mostrarSelectorStaff = false
        }
        sincronizarEstadoLegacyAdmin()
        return
    }

    mostrarSelectorStaff = false

    if (!haySesionAdminActiva()) {
        sincronizarEstadoLegacyAdmin()
        return
    }

    if (esSuperusuarioActivo()) {
        if (acceso.tenantId) {
            actualizarSesionAdmin({ tenantId: acceso.tenantId })
        }
        sincronizarEstadoLegacyAdmin()
        return
    }

    if (tenantSesionActiva() !== acceso.tenantId) {
        limpiarSesionAdminActiva()
        return
    }

    sincronizarEstadoLegacyAdmin()
}

function obtenerTenantActivo() {
    const id = String(tenantActivoId || "").trim()
    return id ? (TENANTS[id] || null) : null
}

function asignarTenantActivo(id) {
    tenantActivoId = String(id || "")
    aplicarTenantEnUI()
    actualizarInfoSesionHeader()
}

function aplicarTenantEnUI() {
    const tenant = obtenerTenantActivo() || primerTenantFallback()
    const titulo = esModoStaff ? "asistIA" : (tenant?.nombre || "Panel ESBAS")
    const linea = esModoStaff ? "Control Inteligente de Asistencia" : (tenant?.linea || "Incorporación y ESBAS")
    const curso = esModoStaff ? "Plataforma asistIA" : (tenant?.curso || "Instrucción ESBAS")
    const tituloCard = esModoStaff
        ? linea
        : (String(curso || "").replace(/^Instrucci[oó]n\s+/i, "").trim() || "ESBAS 2026")
    const logoRuta = esModoStaff ? DEFAULT_INSTITUTION_LOGO : obtenerLogoInstitucion(tenant)

    if (tenantTituloLogin) {
        tenantTituloLogin.innerText = titulo
        tenantTituloLogin.classList.toggle("login-project-title", esModoStaff)
        tenantTituloLogin.classList.toggle("login-project-title-xl", esModoStaff)
    }
    if (tenantSubtituloLogin) {
        tenantSubtituloLogin.innerText = linea
        tenantSubtituloLogin.style.display = esModoStaff ? "none" : "block"
    }
    if (tenantCursoLogin) {
        tenantCursoLogin.innerText = curso
        tenantCursoLogin.style.display = "none"
    }
    if (tenantCardTituloLogin) tenantCardTituloLogin.innerText = tituloCard

    if (tenantTituloMovil) tenantTituloMovil.innerText = titulo
    if (tenantSubtituloMovil) tenantSubtituloMovil.innerText = linea
    if (tenantCursoMovil) tenantCursoMovil.innerText = curso

    if (tenantPanelTitulo) tenantPanelTitulo.innerText = `asistIA Panel Administrativo - ${titulo}`
    if (tenantLogoLoginCard) tenantLogoLoginCard.src = logoRuta
    if (tenantLogoMovil) tenantLogoMovil.src = logoRuta
    if (tenantLogoMovilInicio) tenantLogoMovilInicio.src = logoRuta
    if (tenantLogoFormulario) tenantLogoFormulario.src = logoRuta
    if (tenantLogoPanel) tenantLogoPanel.src = logoRuta
}

function renderTenantSelector() {
    if (!tenantGrid) return
    let html = ""
    listaTenantsOrdenada().forEach(t => {
        const disabled = !t.habilitado
        const btnClass = disabled ? "secondary" : ""
        const btnText = disabled ? "Próximamente" : "Ingresar"
        const logoHtml = `<img src="${obtenerLogoInstitucion(t)}" alt="${t.nombre}" class="tenant-logo">`

        html += `
      <div class="tenant-card">
        <div class="tenant-brand">
          ${logoHtml}
          <div class="tenant-meta">
            <strong>${t.nombre}</strong>
            <small>${t.linea}</small>
          </div>
        </div>
        <span class="tenant-tag ${disabled ? "disabled" : ""}">
          ${disabled ? "No habilitado" : "Activo"}
        </span>
        <button class="${btnClass}" onclick="seleccionarCliente('${t.id}')">${btnText}</button>
      </div>
    `
    })
    tenantGrid.innerHTML = html
}

function seleccionarCliente(id) {
    const tenant = TENANTS[id]
    if (!tenant) {
        alert("Cliente no válido")
        return
    }
    if (!tenant.habilitado) {
        alert("Esta institución aún no está habilitada para ingreso.")
        return
    }
    if (esModoStaff && haySesionAdminActiva()) {
        actualizarSesionAdmin({ tenantId: tenant.id, origen: "staff_root" })
    }
    window.location.href = obtenerRutaTenant(id)
}

function volverSeleccionCliente() {
    if (accesoDirectoInstitucion) {
        window.location.href = "/"
        return
    }
    if (esModoStaff) {
        actualizarSesionAdmin({ tenantId: "" })
        mostrarSelectorStaff = true
        loginMsg.innerText = ""
        loginUser.value = ""
        loginPass.value = ""
        aplicarLayout()
        renderTenantSelector()
        return
    }

    limpiarSesionAdminActiva()
    asignarTenantActivo("")
    loginMsg.innerText = ""
    loginUser.value = ""
    loginPass.value = ""
    aplicarLayout()
}

function withTenantScope(query) {
    if (!MULTITENANT_MODE || !tenantActivoId || !tenantScopeBackendReady) return query
    const tid = String(tenantActivoId).trim().toLowerCase()
    if (esTenantConDatosLegacy(tid)) {
        return query.or(`tenant_id.eq.${tid},tenant_id.is.null`)
    }
    return query.eq("tenant_id", tid)
}

function withTenantPayload(payload) {
    if (!MULTITENANT_MODE || !tenantActivoId) return payload
    const tid = String(tenantActivoId).trim().toLowerCase()
    return Object.assign({}, payload, { tenant_id: tid })
}

function withTenantPayloadList(items) {
    return (items || []).map(withTenantPayload)
}

function filtrarDataTenantActivo(rows) {
    if (!MULTITENANT_MODE || !tenantActivoId) {
        return Array.isArray(rows) ? rows : []
    }
    const tenant = String(tenantActivoId || "").trim().toLowerCase()
    return (rows || []).filter(r => {
        const tenantFila = String(r?.tenant_id || "").trim().toLowerCase()
        if (tenantFila) {
            return tenantFila === tenant
        }
        return esTenantConDatosLegacy(tenant)
    })
}

function esTablaNoExiste(error) {
    return /does not exist|42P01/i.test(String(error?.message || ""))
}

async function actualizarTenantScopeBackendReady() {
    if (!MULTITENANT_MODE || !haySupabase()) {
        tenantScopeBackendReady = false
        return tenantScopeBackendReady
    }

    const tablasTenant = [
        "asistencias",
        "asistencia_alertas",
        "aspirantes",
        "ubos_sedes",
        "curso_configuracion",
        "curso_secciones",
        "curso_sedes_ubo"
    ]

    const checks = await Promise.all(tablasTenant.map(async (tabla) => {
        const { error } = await supabaseClient
            .from(tabla)
            .select("tenant_id")
            .limit(1)

        if (!error) return true
        const msg = String(error.message || "")
        if (esTablaNoExiste(error) || /tenant_id/i.test(msg)) {
            return false
        }
        console.warn(`No se pudo validar tenant_id en ${tabla}:`, msg)
        return false
    }))

    tenantScopeBackendReady = checks.every(Boolean)
    return tenantScopeBackendReady
}

async function asegurarUsuariosAdminPrevioLogin(usuario) {
    const user = String(usuario || "").trim().toLowerCase()
    const yaCargado = user
        ? (usuariosAdmin || []).some(u => String(u.usuario || "").toLowerCase() === user)
        : (usuariosAdmin || []).length > 0

    if (yaCargado || !haySupabase()) return

    try {
        await cargarUsuariosAdminDesdeSupabase()
    } catch (e) {
        console.warn("No se pudo recargar usuarios admin antes del login:", e?.message || e)
    }
}

function esMovil() {
    const ua = navigator.userAgent || ""
    const touchDevice = "ontouchstart" in window || navigator.maxTouchPoints > 0
    const isPhoneUA = /iPhone|iPod|Android.+Mobile|Windows Phone|IEMobile|BlackBerry|Opera Mini|Mobile/i.test(ua)
    const isTabletUA = /iPad|Tablet|Android(?!.*Mobile)/i.test(ua)
    const width = window.innerWidth || document.documentElement.clientWidth || 1024

    // Tablet y laptop deben verse como escritorio para administrar el panel.
    if (isTabletUA) return false
    if (isPhoneUA) return true

    // Fallback: si no hay UA clara, solo tratamos como móvil pantallas muy pequeñas táctiles.
    return touchDevice && width <= 760
}

function getVistaManual() {
    const modeSesion = sessionStorage.getItem(VISTA_MODO_KEY)
    if (modeSesion === "mobile" || modeSesion === "desktop") {
        // Protección anti-bloqueo: en laptop/tablet no mantener "mobile" manual persistido.
        if (modeSesion === "mobile" && !esMovil()) {
            sessionStorage.removeItem(VISTA_MODO_KEY)
            localStorage.removeItem(VISTA_MODO_KEY)
            return "auto"
        }
        return modeSesion
    }

    // Limpia preferencias heredadas de sesiones antiguas.
    const modeLegacy = localStorage.getItem(VISTA_MODO_KEY)
    if (modeLegacy === "mobile" || modeLegacy === "desktop") {
        if (modeLegacy === "mobile" && !esMovil()) {
            localStorage.removeItem(VISTA_MODO_KEY)
            return "auto"
        }
        sessionStorage.setItem(VISTA_MODO_KEY, modeLegacy)
        localStorage.removeItem(VISTA_MODO_KEY)
        return modeLegacy
    }
    return "auto"
}

function getVistaActiva() {
    const manual = getVistaManual()
    if (manual === "mobile") return esMovil() ? "mobile" : "desktop"
    if (manual === "desktop") return "desktop"
    return esMovil() ? "mobile" : "desktop"
}

function actualizarBotonesVista() {
    const mode = getVistaManual()
    const btnForzarMovil = document.getElementById("btnForzarMovil")
    const btnForzarDesktop = document.getElementById("btnForzarDesktop")
    const btnAutoDesktop = document.getElementById("btnVistaAutoDesktop")
    const btnAutoMovil = document.getElementById("btnVistaAutoMovil")
    const setAutoLabel = (el) => {
        if (!el) return
        el.innerText = mode === "auto" ? "Automático ✓" : "Automático"
    }
    if (btnForzarMovil) {
        btnForzarMovil.innerText = mode === "mobile" ? "Ver móvil ✓" : "Ver móvil"
    }
    if (btnForzarDesktop) {
        btnForzarDesktop.innerText = mode === "desktop" ? "Ver escritorio ✓" : "Ver escritorio"
    }
    setAutoLabel(btnAutoDesktop)
    setAutoLabel(btnAutoMovil)
}

function setVistaManual(mode) {
    if (mode === "mobile" || mode === "desktop") {
        sessionStorage.setItem(VISTA_MODO_KEY, mode)
    } else {
        sessionStorage.removeItem(VISTA_MODO_KEY)
        localStorage.removeItem(VISTA_MODO_KEY)
    }
    aplicarLayout()
}

function irEscritorioAdmin() {
    const elTenant = document.getElementById("tenantScreen")
    const elLogin = document.getElementById("loginScreen")
    const elDesktop = document.getElementById("vistaDesktop")
    const elFormulario = document.getElementById("formulario")
    const elMovilInicio = document.getElementById("vistaMovilInicio")
    const elMovil = document.getElementById("vistaMovil")
    setVistaManual("desktop")
    if (!haySesionAdminActiva()) {
        if (!esModoStaff) {
            aplicarLayout()
            return
        }
        if (elTenant) elTenant.style.display = "none"
        if (elLogin) elLogin.style.display = "flex"
        if (elDesktop) elDesktop.style.display = "none"
        if (elFormulario) elFormulario.style.display = "none"
        if (elMovilInicio) elMovilInicio.style.display = "none"
        if (elMovil) elMovil.style.display = "none"
        mostrarPasoMovil("ingreso")
    }
}

function obtenerRangoMesActual() {
    const now = new Date()
    const year = now.getFullYear()
    const month = now.getMonth()
    const from = new Date(year, month, 1)
    const to = new Date(year, month + 1, 0)
    const iso = (d) => d.toISOString().slice(0, 10)
    return { from: iso(from), to: iso(to) }
}

function aplicarRangoMesActualEnFiltros() {
    const { from, to } = obtenerRangoMesActual()
    const elFechaDesde = document.getElementById("fechaDesde")
    const elFechaHasta = document.getElementById("fechaHasta")
    const elDashDesde = document.getElementById("dashDesde")
    const elDashHasta = document.getElementById("dashHasta")
    if (elFechaDesde) elFechaDesde.value = from
    if (elFechaHasta) elFechaHasta.value = to
    if (elDashDesde) elDashDesde.value = from
    if (elDashHasta) elDashHasta.value = to
}

function mostrarPasoMovil(paso) {
    const elIngreso = document.getElementById("mobileStepIngreso")
    const elScan = document.getElementById("mobileStepScan")
    if (elIngreso) elIngreso.style.display = paso === "ingreso" ? "block" : "none"
    if (elScan) elScan.style.display = paso === "scan" ? "block" : "none"
    aplicarVisibilidadAccesoAdminInstitucional()
}

function seleccionarBotonSeccion(valor) {
    document.querySelectorAll(".mobile-section-btn").forEach(btn => {
        btn.classList.toggle("active", btn.dataset.seccion === valor)
    })
}

function setMensaje(texto, tipo = "") {
    mensaje.className = ""
    mensaje.innerText = texto || ""
    if (!texto) return
    if (tipo) mensaje.classList.add(tipo)
}

function obtenerValoresMultiSelect(selectId) {
    const select = document.getElementById(selectId)
    if (!select) return []
    return Array.from(select.selectedOptions || []).map(opt => opt.value)
}

function marcarValoresMultiSelect(selectId, valores = []) {
    const select = document.getElementById(selectId)
    if (!select) return
    const setVals = new Set((valores || []).map(String))
    Array.from(select.options || []).forEach(opt => {
        opt.selected = setVals.has(opt.value)
    })
}

function actualizarEstadoDiasSede() {
    const elTodos = document.getElementById("uboSecTodosDias")
    const elDias = document.getElementById("uboSecDiasSelect")
    const todos = !!elTodos?.checked
    if (elDias) {
        elDias.disabled = todos
        if (todos) {
            marcarValoresMultiSelect("uboSecDiasSelect", [])
            elDias.size = 1
            elDias.style.height = "42px"
        }
    }
}

function activarSelectDiasCompacto(selectId, expandedSize = 7) {
    const select = document.getElementById(selectId)
    if (!select) return
    if (select.dataset.compactoInit === "1") return
    select.dataset.compactoInit = "1"

    const expandir = () => {
        if (select.disabled) return
        select.size = expandedSize
        select.style.height = "auto"
    }

    const contraer = () => {
        select.size = 1
        select.style.height = "42px"
    }

    contraer()

    select.addEventListener("focus", expandir)
    select.addEventListener("mousedown", () => setTimeout(expandir, 0))
    select.addEventListener("blur", () => setTimeout(contraer, 120))
    select.addEventListener("keydown", (e) => {
        if (e.key === "Escape" || e.key === "Tab") {
            contraer()
        }
    })
}

function diasTexto(dias) {
    const arr = (dias || []).filter(Boolean)
    return arr.length ? arr.join(", ") : "-"
}

function normalizarTextoDia(txt) {
    return String(txt || "")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .trim()
}

function obtenerDiaSemanaEs(fechaISO) {
    if (!fechaISO) return ""
    const d = new Date(`${fechaISO}T00:00:00`)
    if (Number.isNaN(d.getTime())) return ""
    const dias = ["domingo", "lunes", "martes", "miercoles", "jueves", "viernes", "sabado"]
    return dias[d.getDay()] || ""
}

function horaATotalMinutos(hora) {
    const h = String(hora || "").slice(0, 5)
    const [hh, mm] = h.split(":")
    const H = Number(hh)
    const M = Number(mm)
    if (!Number.isFinite(H) || !Number.isFinite(M)) return null
    return H * 60 + M
}

function obtenerReglaSeccion(seccion) {
    const sec = String(seccion || "").trim().toUpperCase()
    if (!sec) return null
    const regla = (cursoSecciones || []).find(x => String(x.seccion || "").trim().toUpperCase() === sec)
    if (!regla) return null
    return {
        seccion: sec,
        horaInicioMin: horaATotalMinutos(regla.hora_inicio),
        horaInicioTexto: String(regla.hora_inicio || "").slice(0, 5),
        dias: (regla.dias || []).map(normalizarTextoDia).filter(Boolean)
    }
}

function describirMotivoSemaforo(motivo) {
    const mapa = {
        sin_registro: "Sin registro",
        sin_seccion: "Sin sección asignada",
        sin_hora_configurada: "Sin hora configurada en sección",
        fuera_de_dia_configurado: "Fuera de día configurado",
        sin_hora_marcada: "Sin hora de marcación",
        hora_invalida_para_seccion: "Hora inválida para la sección",
        a_tiempo: "A tiempo",
        tardanza_moderada: "Tardanza moderada",
        tardanza_alta: "Tardanza alta"
    }
    return mapa[motivo] || String(motivo || "Sin criterio")
}

function evaluarSemaforoPorRegla(registrosAlumno) {
    const registros = (registrosAlumno || []).slice().sort((a, b) => {
        const f = String(a.fecha || "").localeCompare(String(b.fecha || ""))
        return f !== 0 ? f : String(a.hora || "").localeCompare(String(b.hora || ""))
    })

    if (!registros.length) {
        return { estado: "rojo", motivo: "sin_registro" }
    }

    const ultimaFecha = (registros[registros.length - 1] || {}).fecha || ""
    const primerMarcadoUltimoDia = registros
        .filter(x => x.fecha === ultimaFecha)
        .sort((a, b) => (a.hora || "").localeCompare(b.hora || ""))[0]
    const seccionEvaluada = String(primerMarcadoUltimoDia?.seccion || "").trim().toUpperCase()
    const regla = obtenerReglaSeccion(seccionEvaluada)
    const horaMarcadaMin = horaATotalMinutos(primerMarcadoUltimoDia?.hora || "")
    const horaMarcadaTexto = String(primerMarcadoUltimoDia?.hora || "").slice(0, 5)

    if (!seccionEvaluada) {
        return { estado: "rojo", motivo: "sin_seccion", fecha: ultimaFecha, horaMarcada: horaMarcadaTexto, seccion: "-", horaInicio: "-" }
    }

    if (!regla || regla.horaInicioMin == null) {
        return { estado: "rojo", motivo: "sin_hora_configurada", fecha: ultimaFecha, horaMarcada: horaMarcadaTexto, seccion: seccionEvaluada, horaInicio: "-" }
    }

    if (regla.dias.length) {
        const dia = obtenerDiaSemanaEs(ultimaFecha)
        if (!regla.dias.includes(dia)) {
            return { estado: "rojo", motivo: "fuera_de_dia_configurado", fecha: ultimaFecha, horaMarcada: horaMarcadaTexto, seccion: seccionEvaluada, horaInicio: regla.horaInicioTexto || "-" }
        }
    }

    if (horaMarcadaMin == null) {
        return { estado: "rojo", motivo: "sin_hora_marcada", fecha: ultimaFecha, horaMarcada: "-", seccion: seccionEvaluada, horaInicio: regla.horaInicioTexto || "-" }
    }

    // Si la marcación cae en madrugada para una sección de tarde/noche, se considera inválida.
    const deltaMin = horaMarcadaMin - regla.horaInicioMin
    if (deltaMin < -120) {
        return { estado: "rojo", motivo: "hora_invalida_para_seccion", fecha: ultimaFecha, horaMarcada: horaMarcadaTexto, seccion: seccionEvaluada, horaInicio: regla.horaInicioTexto || "-" }
    }

    if (deltaMin <= 10) {
        return { estado: "verde", motivo: "a_tiempo", fecha: ultimaFecha, horaMarcada: horaMarcadaTexto, seccion: seccionEvaluada, horaInicio: regla.horaInicioTexto || "-" }
    }
    if (deltaMin <= 30) {
        return { estado: "amarillo", motivo: "tardanza_moderada", fecha: ultimaFecha, horaMarcada: horaMarcadaTexto, seccion: seccionEvaluada, horaInicio: regla.horaInicioTexto || "-" }
    }
    return { estado: "rojo", motivo: "tardanza_alta", fecha: ultimaFecha, horaMarcada: horaMarcadaTexto, seccion: seccionEvaluada, horaInicio: regla.horaInicioTexto || "-" }
}

function distanciaMetros(lat1, lon1, lat2, lon2) {
    const toRad = (deg) => deg * Math.PI / 180
    const R = 6371000
    const dLat = toRad(lat2 - lat1)
    const dLon = toRad(lon2 - lon1)
    const a =
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
        Math.sin(dLon / 2) * Math.sin(dLon / 2)
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
    return R * c
}

function obtenerUbosUnicosDesdeAsistencias(data) {
    return Array.from(new Set((data || []).map(x => (x.ubo || "").trim()).filter(Boolean)))
        .sort((a, b) => parseInt(a) - parseInt(b))
}

function construirOptionsUbo(ubos, includeEmpty = true, emptyText = "Seleccionar UBO") {
    let html = includeEmpty ? `<option value="">${emptyText}</option>` : ""
    ubos.forEach(u => {
        html += `<option value="${u}">${u}</option>`
    })
    return html
}

function cargarFiltroSeccionDashboard() {
    const el = document.getElementById("dashSeccion")
    if (!el) return
    const previo = el.value || ""
    let secciones = (cursoSecciones || [])
        .map(x => String(x.seccion || "").trim().toUpperCase())
        .filter(Boolean)

    if (!secciones.length) {
        secciones = ["A", "B", "C"]
    }

    const unicas = Array.from(new Set(secciones)).sort()
    let html = `<option value="">Todas las Secciones</option>`
    unicas.forEach(s => {
        html += `<option value="${s}">Sección ${s}</option>`
    })
    el.innerHTML = html
    if (previo && unicas.includes(previo)) {
        el.value = previo
    }
}

function descargarExcelDesdeJSON(filename, rows) {
    if (!window.XLSX) {
        alert("Librería XLSX no disponible")
        return
    }
    const ws = XLSX.utils.json_to_sheet(rows)
    const wb = XLSX.utils.book_new()
    XLSX.utils.book_append_sheet(wb, ws, "Datos")
    XLSX.writeFile(wb, filename)
}

function exportarReportesExcel() {
    if (!cacheReportes.length) {
        alert("No hay datos para exportar")
        return
    }

    const rows = cacheReportes.map(r => ({
        DNI: r.dni || "",
        Nombre: r.nombre || "",
        UBO: r.ubo || "",
        Fecha: r.fecha || "",
        Hora: r.hora || "",
        Alerta: r.alerta || ""
    }))

    descargarExcelDesdeJSON("reportes_asistencia.xlsx", rows)
}

function exportarRiesgoUboExcel() {
    if (!cacheRiesgoUbo.length) {
        alert("No hay datos de riesgo UBO para exportar")
        return
    }

    const rows = cacheRiesgoUbo.map(([ubo, casos]) => {
        const item = (casos && typeof casos === "object") ? casos : {}
        return {
            UBO: ubo,
            Total: Number(item.total || 0),
            Tardanza: Number(item.tardanza || 0),
            "Fuera de día": Number(item.fueraDia || 0),
            Otros: Number(item.otros || 0)
        }
    })

    descargarExcelDesdeJSON("dashboard_riesgo_ubo.xlsx", rows)
}

function exportarDashboardPDF() {
    if (!window.jspdf?.jsPDF || !window.html2canvas) {
        alert("Librerías para exportación no disponibles")
        return
    }

    const objetivo = document.getElementById("dashboardKpiCapture")
    if (!objetivo) {
        alert("No se encontró el bloque de KPIs para exportar")
        return
    }

    html2canvas(objetivo, { scale: 2, backgroundColor: "#eff2f7" })
        .then(canvas => {
            const imgData = canvas.toDataURL("image/png")
            const { jsPDF } = window.jspdf
            const doc = new jsPDF("p", "mm", "a4")
            const pageW = doc.internal.pageSize.getWidth()
            const margin = 10
            const maxW = pageW - margin * 2
            const imgW = canvas.width
            const imgH = canvas.height
            const pdfH = (imgH * maxW) / imgW

            doc.setFontSize(13)
            doc.text("Dashboard ESBAS - KPIs", margin, 10)
            doc.addImage(imgData, "PNG", margin, 14, maxW, pdfH)
            doc.save("dashboard_kpis_esbas.pdf")
        })
        .catch(err => {
            console.error(err)
            alert("No se pudo exportar la imagen del dashboard")
        })
}

async function cargarUsuariosAdminDesdeSupabase() {
    if (!haySupabase()) {
        usuariosAdmin = []
        renderUsuariosAdmin()
        return
    }

    let data = []
    let error = null

        ; ({ data, error } = await supabaseClient
            .from("usuarios_admin")
            .select("id,nombre,nombres,apellidos,dni,correo,celular,usuario,clave,rol,activo,tenant_id,auth_user_id")
            .eq("activo", true)
            .order("nombre", { ascending: true }))

    if (error && /(tenant_id|nombres|apellidos|dni|correo|celular|auth_user_id)/i.test(String(error.message || ""))) {
        const fallback = await supabaseClient
            .from("usuarios_admin")
            .select("id,nombre,usuario,clave,rol,activo")
            .eq("activo", true)
            .order("nombre", { ascending: true })
        data = (fallback.data || []).map(u => Object.assign({}, u, {
            tenant_id: null,
            nombres: "",
            apellidos: "",
            dni: "",
            correo: "",
            celular: "",
            auth_user_id: null
        }))
        error = fallback.error
    }

    if (error) {
        if (!esTablaNoExiste(error)) {
            console.warn("No se pudo cargar usuarios_admin:", error.message)
        }
        usuariosAdmin = []
        renderUsuariosAdmin()
        return
    }

    usuariosAdmin = (data || []).map(u => ({
        id: u.id,
        nombre: u.nombre || "",
        nombres: u.nombres || String(u.nombre || "").trim().split(" ").slice(0, 1).join(" "),
        apellidos: u.apellidos || String(u.nombre || "").trim().split(" ").slice(1).join(" "),
        dni: u.dni || "",
        correo: u.correo || "",
        celular: u.celular || "",
        usuario: (u.usuario || "").toLowerCase(),
        clave: u.clave || "",
        rol: normalizarRolUsuario(u.rol),
        tenantId: String(u.tenant_id || "").trim().toLowerCase(),
        authUserId: String(u.auth_user_id || "").trim()
    }))
    renderUsuariosAdmin()
}

function renderUsuariosAdmin() {
    if (!tablaUsuariosAdmin) return
    poblarPerfilesInstitucionales()
    const tenantActual = String(tenantActivoId || "").trim().toLowerCase()
    const usuariosInstitucionales = usuariosAdmin
        .map((u, sourceIndex) => Object.assign({}, u, { sourceIndex }))
        .filter(u =>
            !SYSTEM_USERS.some(s => s.usuario === u.usuario) &&
            normalizarRolUsuario(u.rol) !== ROLES_ADMIN.SUPERUSUARIO &&
            (!tenantActual || !String(u.tenantId || "").trim() || String(u.tenantId || "").trim().toLowerCase() === tenantActual)
        )
    const data = SYSTEM_USERS.concat(usuariosInstitucionales)

    if (!data.length) {
        tablaUsuariosAdmin.innerHTML = `<tr><td colspan="10">Sin usuarios creados.</td></tr>`
        return
    }

    let html = ""
    data.forEach((u, idx) => {
        const isSystem = !!u.system
        const perfilId = String(perfilesUsuariosLocales?.[String(u.usuario || "").toLowerCase()] || "administrador")
        const perfilNombre = obtenerPerfilPorId(perfilId)?.nombre || "Administrador"
        html += `
      <tr>
        <td>${u.nombres || u.nombre || ""}${isSystem ? `<span class="tag-system">SISTEMA</span>` : ""}</td>
        <td>${u.apellidos || "-"}</td>
        <td>${u.dni || "-"}</td>
        <td>${u.correo || "-"}</td>
        <td>${u.celular || "-"}</td>
        <td>${u.usuario || ""}</td>
        <td>${u.rol || ""}</td>
        <td>${perfilNombre}</td>
        <td>
          <div class="table-actions">
            ${isSystem
                ? `<span class="hint">No editable</span>`
                : `<button onclick="editarUsuarioAdmin(${u.sourceIndex})">Modificar</button>
                 <button class="secondary" onclick="eliminarUsuarioAdmin(${u.sourceIndex})">Eliminar</button>`
            }
          </div>
        </td>
      </tr>
    `
    })
    tablaUsuariosAdmin.innerHTML = html
}

function limpiarUsuarioAdmin() {
    if (userNombres) userNombres.value = ""
    if (userApellidos) userApellidos.value = ""
    if (userDni) userDni.value = ""
    if (userCorreo) userCorreo.value = ""
    if (userCelular) userCelular.value = ""
    userLogin.value = ""
    userPass.value = ""
    userRol.value = "administrador"
    if (userPerfil) userPerfil.value = "administrador"
    editUsuarioIndex = -1
}

function cancelarEdicionUsuarioAdmin() {
    limpiarUsuarioAdmin()
}

async function guardarUsuarioAdmin() {
    const nombres = (userNombres?.value || "").trim()
    const apellidos = (userApellidos?.value || "").trim()
    const dni = String(userDni?.value || "").replace(/\D/g, "")
    const correo = String(userCorreo?.value || "").trim().toLowerCase()
    const celular = String(userCelular?.value || "").replace(/\D/g, "")
    const usuario = (userLogin.value || "").trim().toLowerCase()
    const clave = (userPass.value || "").trim()
    const rol = normalizarRolUsuario(userRol.value)
    const perfilId = normalizarPerfilId(userPerfil?.value || "administrador") || "administrador"

    if (!nombres || !apellidos || !dni || !usuario || !clave) {
        alert("Completa nombres, apellidos, DNI, usuario y clave")
        return
    }
    if (dni.length !== 8) {
        alert("El DNI debe tener 8 dígitos.")
        return
    }
    if (correo && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo)) {
        alert("Correo no válido.")
        return
    }
    if (celular && celular.length < 9) {
        alert("Celular no válido.")
        return
    }

    const item = {
        nombre: `${nombres} ${apellidos}`.trim(),
        nombres,
        apellidos,
        dni,
        correo,
        celular,
        usuario,
        clave,
        rol,
        tenant_id: tenantActivoId || null
    }
    const perfil = obtenerPerfilPorId(perfilId)
    if (!perfil || perfil.estado !== "activo") {
        alert("Selecciona un perfil activo.")
        return
    }
    if (rol === ROLES_ADMIN.SUPERUSUARIO) {
        alert("El rol superusuario es global y no se gestiona en este módulo institucional.")
        return
    }
    let accion = "usuario_admin_institucional_creado"
    if (editUsuarioIndex >= 0) {
        const original = usuariosAdmin[editUsuarioIndex]
        if (!original?.id) {
            alert("No se encontró el usuario a editar")
            return
        }
        let { error } = await supabaseClient
            .from("usuarios_admin")
            .update(item)
            .eq("id", original.id)
        if (error && /(tenant_id|nombres|apellidos|dni|correo|celular)/i.test(String(error.message || ""))) {
            const itemFallback = { nombre: `${nombres} ${apellidos}`.trim(), usuario, clave, rol }
            const fallback = await supabaseClient
                .from("usuarios_admin")
                .update(itemFallback)
                .eq("id", original.id)
            error = fallback.error
        }
        if (error) {
            alert(`No se pudo actualizar: ${error.message}`)
            return
        }
        accion = "usuario_admin_institucional_editado"
    } else {
        if (SYSTEM_USERS.some(s => s.usuario === usuario)) {
            alert("Ese usuario es del sistema y ya existe")
            return
        }
        const exists = usuariosAdmin.find(x => x.usuario === usuario)
        if (exists) {
            alert("Ese usuario ya existe")
            return
        }
        let { error } = await supabaseClient
            .from("usuarios_admin")
            .insert([{ ...item, activo: true }])
        if (error && /(tenant_id|nombres|apellidos|dni|correo|celular)/i.test(String(error.message || ""))) {
            const fallback = await supabaseClient
                .from("usuarios_admin")
                .insert([{ nombre: `${nombres} ${apellidos}`.trim(), usuario, clave, rol, activo: true }])
            error = fallback.error
        }
        if (error) {
            alert(`No se pudo crear usuario: ${error.message}`)
            return
        }
    }

    await cargarUsuariosAdminDesdeSupabase()
    perfilesUsuariosLocales[usuario] = perfilId
    guardarLuizLabsEnStorage()
    limpiarUsuarioAdmin()
    registrarActividad(accion, { usuario, rol, perfilId, dni }, { tenantId: tenantActivoId })
}

function editarUsuarioAdmin(idx) {
    const u = usuariosAdmin[idx]
    if (!u) return
    if (userNombres) userNombres.value = u.nombres || u.nombre || ""
    if (userApellidos) userApellidos.value = u.apellidos || ""
    if (userDni) userDni.value = u.dni || ""
    if (userCorreo) userCorreo.value = u.correo || ""
    if (userCelular) userCelular.value = u.celular || ""
    userLogin.value = u.usuario || ""
    userPass.value = u.clave || ""
    userRol.value = normalizarRolUsuario(u.rol)
    if (userPerfil) {
        const perfil = String(perfilesUsuariosLocales?.[String(u.usuario || "").toLowerCase()] || "administrador")
        userPerfil.value = perfil
    }
    editUsuarioIndex = idx
}

async function eliminarUsuarioAdmin(idx) {
    if (!confirm("¿Eliminar usuario?")) return
    const u = usuariosAdmin[idx]
    if (!u?.id) return

    const { error } = await supabaseClient
        .from("usuarios_admin")
        .update({ activo: false })
        .eq("id", u.id)
    if (error) {
        alert(`No se pudo eliminar usuario: ${error.message}`)
        return
    }
    await cargarUsuariosAdminDesdeSupabase()
    delete perfilesUsuariosLocales[String(u.usuario || "").toLowerCase()]
    guardarLuizLabsEnStorage()
    registrarActividad("usuario_admin_institucional_desactivado", {
        usuario: u.usuario || "",
        id: u.id
    }, { tenantId: tenantActivoId })
}

async function cargarExcelAspirantes() {
    const file = archivoAspirantes.files?.[0]
    if (!file) {
        msgCargaAspirantes.innerText = "Selecciona un archivo primero."
        return
    }
    if (!window.XLSX) {
        msgCargaAspirantes.innerText = "No está disponible la librería XLSX."
        return
    }

    const buffer = await file.arrayBuffer()
    const wb = XLSX.read(buffer, { type: "array" })
    const ws = wb.Sheets[wb.SheetNames[0]]
    const rows = XLSX.utils.sheet_to_json(ws, { defval: "" })

    if (!rows.length) {
        msgCargaAspirantes.innerText = "El archivo no tiene filas."
        return
    }

    const keys = Object.keys(rows[0]).map(k => k.toLowerCase().trim())
    const required = ["apellidos", "nombres", "dni", "ubo"]
    const faltantes = required.filter(k => !keys.includes(k))
    if (faltantes.length) {
        msgCargaAspirantes.innerText = `Faltan columnas requeridas: ${faltantes.join(", ")}.`
        return
    }

    const parsed = rows
        .map(r => ({
            apellidos: String(r.apellidos ?? r.Apellidos ?? "").trim(),
            nombres: String(r.nombres ?? r.Nombres ?? "").trim(),
            dni: String(r.dni ?? r.DNI ?? "").replace(/\D/g, ""),
            ubo: String(r.ubo ?? r.UBO ?? "").trim()
        }))
        .filter(r => r.apellidos && r.nombres && r.dni && r.ubo)

    if (!parsed.length) {
        msgCargaAspirantes.innerText = "No se encontraron filas válidas."
        return
    }

    const payload = parsed.map(r => withTenantPayload({
        dni: r.dni,
        nombres: r.nombres,
        apellidos: r.apellidos,
        ubo: r.ubo
    }))

    const { error } = await supabaseClient
        .from("aspirantes")
        .upsert(payload, { onConflict: "dni" })

    if (error) {
        msgCargaAspirantes.innerText = `No se pudo cargar en Supabase: ${error.message}`
        return
    }

    msgCargaAspirantes.innerText = `Carga exitosa: ${payload.length} aspirantes procesados.`
    await cargarAspirantesCargados()
    registrarActividad("aspirantes_carga_excel", {
        total: payload.length
    }, { tenantId: tenantActivoId })
}

async function cargarAspirantesCargados() {
    const tablaEl = document.getElementById("tablaAspirantesCargados")
    const msgEl = document.getElementById("msgCargaAspirantes")
    if (!tablaEl) return
    try {
        if (!haySupabase()) {
            tablaEl.innerHTML = `<tr><td colspan="5">Supabase no disponible.</td></tr>`
            if (msgEl) msgEl.innerText = "No se pudo conectar con Supabase."
            return
        }

        const normalizarTexto = (v) => String(v || "").trim()
        const limpiarDni = (v) => String(v || "").replace(/\D/g, "")
        const registros = new Map()

        let dataAspirantes = []
        let errorAspirantes = null

            // Intenta leer tenant_id para aislar por institución cuando la columna exista.
            ; ({ data: dataAspirantes, error: errorAspirantes } = await withTenantScope(
                supabaseClient
                    .from("aspirantes")
                    .select("apellidos,nombres,dni,ubo,tenant_id")
                    .limit(1000)
            ))

        if (errorAspirantes && /tenant_id/i.test(String(errorAspirantes.message || ""))) {
            // Compatibilidad con esquemas legacy sin tenant_id en aspirantes.
            const fallback = await withTenantScope(
                supabaseClient
                    .from("aspirantes")
                    .select("apellidos,nombres,dni,ubo")
                    .limit(1000)
            )

            dataAspirantes = (fallback.data || []).map(r => Object.assign({}, r, { tenant_id: null }))
            errorAspirantes = fallback.error
        }

        if (errorAspirantes) {
            tablaEl.innerHTML = `<tr><td colspan="5">No se pudo cargar el listado.</td></tr>`
            if (msgEl) msgEl.innerText = `Error listando aspirantes: ${errorAspirantes.message || "desconocido"}`
            return
        }

        const aspirantesScoped = filtrarDataTenantActivo(dataAspirantes || [])

            ; (aspirantesScoped || []).forEach(r => {
                const dni = limpiarDni(r.dni)
                if (!dni) return
                registros.set(dni, {
                    apellidos: normalizarTexto(r.apellidos),
                    nombres: normalizarTexto(r.nombres),
                    dni,
                    ubo: normalizarTexto(r.ubo),
                    origen: "Aspirantes"
                })
            })

        const { data: dataAsistencias, error: errorAsistencias } = await withTenantScope(supabaseClient
            .from("asistencias")
            .select("nombre,dni,ubo,fecha,hora,tenant_id")
            .order("fecha", { ascending: false })
            .order("hora", { ascending: false })
            .limit(1200))

        if (!errorAsistencias) {
            const asistencias = filtrarDataTenantActivo(dataAsistencias)
            asistencias.forEach(r => {
                const dni = limpiarDni(r.dni)
                if (!dni || registros.has(dni)) return
                registros.set(dni, {
                    apellidos: "",
                    nombres: normalizarTexto(r.nombre),
                    dni,
                    ubo: normalizarTexto(r.ubo),
                    origen: "Asistencias (SQL)"
                })
            })
        }

        const lista = Array.from(registros.values())
            .sort((a, b) => {
                const aa = `${a.apellidos} ${a.nombres}`.trim().toLowerCase()
                const bb = `${b.apellidos} ${b.nombres}`.trim().toLowerCase()
                return aa.localeCompare(bb)
            })
            .slice(0, 600)

        if (!lista.length) {
            tablaEl.innerHTML = `<tr><td colspan="5">Sin aspirantes cargados.</td></tr>`
            if (msgEl) msgEl.innerText = "Listado actualizado: 0 registros."
            return
        }

        let html = ""
        lista.forEach(r => {
            html += `
        <tr>
          <td>${r.apellidos || ""}</td>
          <td>${r.nombres || ""}</td>
          <td>${r.dni || ""}</td>
          <td>${r.ubo || ""}</td>
          <td>${r.origen || ""}</td>
        </tr>
      `
        })
        tablaEl.innerHTML = html
        if (msgEl) msgEl.innerText = `Listado actualizado: ${lista.length} registro(s).`
    } catch (e) {
        console.error("Error en cargarAspirantesCargados:", e)
        tablaEl.innerHTML = `<tr><td colspan="5">Error cargando listado.</td></tr>`
        if (msgEl) msgEl.innerText = "Error cargando listado de aspirantes."
    }
}

async function cargarExcelUbosSedes() {
    const file = archivoUbosSedes.files?.[0]
    if (!file) {
        msgCargaUbosSedes.innerText = "Selecciona un archivo primero."
        return
    }
    if (!window.XLSX) {
        msgCargaUbosSedes.innerText = "No está disponible la librería XLSX."
        return
    }

    const buffer = await file.arrayBuffer()
    const wb = XLSX.read(buffer, { type: "array" })
    const ws = wb.Sheets[wb.SheetNames[0]]
    const rows = XLSX.utils.sheet_to_json(ws, { defval: "" })

    if (!rows.length) {
        msgCargaUbosSedes.innerText = "El archivo no tiene filas."
        return
    }

    const normalize = (s) => String(s || "")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .trim()
        .toLowerCase()

    const keyMap = {}
    Object.keys(rows[0]).forEach(k => {
        keyMap[normalize(k)] = k
    })

    const kUbo = keyMap.ubo
    const kLat = keyMap.latitud || keyMap.ltitud
    const kLng = keyMap.longitud || keyMap.longtitud || keyMap.longitug
    const kNombre = keyMap.nombre

    if (!kUbo || !kLat || !kLng) {
        msgCargaUbosSedes.innerText = "Columnas requeridas: UBO, LATITUD y LONGITUD."
        return
    }

    const parsed = rows
        .map(r => ({
            ubo: String(r[kUbo] || "").trim(),
            lat: Number(String(r[kLat] || "").replace(",", ".")),
            lng: Number(String(r[kLng] || "").replace(",", ".")),
            nombre: kNombre ? String(r[kNombre] || "").trim() : ""
        }))
        .filter(r => r.ubo && Number.isFinite(r.lat) && Number.isFinite(r.lng))

    if (!parsed.length) {
        msgCargaUbosSedes.innerText = "No se encontraron filas válidas."
        return
    }

    const payload = parsed.map(r => ({
        ubo: r.ubo,
        nombre: r.nombre || `UBO ${r.ubo}`,
        lat: r.lat,
        lng: r.lng,
        activo: true
    }))

    const { error } = await supabaseClient
        .from("ubos_sedes")
        .upsert(payload, { onConflict: "ubo" })

    if (error) {
        msgCargaUbosSedes.innerText = `No se pudo cargar en Supabase: ${error.message}`
        return
    }

    msgCargaUbosSedes.innerText = `Carga exitosa: ${payload.length} UBO(s) procesadas.`
    await cargarUbos()
    registrarActividad("gps_carga_coordenadas", {
        totalUbos: payload.length
    }, { tenantId: tenantActivoId })
}

async function cargarSedesUbo() {
    const { data, error } = await supabaseClient
        .from("ubos_sedes")
        .select("ubo,nombre,lat,lng,activo")
        .eq("activo", true)

    if (error) {
        console.warn("No se pudo cargar ubos_sedes:", error.message)
        ubosSedeCache = []
        return
    }

    ubosSedeCache = data || []
}

async function cargarSeccionesCursoDesdeSupabase() {
    let q = withTenantScope(supabaseClient.from("curso_secciones").select("*"))
    const { data, error } = await q
        .order("seccion", { ascending: true })

    if (error) {
        if (esTablaNoExiste(error)) return null
        console.warn("No se pudo cargar curso_secciones:", error.message)
        return null
    }

    return (data || []).map(x => ({
        seccion: String(x.seccion || "").trim(),
        modalidad: x.modalidad || "Presencial",
        hora_inicio: x.hora_inicio || "",
        dias: Array.isArray(x.dias) ? x.dias : []
    })).filter(x => x.seccion)
}

async function cargarSedesCursoDesdeSupabase() {
    let q = withTenantScope(supabaseClient.from("curso_sedes_ubo").select("*"))
    const { data, error } = await q
        .order("seccion", { ascending: true })

    if (error) {
        if (esTablaNoExiste(error)) return null
        console.warn("No se pudo cargar curso_sedes_ubo:", error.message)
        return null
    }

    return (data || []).map(x => ({
        seccion: String(x.seccion || "").trim(),
        ubo: String(x.ubo || "").trim(),
        modalidad: x.modalidad || "Presencial",
        hora_inicio: x.hora_inicio || "",
        dias: Array.isArray(x.dias) ? x.dias : [],
        todos_dias: !!x.todos_dias
    })).filter(x => x.seccion)
}

function guardarEstructuraCursoLocal() { }

const CURSO_MSG_CLEAR_MS = 9000
let cursoModuloMsgTimers = {}

function mostrarMsgCursoModulo(elId, texto, tipo = "") {
    const el = typeof elId === "string" ? document.getElementById(elId) : elId
    if (!el) return
    if (cursoModuloMsgTimers[el.id]) {
        clearTimeout(cursoModuloMsgTimers[el.id])
        cursoModuloMsgTimers[el.id] = null
    }
    el.textContent = texto || ""
    el.className = "course-inline-msg"
    if (texto && tipo) {
        el.classList.add(`course-inline-msg--${tipo}`)
    }
    if (texto && tipo && tipo !== "error") {
        cursoModuloMsgTimers[el.id] = setTimeout(() => {
            el.textContent = ""
            el.className = "course-inline-msg"
        }, CURSO_MSG_CLEAR_MS)
    }
}

function actualizarUIModoEdicionSeccion() {
    const btn = document.getElementById("btnSecCursoPrimary")
    const btnCancel = document.getElementById("btnSecCursoCancel")
    const banner = document.getElementById("courseSecEditBanner")
    const label = document.getElementById("courseSecEditLabel")
    const module = document.getElementById("courseModuleSecciones")
    const editing = editSeccionCursoIndex >= 0
    if (btn) btn.textContent = editing ? "GUARDAR CAMBIOS" : "CREAR SECCIÓN"
    if (btnCancel) btnCancel.textContent = editing ? "Cancelar edición" : "Limpiar formulario"
    if (banner) banner.hidden = !editing
    if (label && editing) {
        const item = cursoSecciones[editSeccionCursoIndex]
        label.textContent = item ? String(item.seccion || "").trim() || "—" : "—"
    }
    if (module) module.classList.toggle("course-module--editing", editing)
}

function actualizarUIModoEdicionSede() {
    const btn = document.getElementById("btnSedePrimary")
    const btnCancel = document.getElementById("btnSedeCancel")
    const banner = document.getElementById("courseSedeEditBanner")
    const label = document.getElementById("courseSedeEditLabel")
    const module = document.getElementById("courseModuleSedeUbo")
    const editing = editSedeUboIndex >= 0
    if (btn) btn.textContent = editing ? "GUARDAR CAMBIOS" : "CREAR SEDE UBO"
    if (btnCancel) btnCancel.textContent = editing ? "Cancelar edición" : "Limpiar formulario"
    if (banner) banner.hidden = !editing
    if (label && editing) {
        const item = cursoSedesUbo[editSedeUboIndex]
        if (item) {
            label.textContent = `Sección ${String(item.seccion || "").trim()} · UBO ${String(item.ubo || "").trim()}`
        } else {
            label.textContent = "—"
        }
    }
    if (module) module.classList.toggle("course-module--editing", editing)
}

function cancelarEdicionSeccionCurso() {
    const wasEditing = editSeccionCursoIndex >= 0
    limpiarFormSeccionCurso()
    if (wasEditing) {
        mostrarMsgCursoModulo("msgCursoSeccion", "Edición cancelada.", "info")
    } else {
        mostrarMsgCursoModulo("msgCursoSeccion", "Formulario limpiado.", "info")
    }
}

function cancelarEdicionSedeUbo() {
    const wasEditing = editSedeUboIndex >= 0
    limpiarFormSedeUbo()
    if (wasEditing) {
        mostrarMsgCursoModulo("msgCursoSede", "Edición cancelada.", "info")
    } else {
        mostrarMsgCursoModulo("msgCursoSede", "Formulario limpiado.", "info")
    }
}

function confirmarLimpiarListasCurso() {
    const ok = confirm(
        "¿Eliminar todas las secciones y sedes UBO del curso?\n\n" +
        "Se borrarán en el servidor las filas de secciones y de sedes UBO (curso actual). " +
        "La configuración general del curso (nombre, fechas, radio) no se elimina en base de datos; " +
        "después de vaciar, la pantalla se sincronizará con el servidor para que coincida cache y formulario.\n\n" +
        "Esta operación no se puede deshacer."
    )
    if (!ok) {
        mostrarMsgCursoModulo("msgCursoFooter", "Operación cancelada.", "info")
        return
    }
    void limpiarCurso()
}

async function aplicarCursoEnUI(cfg) {
    editSeccionCursoIndex = -1
    editSedeUboIndex = -1
    if (cfg) {
        cursoNombre.value = String(cfg.nombre_curso || "").toUpperCase()
        cursoInicio.value = cfg.fecha_inicio || ""
        cursoFin.value = cfg.fecha_fin || ""
        cursoRadio.value = cfg.radio_m || 50
        toggleGPS.checked = !!cfg.gps_activo
    } else {
        cursoNombre.value = ""
        cursoInicio.value = ""
        cursoFin.value = ""
        cursoRadio.value = "50"
        toggleGPS.checked = false
    }

    const seccionesDb = await cargarSeccionesCursoDesdeSupabase()
    if (Array.isArray(seccionesDb)) {
        cursoSecciones = seccionesDb
    } else {
        cursoSecciones = []
    }

    const sedesDb = await cargarSedesCursoDesdeSupabase()
    if (Array.isArray(sedesDb)) {
        cursoSedesUbo = sedesDb
    } else {
        cursoSedesUbo = []
    }

    guardarEstructuraCursoLocal()

    renderSeccionesCurso()
    actualizarOpcionesSeccionSede()
    cargarFiltroSeccionDashboard()
    renderSedesUbo()
    actualizarUIModoEdicionSeccion()
    actualizarUIModoEdicionSede()
}

async function cargarConfigCurso() {
    let q = withTenantScope(supabaseClient.from("curso_configuracion").select("*"))
    const { data, error } = await q
        .maybeSingle()

    if (error) {
        console.warn("No se pudo cargar curso_configuracion:", error.message)
        cursoConfigCache = null
        await aplicarCursoEnUI(null)
        return
    }

    cursoConfigCache = data || null
    await aplicarCursoEnUI(cursoConfigCache)
}

function obtenerGeoActual() {
    return new Promise((resolve, reject) => {
        if (!navigator.geolocation) {
            reject(new Error("Geolocalización no disponible en este navegador"))
            return
        }

        navigator.geolocation.getCurrentPosition(
            (pos) => resolve(pos.coords),
            (err) => reject(err),
            { enableHighAccuracy: true, timeout: 12000, maximumAge: 0 }
        )
    })
}

async function registrarAlerta(payload) {
    try {
        await supabaseClient.from("asistencia_alertas").insert(withTenantPayloadList([payload]))
    } catch (e) {
        console.warn("No se pudo registrar alerta:", e)
    }
}

function obtenerClavesAlertaDispositivo(data) {
    const claves = new Set()
    const historial = (data || []).slice().sort((a, b) => {
        const aKey = `${a.fecha || ""} ${a.hora || ""}`
        const bKey = `${b.fecha || ""} ${b.hora || ""}`
        return aKey.localeCompare(bKey)
    })

    const dniPorDispositivo = {}

    historial.forEach(r => {
        const dev = r.device_id || ""
        const dniVal = (r.dni || "").trim()
        if (!dev || !dniVal) return

        if (!dniPorDispositivo[dev]) {
            dniPorDispositivo[dev] = new Set()
        }

        if (dniPorDispositivo[dev].size > 0 && !dniPorDispositivo[dev].has(dniVal)) {
            claves.add(`${dev}|${dniVal}|${r.fecha || ""}|${r.hora || ""}`)
        }

        dniPorDispositivo[dev].add(dniVal)
    })

    return claves
}

function abrirScanner() {
    if (scanningActivo) return
    scanningActivo = true
    scanOverlay.style.display = "flex"
    video.style.display = "block"
}

function cerrarScanner() {
    scanningActivo = false
    detenerCamara()
    scanOverlay.style.display = "none"
    video.style.display = "none"
}

function aplicarLayout() {
    const elTenant = document.getElementById("tenantScreen")
    const elLogin = document.getElementById("loginScreen")
    const elDesktop = document.getElementById("vistaDesktop")
    const elLuizLabs = document.getElementById("vistaLuizLabs")
    const elMovilInicio = document.getElementById("vistaMovilInicio")
    const elMovil = document.getElementById("vistaMovil")
    const elFormulario = document.getElementById("formulario")
    const elBtnInstitucion = document.getElementById("btnInstitucion")
    const elBtnVolverLuizLabs = document.getElementById("btnVolverLuizLabs")
    const vista = getVistaActiva()

    // --- Lógica de Title Dinámico ---
    if (!accesoDirectoInstitucion) {
        document.title = "asistIA - Panel Administrativo";
    } else {
        const t = institucionesLuiz.find(x => x.id === tenantActivoId);
        document.title = (t && t.nombre ? t.nombre : "Institución") + " - Panel Administrativo";
    }


    if (elBtnInstitucion) {
        elBtnInstitucion.style.display = accesoDirectoInstitucion ? "none" : "inline-flex"
    }
    if (elBtnVolverLuizLabs) {
        const mostrar = !esModoStaff && haySesionAdminActiva() && esSuperusuarioActivo()
        elBtnVolverLuizLabs.style.display = mostrar ? "inline-flex" : "none"
    }

    if (vista === "mobile") {
        if (puedeEntrarPanelAdmin()) {
            cerrarScanner()
            if (elTenant) elTenant.style.display = "none"
            if (elLogin) elLogin.style.display = "none"
            if (elLuizLabs) elLuizLabs.style.display = "none"
            if (elMovilInicio) elMovilInicio.style.display = "none"
            if (elMovil) elMovil.style.display = "none"
            if (elFormulario) elFormulario.style.display = "none"
            if (elDesktop) elDesktop.style.display = "block"
            aplicarRestriccionesPanelPorContexto()
            if (!vistaAdminActual) {
                mostrarVista("reportes")
            }
        } else {
            if (puedeEntrarPanelLuizLabs()) {
                if (elTenant) elTenant.style.display = "none"
                if (elLogin) elLogin.style.display = "none"
                if (elDesktop) elDesktop.style.display = "none"
                if (elMovilInicio) elMovilInicio.style.display = "none"
                if (elMovil) elMovil.style.display = "none"
                if (elFormulario) elFormulario.style.display = "none"
                if (elLuizLabs) elLuizLabs.style.display = "block"
                renderPanelLuizLabs()
                return
            }
            if (elTenant) elTenant.style.display = "none"
            if (elLogin) elLogin.style.display = "none"
            if (elDesktop) elDesktop.style.display = "none"
            if (elLuizLabs) elLuizLabs.style.display = "none"
            if (elMovilInicio) elMovilInicio.style.display = dniMovil ? "none" : "flex"
            if (elMovil) elMovil.style.display = dniMovil ? "block" : "none"

            if (elFormulario && elFormulario.style.display !== "block") {
                mostrarPasoMovil(dniMovil ? "scan" : "ingreso")
            }
        }
    } else {
        cerrarScanner()
        if (elMovilInicio) elMovilInicio.style.display = "none"
        if (elMovil) elMovil.style.display = "none"
        if (elFormulario) elFormulario.style.display = "none"

        if (puedeEntrarPanelLuizLabs()) {
            if (elTenant) elTenant.style.display = "none"
            if (elLogin) elLogin.style.display = "none"
            if (elDesktop) elDesktop.style.display = "none"
            if (elLuizLabs) elLuizLabs.style.display = "block"
            renderPanelLuizLabs()
        } else if (puedeEntrarPanelAdmin()) {
            if (elTenant) elTenant.style.display = "none"
            if (elLogin) elLogin.style.display = "none"
            if (elDesktop) elDesktop.style.display = "block"
            if (elLuizLabs) elLuizLabs.style.display = "none"
            aplicarRestriccionesPanelPorContexto()
        } else {
            if (!esModoStaff) {
                // En escritorio institucional mostramos la vista de login/admin.
                if (elTenant) elTenant.style.display = "none"
                if (elLogin) elLogin.style.display = "flex"
                if (elDesktop) elDesktop.style.display = "none"
                if (elLuizLabs) elLuizLabs.style.display = "none"
                if (elMovilInicio) elMovilInicio.style.display = "none"
                if (elMovil) elMovil.style.display = "none"
                if (elFormulario) elFormulario.style.display = "none"
                mostrarPasoMovil("ingreso")
                actualizarBotonesVista()
                aplicarVisibilidadAccesoAdminInstitucional()
                return
            }
            const verSelector = esModoStaff && mostrarSelectorStaff
            if (elTenant) elTenant.style.display = verSelector ? "flex" : "none"
            if (elDesktop) elDesktop.style.display = "none"
            if (elLuizLabs) elLuizLabs.style.display = "none"
            if (elLogin) elLogin.style.display = verSelector ? "none" : "flex"
        }
    }

    actualizarBotonesVista()
    aplicarVisibilidadAccesoAdminInstitucional()
    actualizarInfoSesionHeader()
    evaluarInicioTutorialAutomatico()
}

function actualizarEstadoChecks() {
    document.querySelectorAll(".dias label").forEach(label => {
        const input = label.querySelector("input")
        label.classList.toggle("active-day", !!input?.checked)
    })

    document.querySelectorAll(".mode-options label").forEach(label => {
        const input = label.querySelector("input")
        label.classList.toggle("active-option", !!input?.checked)
    })
}

window.onload = async () => {
    enlazarIdsGlobales()
    await cargarLuizLabsDesdeStorage()
    renderTenantSelector()
    cargarSesionAdminDesdeStorage()
    aplicarAccesoDesdeRuta()
    await actualizarTenantScopeBackendReady()

    try {
        aplicarLayout()
    } catch (e) {
        console.error("Error aplicando layout inicial:", e)
    }

    try {
        aplicarRangoMesActualEnFiltros()
        aplicarRangoMesActualEnLogs()
        await hidratarActividadLogsInicial()
    } catch (e) {
        console.error("Error aplicando rango de fechas:", e)
    }

    if (haySupabase()) {
        try {
            await cargarUbos()
        } catch (e) {
            console.error("Error cargando UBOs:", e)
        }
        try {
            await cargarConfigCurso()
        } catch (e) {
            console.error("Error cargando config curso:", e)
        }
        try {
            await cargarAspirantesCargados()
        } catch (e) {
            console.error("Error cargando aspirantes:", e)
        }
    } else {
        console.error("Supabase no cargó. Verifica conexión/CDN.")
    }

    try {
        await cargarUsuariosAdminDesdeSupabase()
    } catch (e) {
        console.error("Error cargando usuarios admin:", e)
    }

    try {
        actualizarEstadoChecks()
        actualizarEstadoDiasSede()
        activarSelectDiasCompacto("secCursoDiasSelect")
        activarSelectDiasCompacto("uboSecDiasSelect")
        cargarFiltroSeccionDashboard()
    } catch (e) {
        console.error("Error actualizando estado visual:", e)
    }

    try {
        aplicarLayout()
    } catch (e) {
        console.error("Error aplicando layout final:", e)
    }

    if (supabaseClient) {
        const { data: authData } = await supabaseClient.auth.getUser();
        if (authData?.user) {
            await bootstrapAuthorizedApp();
        }
    }

}

async function autenticarAdminConSupabaseAuth(usuario, clave) {
    if (!haySupabase()) return { ok: false, intentado: false }
    const userDb = (usuariosAdmin || []).find(u => u.usuario === usuario)

    const candidatos = []
    const correoDb = String(userDb.correo || "").trim().toLowerCase()
    if (correoDb && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correoDb)) {
        candidatos.push(correoDb)
    }
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(usuario)) {
        candidatos.push(usuario)
    }
    candidatos.push(`${usuario}@asistia.local`)
    const emails = Array.from(new Set(candidatos.filter(Boolean)))
    let intentado = false

    for (const email of emails) {
        intentado = true

        const { data, error } = await supabaseClient.auth.signInWithPassword({
            email,
            password: clave
        })

        // ✅ Exigir sesión real, no solo user
        if (error || !data?.user || !data?.session) {
            try {
                await supabaseClient.auth.signOut()
            } catch (_) { }
            continue
        }

        // ✅ Validar que la sesión quedó realmente activa
        const { data: sessionWrap, error: sessionError } = await supabaseClient.auth.getSession()
        const session = sessionWrap?.session || null

        if (sessionError || !session?.access_token || !session?.user) {
            try {
                await supabaseClient.auth.signOut()
            } catch (_) { }
            continue
        }

        const authId = String(session.user.id || data.user.id || "")

        if (userDb?.authUserId) {
            if (authId && authId === String(userDb.authUserId || "")) {
                return {
                    ok: true,
                    intentado: true,
                    authUserId: authId
                }
            }
            await supabaseClient.auth.signOut()
            continue
        }

        if (authId) {
            return {
                ok: true,
                intentado: true,
                authUserId: authId
            }
        }
    }

    return { ok: false, intentado }
}

async function resolverCredencialesAdminViaRPC(usuario, clave, tenantId = "") {
    if (!haySupabase()) return null
    const tenant = String(tenantId || "").trim().toLowerCase() || null
    const { data, error } = await supabaseClient.rpc("resolver_login_admin", {
        p_usuario: String(usuario || "").trim().toLowerCase(),
        p_clave: String(clave || ""),
        p_tenant: tenant
    })

    if (error) {
        // Compatibilidad: si la RPC aún no existe, seguimos con el flujo actual.
        if (/42883|does not exist|resolver_login_admin/i.test(String(error.message || ""))) {
            return null
        }
        console.warn("No se pudo autenticar por RPC:", error.message)
        return null
    }

    const row = Array.isArray(data) ? data[0] : data
    if (!row) return { valido: false, motivo: "credenciales_invalidas", viaRpc: true }

    const rolNormalizado = normalizarRolUsuario(row.rol || "")
    const perfilId = String(row.perfil_id || "administrador")
    return {
        valido: true,
        usuario: String(row.usuario || "").trim().toLowerCase(),
        rol: rolNormalizado,
        tenantId: String(row.tenant_id || "").trim().toLowerCase(),
        perfilId,
        esLegacy: false,
        viaAuth: true,
        viaRpc: true
    }
}

async function resolverCredencialesAdmin(usuario, clave, contexto = {}) {
    const tenantContexto = String(contexto?.tenantId || "").trim().toLowerCase()
    const requiereJwt = String(contexto?.origen || "") === "tenant_route"

    // 🔥 IMPORTANTE:
    // En ruta institucional NO aceptamos autenticación solo por RPC,
    // porque RLS necesita un JWT real en el navegador.
    // La RPC queda permitida solo para staff_root.
    let resultadoRpc = null
    if (!requiereJwt) {
        resultadoRpc = await resolverCredencialesAdminViaRPC(usuario, clave, tenantContexto)
        if (resultadoRpc) {
            return resultadoRpc
        }
    }

    const userLocal = (usuariosAdmin || []).find(u => u.usuario === usuario)
    const userLuiz = (usuariosAdminLuiz || []).find(u => u.usuario === usuario)
    const authResultado = await autenticarAdminConSupabaseAuth(usuario, clave)

    if (requiereJwt && !authResultado.ok) {
        return { valido: false, motivo: "clave_incorrecta" }
    }

    if (userLocal?.authUserId && !authResultado.ok) {
        return { valido: false, motivo: "clave_incorrecta" }
    }

    if (userLocal && (authResultado.ok || (!requiereJwt && !userLocal?.authUserId && String(userLocal.clave || "") === clave))) {
        const perfilLocal = String(perfilesUsuariosLocales?.[String(userLocal.usuario || "").toLowerCase()] || "administrador")
        const perfilDataLocal = obtenerPerfilPorId(perfilLocal)
        const rolLocal = normalizarRolUsuario(userLocal.rol)
        if (rolLocal === ROLES_ADMIN.ADMINISTRADOR && (!perfilDataLocal || String(perfilDataLocal.estado || "activo") !== "activo")) {
            return { valido: false, motivo: "perfil_inactivo" }
        }
        return {
            valido: true,
            usuario: userLocal.usuario,
            rol: rolLocal,
            tenantId: String(userLocal.tenantId || "").trim().toLowerCase(),
            perfilId: perfilLocal,
            esLegacy: false,
            viaAuth: !!authResultado.ok
        }
    }

    if (requiereJwt && authResultado.ok && !userLocal && authResultado.authUserId) {
        let dataDb = null
        let errorDb = null
            ; ({ data: dataDb, error: errorDb } = await supabaseClient
                .from("usuarios_admin")
                .select("usuario,rol,tenant_id,activo")
                .eq("auth_user_id", authResultado.authUserId)
                .eq("activo", true)
                .limit(1))

        if (errorDb && /tenant_id/i.test(String(errorDb.message || ""))) {
            const fallback = await supabaseClient
                .from("usuarios_admin")
                .select("usuario,rol,activo")
                .eq("auth_user_id", authResultado.authUserId)
                .eq("activo", true)
                .limit(1)
            dataDb = (fallback.data || []).map(x => Object.assign({}, x, { tenant_id: tenantContexto || "" }))
            errorDb = fallback.error
        }

        const row = Array.isArray(dataDb) ? dataDb[0] : null
        if (!errorDb && row) {
            const usuarioDb = String(row.usuario || usuario).trim().toLowerCase()
            const perfilLocal = String(perfilesUsuariosLocales?.[usuarioDb] || "administrador")
            return {
                valido: true,
                usuario: usuarioDb,
                rol: normalizarRolUsuario(row.rol || ROLES_ADMIN.ADMINISTRADOR),
                tenantId: String(row.tenant_id || tenantContexto || "").trim().toLowerCase(),
                perfilId: perfilLocal,
                esLegacy: false,
                viaAuth: true
            }
        }
    }

    if (!requiereJwt && userLuiz && String(userLuiz.password || userLuiz.clave || "") === clave) {
        if (String(userLuiz.estado || "activo") !== "activo") {
            return { valido: false, motivo: "usuario_inactivo" }
        }
        const perfilUser = String(userLuiz.perfilId || "administrador")
        const perfilData = obtenerPerfilPorId(perfilUser)
        if (normalizarRolUsuario(userLuiz.rol || ROLES_ADMIN.ADMINISTRADOR) === ROLES_ADMIN.ADMINISTRADOR) {
            if (!perfilData || String(perfilData.estado || "activo") !== "activo") {
                return { valido: false, motivo: "perfil_inactivo" }
            }
        }
        return {
            valido: true,
            usuario: userLuiz.usuario,
            rol: normalizarRolUsuario(userLuiz.rol || ROLES_ADMIN.ADMINISTRADOR),
            tenantId: userLuiz.tenantId || "",
            perfilId: perfilUser,
            esLegacy: false
        }
    }

    return { valido: false }
}

async function loginAccesoAdminInstitucional() {
    if (!esRutaInstitucionalValidaActiva()) {
        setMensajeAccesoAdminInstitucional("Institución inactiva o no válida.")
        return
    }

    const usuario = String(tenantAdminUser?.value || "").trim().toLowerCase()
    const clave = String(tenantAdminPass?.value || "").trim()
    await asegurarUsuariosAdminPrevioLogin(usuario)
    if (!usuario || !clave) {
        setMensajeAccesoAdminInstitucional("Completa usuario y clave.")
        return
    }

    const tenant = obtenerTenantActivo()
    const resultado = await resolverCredencialesAdmin(usuario, clave, { tenantId: tenant.id, origen: "tenant_route" })

    if (!resultado.valido) {
        if (resultado.motivo === "usuario_inactivo") {
            setMensajeAccesoAdminInstitucional("Usuario inactivo.")
        } else if (resultado.motivo === "perfil_inactivo") {
            setMensajeAccesoAdminInstitucional("Perfil inactivo. Contacta a Luiz Labs.")
        } else {
            setMensajeAccesoAdminInstitucional("Credenciales inválidas.")
        }
        return
    }

    if (resultado.rol === ROLES_ADMIN.ADMINISTRADOR) {
        const tenantAsignado = resultado.tenantId || obtenerTenantAsignadoUsuario(resultado.usuario)
        if (!tenantAsignado || tenantAsignado !== tenant.id) {
            setMensajeAccesoAdminInstitucional("Usuario no autorizado para esta institución.")
            return
        }
    }

    if (resultado.tenantId && resultado.tenantId !== tenant.id && resultado.rol !== ROLES_ADMIN.SUPERUSUARIO) {
        setMensajeAccesoAdminInstitucional("Usuario no pertenece a esta institución.")
        return
    }

    setSesionAdminActiva({
        autenticado: true,
        usuario: resultado.usuario,
        rol: resultado.rol,
        tenantId: tenant.id,
        origen: "tenant_route",
        perfilId: resultado.perfilId || ""
    })
    registrarActividad("login_admin_institucional", {
        via: "acceso_administrativo_ruta",
        usuario: resultado.usuario,
        rol: resultado.rol
    }, { tenantId: tenant.id, usuario: resultado.usuario, rol: resultado.rol })

    cerrarAccesoAdminInstitucional()
    mostrarVista("reportes")
    cargarDatos()
    aplicarLayout()

    await bootstrapAuthorizedApp();
}

async function login() {
    const usuario = (loginUser.value || "").trim().toLowerCase()
    const clave = (loginPass.value || "").trim()
    await asegurarUsuariosAdminPrevioLogin(usuario)
    const resultado = await resolverCredencialesAdmin(usuario, clave, {
        tenantId: esModoStaff ? "" : String(tenantActivoId || "").trim().toLowerCase(),
        origen: esModoStaff ? "staff_root" : "tenant_route"
    })

    if (!esModoStaff) {
        const tenant = obtenerTenantActivo()
        if (!tenant) {
            loginMsg.innerText = "Institución no válida para esta ruta."
            return
        }
        if (!tenant.habilitado) {
            loginMsg.innerText = "Institución inactiva. Contacta a Luiz Labs."
            return
        }
        if (resultado.valido && resultado.tenantId && resultado.tenantId !== tenant.id) {
            loginMsg.innerText = "Ese usuario no pertenece a esta institución."
            return
        }
        if (resultado.valido && resultado.rol === ROLES_ADMIN.ADMINISTRADOR) {
            const tenantAsignado = resultado.tenantId || obtenerTenantAsignadoUsuario(resultado.usuario)
            if (!tenantAsignado || tenantAsignado !== tenant.id) {
                loginMsg.innerText = "Usuario no autorizado para esta institución."
                return
            }
        }
    }

    if (!esModoStaff && resultado.valido) {
        const { data: sessionData, error: sessionError } = await supabaseClient.auth.getSession()
        if (sessionError || !sessionData?.session?.access_token || !sessionData?.session?.user) {
            loginMsg.innerText = "Login inválido: no se generó sesión JWT."
            return
        }
    }

    if (resultado.valido) {
        if (esModoStaff) {
            if (resultado.rol !== ROLES_ADMIN.SUPERUSUARIO) {
                loginMsg.innerText = "Solo superusuario puede ingresar desde esta ruta."
                return
            }
            // En raíz se guarda sesión administrativa y luego se selecciona institución.
            setSesionAdminActiva({
                autenticado: true,
                usuario: resultado.usuario,
                rol: resultado.rol,
                tenantId: "",
                origen: "staff_root",
                perfilId: resultado.perfilId || ""
            })
            registrarActividad("login_admin", {
                via: "root",
                usuario: resultado.usuario,
                rol: resultado.rol
            }, { usuario: resultado.usuario, rol: resultado.rol, tenantId: "" })
            mostrarSelectorStaff = false
            loginMsg.innerText = ""
            aplicarLayout()
            renderTenantSelector()
            await bootstrapAuthorizedApp();
            return
        }

        setSesionAdminActiva({
            autenticado: true,
            usuario: resultado.usuario,
            rol: resultado.rol,
            tenantId: tenantActivoId,
            origen: "tenant_route",
            perfilId: resultado.perfilId || ""
        })
        registrarActividad("login_admin", {
            via: "tenant_login",
            usuario: resultado.usuario,
            rol: resultado.rol
        }, { usuario: resultado.usuario, rol: resultado.rol, tenantId: tenantActivoId })
        loginScreen.style.display = "none"
        vistaDesktop.style.display = "block"
        mostrarVista("reportes")
        cargarDatos()
        await bootstrapAuthorizedApp();
    } else {
        loginMsg.innerText = resultado.motivo === "perfil_inactivo"
            ? "Perfil inactivo. Contacta a Luiz Labs."
            : "Usuario o clave incorrecta"
    }
}

function verCriterio(tipo) {
    let titulo = "Criterio"
    let contenido = ""

    if (tipo === "semaforo") {
        titulo = "Criterio Semáforo"
        contenido = `
      <p><strong>Verde:</strong> primera marcación del último día hasta +10 minutos sobre la hora de inicio de su sección.</p>
      <p><strong>Amarillo:</strong> primera marcación entre +11 y +30 minutos sobre la hora de inicio.</p>
      <p><strong>Rojo:</strong> más de +30 minutos, fuera de día configurado o sin sección/hora válida para evaluar.</p>
      <p style="margin-top:10px;color:#5f6f8f;">El cálculo es dinámico por sección (<code>hora_inicio</code> y días). No usa horas fijas globales.</p>
    `
    }

    if (tipo === "riesgo") {
        titulo = "Criterio Riesgo UBO"
        contenido = `
      <p>Se cuenta cuántos aspirantes quedaron en <strong>Rojo</strong> y se agrupan por UBO.</p>
      <p>El listado muestra las UBOs con más casos para priorizar seguimiento.</p>
      <p style="margin-top:10px;color:#5f6f8f;">Usa el mismo criterio de semáforo y respeta el filtro de fechas.</p>
    `
    }

    modalTitulo.innerText = titulo
    modalContenido.innerHTML = contenido
    modal.style.display = "flex"
}

function logout() {
    if (haySupabase()) {
        void supabaseClient.auth.signOut()
    }
    const sesionPrev = obtenerSesionAdminActiva()
    const origenSesion = sesionPrev.origen || ""
    if (sesionPrev?.autenticado) {
        registrarActividad("logout_admin", {
            origen: origenSesion
        }, {
            usuario: sesionPrev.usuario,
            rol: sesionPrev.rol,
            tenantId: sesionPrev.tenantId || tenantActivoId || ""
        })
    }
    cerrarTutorial()
    limpiarSesionAdminActiva()

    mostrarSelectorStaff = false
    dniMovil = ""
    seccion = ""
    if (loginMsg) loginMsg.innerText = ""
    if (loginUser) loginUser.value = ""
    if (loginPass) loginPass.value = ""
    if (mobileDni) mobileDni.value = ""
    if (mobileDniInicio) mobileDniInicio.value = ""
    sessionStorage.removeItem(VISTA_MODO_KEY)
    localStorage.removeItem(VISTA_MODO_KEY)

    if (accesoDirectoInstitucion && origenSesion === "staff_root") {
        window.location.href = "/"
        return
    }

    if (esModoStaff) {
        aplicarLayout()
        return
    }
    location.reload()
}

/* QR */
let stream, seccion = ""

function renderSeccionesMovil() {
    const container = document.getElementById("mobileSectionsContainer")
    if (!container) return

    // Cada ingreso al formulario debe exigir selección explícita.
    seccion = ""
    seleccionarBotonSeccion("")

    // Limpiamos previo
    container.innerHTML = ""

    if (!cursoSecciones || cursoSecciones.length === 0) {
        container.innerHTML = `<p style="color:#666;font-size:14px;padding:10px;">No hay secciones configuradas para este curso.</p>`
        return
    }

    const nombre = cursoConfigCache?.nombre_curso || "Curso"
    let html = `<p style="font-size:14px;color:#555;margin-bottom:4px;font-weight:700;text-transform:uppercase;">${nombre}</p>`
    html += "<p style=\"font-size:13px;color:#777;margin-bottom:12px;\">Selecciona tu sección para registrar asistencia</p>"
    cursoSecciones.forEach(sec => {
        const d = Array.isArray(sec.dias) ? sec.dias.join(", ") : ""
        const label = `Sección ${sec.seccion} (${d} ${sec.modalidad})`
        html += `<button class="mobile-section-btn" data-seccion="${sec.seccion}" onclick="setSeccion('${sec.seccion}')">${label}</button>`
    })

    container.innerHTML = html
}

function ingresarMovilInicio() {
    const input = document.getElementById("mobileDniInicio")
    const dniLimpio = (input?.value || "").replace(/\D/g, "").slice(0, 8)
    if (input) input.value = dniLimpio

    if (!dniLimpio) {
        alert("Ingresa tu DNI para continuar")
        return
    }

    dniMovil = dniLimpio
    if (mobileDni) mobileDni.value = dniLimpio

    vistaMovilInicio.style.display = "none"
    vistaMovil.style.display = "block"
    mostrarPasoMovil("scan")
}

function ingresarMovil() {
    const dniLimpio = (mobileDni.value || "").replace(/\D/g, "").slice(0, 8)
    mobileDni.value = dniLimpio

    if (!dniLimpio) {
        alert("Ingresa tu DNI para continuar")
        return
    }

    dniMovil = dniLimpio
    mostrarPasoMovil("scan")
}

function iniciarEscaneo() {
    if (!dniMovil) {
        alert("Primero ingresa tu DNI")
        mostrarPasoMovil("ingreso")
        return
    }

    abrirScanner()

    navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" }
    })
        .then(s => {
            stream = s
            video.srcObject = s
            video.play()
            scanQR()
        })
        .catch(err => {
            cerrarScanner()
            alert("Error cámara: " + err)
            console.error(err)
        })
}

function scanQR() {
    if (!scanningActivo) return

    const ctx = canvas.getContext("2d")

    if (video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.width = video.videoWidth
        canvas.height = video.videoHeight
        ctx.drawImage(video, 0, 0)

        const img = ctx.getImageData(0, 0, canvas.width, canvas.height)
        const code = jsQR(img.data, img.width, img.height)

        if (code) {
            cerrarScanner()

            renderSeccionesMovil()
            vistaMovil.style.display = "none"
            formulario.style.display = "block"
            aplicarVisibilidadAccesoAdminInstitucional()

            console.log("QR detectado:", code.data) // 🔥 debug

            return
        }
    }
    requestAnimationFrame(scanQR)
}

function detenerCamara() {
    if (stream) stream.getTracks().forEach(t => t.stop())
}

function volverInicio() {
    cerrarScanner()
    formulario.style.display = "none"
    vistaMovil.style.display = "block"
    mostrarPasoMovil(dniMovil ? "scan" : "ingreso")
    aplicarVisibilidadAccesoAdminInstitucional()
    setMensaje("")
}

function setSeccion(s) {
    seccion = s
    seleccionarBotonSeccion(s)
}

function getDeviceId() {
    let id = localStorage.getItem("dev")
    if (!id) {
        id = "dev-" + Math.random()
        localStorage.setItem("dev", id)
    }
    return id
}

async function guardarAsistencia() {
    const dniRegistro = (dniMovil || mobileDni.value || "").replace(/\D/g, "")
    const nombresValor = (nombres.value || "").trim()
    const apellidosValor = (apellidos.value || "").trim()
    const uboValor = (ubo.value || "").replace(/\D/g, "")
    const deviceId = getDeviceId()
    const nombreCompleto = `${nombresValor} ${apellidosValor}`.replace(/\s+/g, " ").trim()
    const now = new Date()
    const fechaHoy = now.toISOString().slice(0, 10)
    const horaHoy = now.toTimeString().slice(0, 8)

    if (!dniRegistro) {
        setMensaje("⚠ DNI no válido", "error")
        return
    }

    if (!nombresValor || !apellidosValor) {
        setMensaje("⚠ Completa nombres y apellidos", "error")
        return
    }

    if (!uboValor) {
        setMensaje("⚠ UBO debe ser numérico", "error")
        return
    }

    if (!seccion) {
        setMensaje("⚠ Selecciona una sección", "error")
        return
    }

    // Lógica local de dispositivos y duplicados delegada a la RPC rpc_registrar_asistencia

    if (cursoConfigCache?.gps_activo) {
        if (cursoConfigCache.fecha_inicio && fechaHoy < cursoConfigCache.fecha_inicio) {
            setMensaje("⚠ El curso aún no inicia para marcar asistencia", "error")
            return
        }

        if (cursoConfigCache.fecha_fin && fechaHoy > cursoConfigCache.fecha_fin) {
            setMensaje("⚠ El curso ya finalizó para marcar asistencia", "error")
            return
        }

        const radio = Number(cursoConfigCache?.radio_m || 50)

        const sedesAsignadas = cursoSedesUbo.filter(s => String(s.seccion).toUpperCase() === String(seccion).toUpperCase() && s.ubo)

        if (sedesAsignadas.length === 0) {
            setMensaje(`⚠ No hay UBO sede configurada para Sección ${seccion}`, "error")
            return
        }

        let coords
        try {
            coords = await obtenerGeoActual()
        } catch (err) {
            setMensaje("⚠ No se pudo obtener GPS del dispositivo", "error")
            return
        }

        let enRango = false
        let detalleErrorUbos = []
        let menorDistancia = Infinity
        let uboMasCercano = null

        for (const asignada of sedesAsignadas) {
            const uboSedeReq = asignada.ubo
            const sedeCache = ubosSedeCache.find(x => String(x.ubo) === String(uboSedeReq))

            if (!sedeCache || sedeCache.lat == null || sedeCache.lng == null) {
                detalleErrorUbos.push(`La UBO sede ${uboSedeReq} no tiene coordenadas`)
                continue
            }

            const dist = distanciaMetros(
                Number(coords.latitude), Number(coords.longitude),
                Number(sedeCache.lat), Number(sedeCache.lng)
            )

            if (dist <= radio) {
                enRango = true
                break
            }

            if (dist < menorDistancia) {
                menorDistancia = dist
                uboMasCercano = uboSedeReq
            }
        }

        if (!enRango) {
            if (uboMasCercano === null) {
                setMensaje(`⚠ ${detalleErrorUbos[0] || "No hay UBO válida con coordenadas"}`, "error")
                return
            }

            await registrarAlerta({
                fecha: fechaHoy,
                hora: horaHoy,
                dni: dniRegistro,
                nombre: nombreCompleto,
                ubo: uboValor,
                seccion,
                tipo: "fuera_rango_gps",
                detalle: `Fuera de rango (${Math.round(menorDistancia)}m de UBO ${uboMasCercano}, radio ${radio}m)`,
                device_id: deviceId,
                lat: Number(coords.latitude),
                lng: Number(coords.longitude),
                ubo_sede: String(uboMasCercano),
                distancia_m: Math.round(menorDistancia),
                radio_m: radio
            })

            alert("⚠ Usted se encuentra fuera del rango de la(s) UBO(s) sede(s). No se permite marcar asistencia.")
            setMensaje("⚠ Fuera de rango GPS. Registro bloqueado.", "error")
            return
        }
    }

    let lat = 0, lng = 0;
    try {
        if (typeof coords !== 'undefined' && coords) {
            lat = Number(coords.latitude);
            lng = Number(coords.longitude);
        }
    } catch (e) { }

    const { data, error } = await supabaseClient.rpc('rpc_registrar_asistencia', {
        p_dni: dniRegistro,
        p_tenant_id: tenantActivoId,
        p_seccion: seccion,
        p_latitud: lat,
        p_longitud: lng,
        p_device_id: deviceId,
        p_timestamp_local: new Date().toISOString()
    });

    if (error) {
        console.error("Error RPC asistencia:", error);
        setMensaje("⚠ Error de comunicación con el servidor", "error");
        return;
    }

    if (!data.success) {
        setMensaje(`⚠ ${data.message}`, "error");
        return;
    }

    if (data.warning) {
        const warnMsgs = Array.isArray(data.warnings) ? data.warnings.join(" | ") : "Atención requerida";
        alert(`⚠ Atención: ${warnMsgs}`);
        setMensaje(`✅ Registrado con alerta: ${warnMsgs}`, "warning");
    } else {
        setMensaje("✅ Registrado", "ok");
    }

    nombres.value = ""
    apellidos.value = ""
    ubo.value = ""
    seccion = ""
    seleccionarBotonSeccion("")
}

/* ADMIN */
async function cargarDatos() {
    let q = withTenantScope(supabaseClient.from("asistencias").select("*"))

    if (fechaDesde.value) {
        q = q.gte("fecha", fechaDesde.value)
    }
    if (fechaHasta.value) {
        q = q.lte("fecha", fechaHasta.value)
    }
    if (filtroUbo.value) {
        q = q.ilike("ubo", "%" + filtroUbo.value + "%")
    }

    const { data } = await q
    const scopedData = filtrarDataTenantActivo(data)
    renderTabla((scopedData || []).filter(d => d.estado !== "retirado"))
    await cargarAlertasReporte()
}

function renderTabla(data) {
    const activos = (data || []).filter(r => r.estado !== "retirado")
    const hayFiltroUbo = !!String(filtroUbo?.value || "").trim()
    const clavesAlerta = obtenerClavesAlertaDispositivo(activos)
    cacheReportes = []

    if (!activos.length) {
        const msg = hayFiltroUbo
            ? "No hay registros para la UBO seleccionada en el rango indicado."
            : "No hay datos para el rango seleccionado."
        tabla.innerHTML = `
      <div class="hint" style="padding:8px 2px;">
        ${msg}
      </div>
    `
        return
    }

    let html = `
  <table>
    <thead>
      <tr>
        <th>DNI</th>
        <th>Nombre</th>
        <th>UBO</th>
        <th>Fecha</th>
        <th>Hora</th>
        <th>Alerta</th>
      </tr>
    </thead>
    <tbody>
  `

    activos.forEach(r => {
        const clave = `${r.device_id || ""}|${(r.dni || "").trim()}|${r.fecha || ""}|${r.hora || ""}`
        const hayAlerta = clavesAlerta.has(clave)
        cacheReportes.push({
            dni: r.dni || "",
            nombre: r.nombre || "",
            ubo: r.ubo || "",
            fecha: r.fecha || "",
            hora: r.hora || "",
            alerta: hayAlerta ? "DNI distinto en dispositivo" : "Sin alerta"
        })

        html += `
      <tr>
        <td>${r.dni}</td>
        <td>${r.nombre}</td>
        <td>${r.ubo}</td>
        <td>${r.fecha}</td>
        <td>${r.hora}</td>
        <td>
          <span class="badge-alerta ${hayAlerta ? "warn" : "ok"}">
            ${hayAlerta ? "DNI distinto en dispositivo" : "Sin alerta"}
          </span>
        </td>
      </tr>
    `
    })

    html += `
    </tbody>
  </table>

  <div style="margin-top:10px;font-weight:bold;">
    Total registros: ${activos.length}
  </div>
  `

    tabla.innerHTML = html
}

async function cargarAlertasReporte() {
    let q = withTenantScope(supabaseClient
        .from("asistencia_alertas")
        .select("*")
        .order("fecha", { ascending: false })
        .order("hora", { ascending: false })
        .limit(120))

    if (filtroUbo.value) {
        q = q.eq("ubo", filtroUbo.value)
    }

    if (fechaDesde.value) {
        q = q.gte("fecha", fechaDesde.value)
    }

    if (fechaHasta.value) {
        q = q.lte("fecha", fechaHasta.value)
    }

    const { data, error } = await q

    if (error) {
        console.warn("No se pudo cargar asistencia_alertas:", error.message)
        tablaAlertasContenido.innerHTML = "No se pudieron cargar alertas."
        return
    }

    const scopedData = filtrarDataTenantActivo(data)

    if (!scopedData || scopedData.length === 0) {
        tablaAlertasContenido.innerHTML = "No hay alertas registradas en este período."
        return
    }

    let html = `
  <table>
    <thead>
      <tr>
        <th>Fecha</th>
        <th>Hora</th>
        <th>DNI</th>
        <th>Nombre</th>
        <th>UBO</th>
        <th>Sección</th>
        <th>Tipo</th>
        <th>Detalle</th>
      </tr>
    </thead>
    <tbody>
  `

    scopedData.forEach(r => {
        html += `
      <tr>
        <td>${r.fecha || ""}</td>
        <td>${r.hora || ""}</td>
        <td>${r.dni || ""}</td>
        <td>${r.nombre || ""}</td>
        <td>${r.ubo || ""}</td>
        <td>${r.seccion || ""}</td>
        <td>${r.tipo || ""}</td>
        <td>${r.detalle || ""}</td>
      </tr>
    `
    })

    html += "</tbody></table>"
    tablaAlertasContenido.innerHTML = html
}

async function aplicarFiltros() {

    let q = withTenantScope(supabaseClient.from("asistencias").select("*"))

    if (filtroUbo.value) {
        q = q.ilike("ubo", "%" + filtroUbo.value + "%")
    }

    if (fechaDesde.value) {
        q = q.gte("fecha", fechaDesde.value)
    }

    if (fechaHasta.value) {
        q = q.lte("fecha", fechaHasta.value)
    }

    const { data, error } = await q

    if (error) {
        console.error(error)
        alert("Error al filtrar")
        return
    }

    const scopedData = filtrarDataTenantActivo(data)
    renderTabla(scopedData.filter(d => d.estado !== "retirado"))
    await cargarAlertasReporte()

}

function limpiarFiltros() {
    const { from, to } = obtenerRangoMesActual()
    filtroUbo.value = ""
    fechaDesde.value = from
    fechaHasta.value = to

    tabla.innerHTML = ""
    tablaAlertasContenido.innerHTML = "Sin alertas registradas."

}

async function cargarDashboard() {

    let q = withTenantScope(supabaseClient.from("asistencias").select("*"))

    if (dashDesde.value) {
        q = q.gte("fecha", dashDesde.value)
    }

    if (dashHasta.value) {
        q = q.lte("fecha", dashHasta.value)
    }

    if (dashUbo.value) {
        q = q.eq("ubo", dashUbo.value)
    }
    if (dashSeccion.value) {
        q = q.eq("seccion", dashSeccion.value)
    }

    const { data } = await q
    const scopedData = filtrarDataTenantActivo(data)
    const dataActivos = (scopedData || []).filter(r => r.estado !== "retirado")
    cacheDashboard = dataActivos

    let padronTotal = 0
    try {
        let padronQ = withTenantScope(supabaseClient
            .from("aspirantes")
            .select("dni", { count: "exact", head: true }))
        if (dashUbo.value) {
            padronQ = padronQ.eq("ubo", dashUbo.value)
        }
        const { count } = await padronQ
        padronTotal = Number(count || 0)
    } catch (e) {
        console.warn("No se pudo calcular padrón total:", e)
    }

    let alertasQ = withTenantScope(supabaseClient
        .from("asistencia_alertas")
        .select("id", { count: "exact", head: true })
        .eq("tipo", "dni_en_otro_dispositivo"))

    if (dashDesde.value) {
        alertasQ = alertasQ.gte("fecha", dashDesde.value)
    }
    if (dashHasta.value) {
        alertasQ = alertasQ.lte("fecha", dashHasta.value)
    }
    if (dashUbo.value) {
        alertasQ = alertasQ.eq("ubo", dashUbo.value)
    }
    if (dashSeccion.value) {
        alertasQ = alertasQ.eq("seccion", dashSeccion.value)
    }

    const { count: alertasDispNoHabitual } = await alertasQ

    let alertasDetalleQ = withTenantScope(supabaseClient
        .from("asistencia_alertas")
        .select("fecha,hora,dni,nombre,ubo,seccion,detalle,device_id")
        .eq("tipo", "dni_en_otro_dispositivo")
        .order("fecha", { ascending: false })
        .order("hora", { ascending: false })
        .limit(120))

    if (dashDesde.value) {
        alertasDetalleQ = alertasDetalleQ.gte("fecha", dashDesde.value)
    }
    if (dashHasta.value) {
        alertasDetalleQ = alertasDetalleQ.lte("fecha", dashHasta.value)
    }
    if (dashUbo.value) {
        alertasDetalleQ = alertasDetalleQ.eq("ubo", dashUbo.value)
    }
    if (dashSeccion.value) {
        alertasDetalleQ = alertasDetalleQ.eq("seccion", dashSeccion.value)
    }

    const { data: alertasDetalle } = await alertasDetalleQ
    window.detalleAlertasDispositivo = filtrarDataTenantActivo(alertasDetalle)

    let alumnos = {}

    dataActivos.forEach(r => {
        if (!alumnos[r.dni]) {
            alumnos[r.dni] = { nombre: r.nombre, ubo: r.ubo, total: 0 }
        }
        alumnos[r.dni].total++
    })

    let total = Object.keys(alumnos).length

    let verde = 0, amarillo = 0, rojo = 0
    let rojoTardanza = 0
    let rojoFueraDia = 0

    // 🔥 GUARDAMOS DETALLE GLOBAL
    window.detalleSemaforo = {
        verde: [],
        amarillo: [],
        rojo: []
    }

    let uboMap = {}

    for (let dni in alumnos) {

        let a = alumnos[dni]
        let estado = "rojo"

        const registros = dataActivos.filter(x => x.dni == dni)
        const evaluacion = evaluarSemaforoPorRegla(registros)
        estado = evaluacion.estado

        if (estado === "verde") verde++
        if (estado === "amarillo") amarillo++
        if (estado === "rojo") rojo++

        window.detalleSemaforo[estado].push({
            dni,
            nombre: a.nombre,
            ubo: a.ubo,
            total: a.total,
            criterioCodigo: evaluacion.motivo || "",
            criterio: describirMotivoSemaforo(evaluacion.motivo),
            fecha: evaluacion.fecha || "-",
            horaMarcada: evaluacion.horaMarcada || "-",
            seccion: evaluacion.seccion || "-",
            horaInicio: evaluacion.horaInicio || "-"
        })

        if (estado === "rojo") {
            if (evaluacion.motivo === "tardanza_alta") rojoTardanza++
            if (evaluacion.motivo === "fuera_de_dia_configurado") rojoFueraDia++

            if (!uboMap[a.ubo]) {
                uboMap[a.ubo] = { total: 0, tardanza: 0, fueraDia: 0, otros: 0 }
            }
            uboMap[a.ubo].total++
            if (evaluacion.motivo === "tardanza_alta") {
                uboMap[a.ubo].tardanza++
            } else if (evaluacion.motivo === "fuera_de_dia_configurado") {
                uboMap[a.ubo].fueraDia++
            } else {
                uboMap[a.ubo].otros++
            }
        }
    }

    kpiTotal.innerText = total
    kpiAsistencia.innerText = total
        ? Math.round((verde / total) * 100) + "%"
        : "0%"
    const inasistencias = Math.max(0, padronTotal - total)
    kpiInasistencia.innerText = inasistencias
    kpiCobertura.innerText = padronTotal ? Math.round((total / padronTotal) * 100) + "%" : "0%"

    verdeCount.innerText = verde
    amarilloCount.innerText = amarillo
    rojoCount.innerText = rojo
    kpiRojoTardanza.innerText = rojoTardanza
    kpiRojoFueraDia.innerText = rojoFueraDia
    kpiDispNoHabitual.innerText = alertasDispNoHabitual || 0
    kpiDispCard.style.opacity = (alertasDispNoHabitual || 0) > 0 ? "1" : "0.75"

    cacheRiesgoUbo = Object.entries(uboMap)
        .sort((a, b) => b[1].total - a[1].total)

    let html = ""
    cacheRiesgoUbo
        .slice(0, 5)
        .forEach(([ubo, val]) => {
            html += `<p onclick="verUbo('${ubo}')" style="cursor:pointer;">
      ⚠ ${ubo} - ${val.total} casos (tardanza: ${val.tardanza}, fuera día: ${val.fueraDia})
      </p>`
        })

    if (!html) {
        html = `<p class="hint">No hay datos para el rango seleccionado.</p>`
    }

    topUbo.innerHTML = html
    semaforoInfo.innerText = "Semáforo: usa la primera marcación del último día y la compara con la hora_inicio de su sección (Verde: hasta +10m, Amarillo: +11 a +30m, Rojo: >+30m, fuera de día o sin configuración válida)."
    riesgoInfo.innerText = "Riesgo por UBO: cantidad de aspirantes en Rojo según la configuración de horario/días y el rango filtrado."
}

function verAlertasDispositivo() {
    const data = window.detalleAlertasDispositivo || []

    if (!data.length) {
        modalTitulo.innerText = "Alertas de Dispositivo"
        modalContenido.innerHTML = "<p>No hay alertas en el rango seleccionado.</p>"
        modal.style.display = "flex"
        return
    }

    let html = `
  <table>
    <tr>
      <th>Fecha</th>
      <th>Hora</th>
      <th>DNI</th>
      <th>Nombre</th>
      <th>UBO</th>
      <th>Sección</th>
      <th>Detalle</th>
    </tr>
  `

    data.forEach(r => {
        html += `
      <tr>
        <td>${r.fecha || ""}</td>
        <td>${r.hora || ""}</td>
        <td>${r.dni || ""}</td>
        <td>${r.nombre || ""}</td>
        <td>${r.ubo || ""}</td>
        <td>${r.seccion || ""}</td>
        <td>${r.detalle || ""}</td>
      </tr>
    `
    })
    html += "</table>"

    modalTitulo.innerText = "Alertas: Dispositivo No Habitual"
    modalContenido.innerHTML = html
    modal.style.display = "flex"
}

function verUbo(ubo) {

    let data = window.detalleSemaforo["rojo"]
        .filter(x => x.ubo == ubo)

    let html = `
  <table>
    <tr>
      <th>DNI</th>
      <th>Nombre</th>
      <th>UBO</th>
      <th>Sección</th>
      <th>Hora sección</th>
      <th>Fecha</th>
      <th>Hora marcada</th>
      <th>Asistencias</th>
      <th>Criterio</th>
    </tr>
  `

    data.forEach(r => {
        html += `
      <tr>
        <td>${r.dni}</td>
        <td>${r.nombre}</td>
        <td>${r.ubo}</td>
        <td>${r.seccion || "-"}</td>
        <td>${r.horaInicio || "-"}</td>
        <td>${r.fecha || "-"}</td>
        <td>${r.horaMarcada || "-"}</td>
        <td>${r.total}</td>
        <td>${r.criterio || "-"}</td>
      </tr>
    `
    })

    html += "</table>"

    modalTitulo.innerText = "UBO " + ubo
    modalContenido.innerHTML = html

    modal.style.display = "flex"
}

async function buscarAspirantes() {

    const ubo = filtroUboConfig.value
    const texto = String(filtroTextoRetiro?.value || "").trim().toLowerCase()

    const { data } = await withTenantScope(supabaseClient
        .from("asistencias")
        .select("dni,nombre,ubo,tenant_id")
        .ilike("ubo", "%" + ubo + "%"))
    const scopedData = filtrarDataTenantActivo(data)
    const dedupe = new Map()

        ; (scopedData || []).forEach(a => {
            const dni = String(a?.dni || "").trim()
            const nombre = String(a?.nombre || "").trim()
            const matchTexto = !texto ||
                dni.toLowerCase().includes(texto) ||
                nombre.toLowerCase().includes(texto)
            if (!matchTexto) return
            if (!dni || dedupe.has(dni)) return
            dedupe.set(dni, {
                dni,
                nombre: nombre || "Sin nombre",
                ubo: String(a?.ubo || "").trim()
            })
        })

    const lista = Array.from(dedupe.values()).sort((a, b) =>
        `${a.nombre} ${a.dni}`.localeCompare(`${b.nombre} ${b.dni}`)
    )

    let html = ""

    lista.forEach(a => {
        html += `
      <p onclick="seleccionarAspirante('${a.dni}','${a.nombre}')">
        ${a.nombre} (${a.dni})${a.ubo ? ` - UBO ${a.ubo}` : ""}
      </p>
    `
    })

    listaAspirantes.innerHTML = html || `<p class="hint">No hay aspirantes para el filtro seleccionado.</p>`
}

async function retirarAspirante(dni) {

    const { error } = await withTenantScope(supabaseClient
        .from("asistencias")
        .update({ estado: "retirado" })
        .eq("dni", dni))

    if (error) {
        alert("Error al retirar")
        console.error(error)
    } else {
        alert("Aspirante retirado correctamente")
        buscarAspirantes() // 🔥 refresca lista
        registrarActividad("aspirante_retirado", {
            dni: String(dni || "").trim()
        }, { tenantId: tenantActivoId })
    }

}

function mostrarVista(vista) {
    vista = aplicarPermisosVistasPorPerfil(vista)
    if (esModoAdminMovilLimitado() && !esVistaPermitidaEnAdminMovil(vista)) {
        vista = "dashboard"
    }

    vistaReportes.style.display = "none"
    document.getElementById("vistaDashboard").style.display = "none"
    document.getElementById("vistaConfig").style.display = "none"
    document.getElementById("vistaUsuarios").style.display = "none"
    document.getElementById("vistaActividad").style.display = "none"
    document.querySelectorAll(".nav-item")
        .forEach(el => el.classList.remove("active"))
    marcarNavActiva(vista)

    if (vista === "dashboard") {
        document.getElementById("vistaDashboard").style.display = "block"
        cargarDashboard()
    }

    if (vista === "reportes") {
        vistaReportes.style.display = "block"
        if (!tabla.innerHTML.trim()) cargarDatos()
    }

    if (vista === "config") {
        document.getElementById("vistaConfig").style.display = "block"
        cargarUbos()
        cargarConfigCurso()
        cargarAspirantesCargados()
    }

    if (vista === "usuarios") {
        document.getElementById("vistaUsuarios").style.display = "block"
        renderUsuariosAdmin()
    }

    if (vista === "actividad") {
        document.getElementById("vistaActividad").style.display = "block"
        cargarActividadTenant()
    }

    vistaAdminActual = vista
    aplicarRestriccionesPanelPorContexto()

}

function seleccionarAspirante(dni, nombre) {

    const confirmar = confirm("Retirar a " + nombre + " ?")

    if (confirmar) {
        retirarAspirante(dni)
    }

}

function verDetalle(color) {

    let data = window.detalleSemaforo[color] || []

    let html = `
  <table>
    <tr>
      <th>DNI</th>
      <th>Nombre</th>
      <th>UBO</th>
      <th>Sección</th>
      <th>Hora sección</th>
      <th>Fecha</th>
      <th>Hora marcada</th>
      <th>Asistencias</th>
      <th>Criterio</th>
    </tr>
  `

    data.forEach(x => {
        html += `
      <tr>
        <td>${x.dni}</td>
        <td>${x.nombre}</td>
        <td>${x.ubo}</td>
        <td>${x.seccion || "-"}</td>
        <td>${x.horaInicio || "-"}</td>
        <td>${x.fecha || "-"}</td>
        <td>${x.horaMarcada || "-"}</td>
        <td>${x.total}</td>
        <td>${x.criterio || "-"}</td>
      </tr>
    `
    })

    html += "</table>"

    modalTitulo.innerText = "Semáforo " + color.toUpperCase()
    modalContenido.innerHTML = html

    modal.style.display = "flex"
}

async function cargarUbos() {
    const dashUboPrevio = dashUbo?.value || ""
    const { data } = await withTenantScope(supabaseClient
        .from("asistencias")
        .select("ubo,tenant_id"))
    const ubosAsistencia = obtenerUbosUnicosDesdeAsistencias(filtrarDataTenantActivo(data))

    await cargarSedesUbo()
    const ubosSedes = obtenerUbosUnicosDesdeAsistencias(ubosSedeCache)
    const ubos = Array.from(new Set(ubosAsistencia.concat(ubosSedes)))
        .sort((a, b) => parseInt(a) - parseInt(b))

    let html = construirOptionsUbo(ubos, true, "Seleccionar UBO")

    filtroUboConfig.innerHTML = html
    filtroUbo.innerHTML = html
    filtroRetirados.innerHTML = html
    dashUbo.innerHTML = construirOptionsUbo(ubos, true, "Todas las UBO")
    if (dashUboPrevio && ubos.includes(dashUboPrevio)) {
        dashUbo.value = dashUboPrevio
    }

    const htmlSede = construirOptionsUbo(ubos, true, "Seleccionar UBO sede")
    uboSecUbo.innerHTML = htmlSede
}

function cerrarModal() {
    modal.style.display = "none"
}

// cerrar con ESC
document.addEventListener("keydown", e => {
    if (e.key === "Escape") {
        cerrarModal()
        cerrarCuentaModal()
        cerrarAccesoAdminInstitucional()
        if (tutorialActivo) {
            cerrarTutorial()
        }
    }
})

window.addEventListener("resize", () => {
    if (!tutorialActivo) return
    const step = tutorialSteps[tutorialPasoActual]
    posicionarTooltipTutorial(obtenerTargetTutorial(step))
})

window.addEventListener("scroll", () => {
    if (!tutorialActivo) return
    const step = tutorialSteps[tutorialPasoActual]
    posicionarTooltipTutorial(obtenerTargetTutorial(step))
}, true)

async function guardarCurso() {
    if (!haySupabase()) {
        mostrarMsgCursoModulo("msgCursoFooter", "Sin conexión a Supabase. No se puede guardar la configuración del curso.", "error")
        return
    }
    const mapSedes = {}
    cursoSedesUbo.forEach(x => {
        mapSedes[x.seccion] = x.ubo
    })

    const payload = withTenantPayload({
        id: 1,
        nombre_curso: (cursoNombre.value || "").toUpperCase() || null,
        fecha_inicio: cursoInicio.value || null,
        fecha_fin: cursoFin.value || null,
        radio_m: Number(cursoRadio.value || 50),
        gps_activo: !!toggleGPS.checked
    })

    const { error, data } = await supabaseClient
        .from("curso_configuracion")
        .upsert(payload, { onConflict: "tenant_id" })
        .select()
        .single()

    if (error) {
        if (/nombre_curso/i.test(String(error.message || ""))) {
            const payloadSinNombre = withTenantPayload({
                id: 1,
                fecha_inicio: cursoInicio.value || null,
                fecha_fin: cursoFin.value || null,
                radio_m: Number(cursoRadio.value || 50),
                gps_activo: !!toggleGPS.checked
            })
            const { error: errorSinNombre, data: dataSinNombre } = await supabaseClient
                .from("curso_configuracion")
                .upsert(payloadSinNombre, { onConflict: "tenant_id" })
                .select()
                .single()
            if (errorSinNombre) {
                mostrarMsgCursoModulo("msgCursoFooter", "No se pudo guardar la configuración del curso. Revisa la consola.", "error")
                console.error(errorSinNombre)
                return
            }
            cursoConfigCache = {
                ...(dataSinNombre || {}),
                nombre_curso: (cursoNombre.value || "").toUpperCase()
            }
            mostrarMsgCursoModulo(
                "msgCursoFooter",
                "Configuración guardada. Aviso: en Supabase falta la columna nombre_curso; el nombre se conserva en esta sesión.",
                "warning"
            )
            registrarActividad("configuracion_curso_guardada", {
                nombreCurso: (cursoNombre.value || "").toUpperCase(),
                gpsActivo: !!toggleGPS.checked
            }, { tenantId: tenantActivoId })
            return
        }
        mostrarMsgCursoModulo("msgCursoFooter", "No se pudo guardar la configuración del curso. Revisa la consola o la conexión.", "error")
        console.error(error)
        return
    }

    cursoConfigCache = {
        ...(data || {}),
        nombre_curso: (cursoNombre.value || "").toUpperCase()
    }
    mostrarMsgCursoModulo("msgCursoFooter", "Configuración del curso guardada correctamente.", "ok")
    registrarActividad("configuracion_curso_guardada", {
        nombreCurso: (cursoNombre.value || "").toUpperCase(),
        gpsActivo: !!toggleGPS.checked
    }, { tenantId: tenantActivoId })
}

function actualizarOpcionesSeccionSede() {
    const base = Array.from(new Set((cursoSecciones || []).map(x => String(x.seccion || "").trim()).filter(Boolean)))

    let html = `<option value="">Seleccionar sección</option>`
    if (base.length > 1) {
        html += `<option value="__ALL__">Todas las secciones</option>`
    }
    base.forEach(code => {
        html += `<option value="${code}">Sección ${code}</option>`
    })
    uboSecNombre.innerHTML = html
}

function limpiarFormSeccionCurso() {
    secCursoNombre.value = ""
    secCursoModalidad.value = "Presencial"
    secCursoHora.value = ""
    marcarValoresMultiSelect("secCursoDiasSelect", [])
    editSeccionCursoIndex = -1
    actualizarUIModoEdicionSeccion()
}

function limpiarFormSedeUbo() {
    uboSecNombre.value = ""
    uboSecUbo.value = ""
    uboSecHora.value = ""
    uboSecModalidad.value = "Presencial"
    uboSecTodosDias.checked = false
    marcarValoresMultiSelect("uboSecDiasSelect", [])
    actualizarEstadoDiasSede()
    editSedeUboIndex = -1
    actualizarUIModoEdicionSede()
}

async function guardarSeccionCurso() {
    if (!haySupabase()) {
        mostrarMsgCursoModulo("msgCursoSeccion", "Sin conexión a Supabase. No se puede guardar la sección.", "error")
        return
    }
    const seccionValor = String(secCursoNombre.value || "").trim().toUpperCase()
    const dias = obtenerValoresMultiSelect("secCursoDiasSelect")
    const fueEdicion = editSeccionCursoIndex >= 0

    if (!seccionValor) {
        mostrarMsgCursoModulo("msgCursoSeccion", "Define el nombre o código de la sección.", "error")
        return
    }

    if (!secCursoHora.value) {
        mostrarMsgCursoModulo("msgCursoSeccion", "Indica la hora de inicio de la sección.", "error")
        return
    }

    if (!dias.length) {
        mostrarMsgCursoModulo("msgCursoSeccion", "Selecciona al menos un día para la sección.", "error")
        return
    }

    const accion = fueEdicion ? "seccion_curso_editada" : "seccion_curso_creada"
    const item = {
        seccion: seccionValor,
        modalidad: secCursoModalidad.value,
        hora_inicio: secCursoHora.value,
        dias
    }
    const oldSeccion = editSeccionCursoIndex >= 0 ? cursoSecciones[editSeccionCursoIndex]?.seccion : null

    if (editSeccionCursoIndex < 0) {
        const existing = cursoSecciones.findIndex(x => x.seccion === item.seccion)
        if (existing >= 0) {
            if (!confirm(`La Sección ${item.seccion} ya existe. ¿Deseas reemplazarla?`)) return
        }
    }

    let persistioEnDb = false
    try {
        if (oldSeccion && oldSeccion !== item.seccion) {
            let q = withTenantScope(supabaseClient.from("curso_secciones").delete())
            await q.eq("seccion", oldSeccion)
        }

        let qAct = withTenantScope(supabaseClient.from("curso_secciones").delete())
        const { error: errorDeleteActual } = await qAct
            .eq("seccion", item.seccion)
        if (errorDeleteActual && !esTablaNoExiste(errorDeleteActual)) {
            throw errorDeleteActual
        }

        const payloadSeccion = withTenantPayload({
            curso_id: 1,
            seccion: item.seccion,
            modalidad: item.modalidad,
            hora_inicio: item.hora_inicio,
            dias: item.dias
        })

        let { error } = await supabaseClient
            .from("curso_secciones")
            .insert([payloadSeccion])

        if (error && /dias/i.test(String(error.message || ""))) {
            ({ error } = await supabaseClient
                .from("curso_secciones")
                .insert([withTenantPayload({
                    curso_id: 1,
                    seccion: item.seccion,
                    modalidad: item.modalidad,
                    hora_inicio: item.hora_inicio
                })]))
        }

        if (error) {
            if (!esTablaNoExiste(error)) {
                console.warn("No se pudo guardar curso_secciones:", error.message)
                mostrarMsgCursoModulo(
                    "msgCursoSeccion",
                    `No se pudo guardar en el servidor: ${error.message || "error desconocido"}`,
                    "error"
                )
            }
        } else {
            persistioEnDb = true
        }
    } catch (e) {
        console.warn("No se pudo persistir sección en Supabase:", e)
        mostrarMsgCursoModulo(
            "msgCursoSeccion",
            "No se pudo guardar la sección. Revisa la conexión o los permisos de Supabase.",
            "error"
        )
    }

    if (persistioEnDb) {
        const seccionesDb = await cargarSeccionesCursoDesdeSupabase()
        if (Array.isArray(seccionesDb)) cursoSecciones = seccionesDb

        guardarEstructuraCursoLocal()
        renderSeccionesCurso()
        actualizarOpcionesSeccionSede()
        limpiarFormSeccionCurso()

        mostrarMsgCursoModulo(
            "msgCursoSeccion",
            fueEdicion ? "Cambios guardados correctamente." : "Sección creada correctamente.",
            "ok"
        )
    }

    // Ya no hacemos render() afuera incondicionalmente,
    // garantizando que si falló no mostremos falsos positivos.
    registrarActividad(accion, {
        seccion: item.seccion,
        modalidad: item.modalidad,
        horaInicio: item.hora_inicio,
        dias: item.dias
    }, { tenantId: tenantActivoId })
}

function editarSeccionCurso(idx) {
    const item = cursoSecciones[idx]
    if (!item) return
    secCursoNombre.value = item.seccion
    secCursoModalidad.value = item.modalidad
    secCursoHora.value = item.hora_inicio
    marcarValoresMultiSelect("secCursoDiasSelect", item.dias || [])
    editSeccionCursoIndex = idx
    mostrarMsgCursoModulo("msgCursoSeccion", "", "")
    actualizarUIModoEdicionSeccion()
}

async function eliminarSeccionCurso(idx) {
    if (!confirm("¿Eliminar esta sección?")) return
    const seccion = cursoSecciones[idx]?.seccion
    if (editSeccionCursoIndex === idx) {
        limpiarFormSeccionCurso()
    } else if (editSeccionCursoIndex > idx) {
        editSeccionCursoIndex--
    }
    cursoSecciones.splice(idx, 1)

    try {
        if (seccion) {
            let qDel = withTenantScope(supabaseClient.from("curso_secciones").delete())
            const { error } = await qDel
                .eq("seccion", seccion)

            if (error && !esTablaNoExiste(error)) {
                console.warn("No se pudo eliminar sección de Supabase:", error.message)
            }
        }
    } catch (e) {
        console.warn("No se pudo eliminar sección en Supabase:", e)
    }

    guardarEstructuraCursoLocal()
    renderSeccionesCurso()
    actualizarOpcionesSeccionSede()
    if (editSeccionCursoIndex >= 0) {
        actualizarUIModoEdicionSeccion()
    }
    registrarActividad("seccion_curso_eliminada", {
        seccion: String(seccion || "")
    }, { tenantId: tenantActivoId })
}

function renderSeccionesCurso() {
    if (!cursoSecciones.length) {
        tablaSeccionesCurso.innerHTML = `<tr><td colspan="5">Sin secciones creadas.</td></tr>`
        return
    }

    let html = ""

    cursoSecciones.forEach((s, idx) => {
        html += `
      <tr>
        <td>Sección ${s.seccion}</td>
        <td>${s.modalidad}</td>
        <td>${s.hora_inicio || "-"}</td>
        <td>${diasTexto(s.dias)}</td>
        <td>
          <div class="table-actions">
            <button onclick="editarSeccionCurso(${idx})">Modificar</button>
            <button class="secondary" onclick="eliminarSeccionCurso(${idx})">Eliminar</button>
          </div>
        </td>
      </tr>
    `
    })

    tablaSeccionesCurso.innerHTML = html
}

async function guardarSedeUbo() {
    if (!haySupabase()) {
        mostrarMsgCursoModulo("msgCursoSede", "Sin conexión a Supabase. No se puede guardar la sede UBO.", "error")
        return
    }
    const seccionValor = String(uboSecNombre.value || "").trim().toUpperCase()
    const esTodasSecciones = seccionValor === "__ALL__"
    const seccionesDisponibles = Array.from(new Set((cursoSecciones || [])
        .map(x => String(x.seccion || "").trim().toUpperCase())
        .filter(Boolean)))
    const todosDias = !!uboSecTodosDias.checked
    const dias = todosDias ? [] : obtenerValoresMultiSelect("uboSecDiasSelect")
    const fueEdicionSede = editSedeUboIndex >= 0

    if (!seccionValor) {
        mostrarMsgCursoModulo("msgCursoSede", "Selecciona una sección existente.", "error")
        return
    }

    if (editSedeUboIndex >= 0 && esTodasSecciones) {
        mostrarMsgCursoModulo(
            "msgCursoSede",
            "Para aplicar a todas las secciones, cancela la edición y crea un registro nuevo.",
            "error"
        )
        return
    }

    if (esTodasSecciones && !seccionesDisponibles.length) {
        mostrarMsgCursoModulo("msgCursoSede", "No hay secciones creadas para aplicar esta configuración.", "error")
        return
    }

    if (!esTodasSecciones && !seccionesDisponibles.includes(seccionValor)) {
        mostrarMsgCursoModulo("msgCursoSede", "La sección seleccionada no existe. Créala primero en el bloque superior.", "error")
        return
    }

    if (!uboSecUbo.value) {
        mostrarMsgCursoModulo("msgCursoSede", "Selecciona una UBO sede.", "error")
        return
    }

    if (!uboSecHora.value) {
        mostrarMsgCursoModulo("msgCursoSede", "Indica la hora de inicio para la sede UBO.", "error")
        return
    }

    if (!todosDias && !dias.length) {
        mostrarMsgCursoModulo("msgCursoSede", "Selecciona al menos un día o activa la opción «Todos».", "error")
        return
    }

    const accion = fueEdicionSede ? "sede_ubo_editada" : "sede_ubo_creada"
    const seccionesObjetivo = esTodasSecciones ? seccionesDisponibles : [seccionValor]
    const uboValor = uboSecUbo.value
    const modalidadValor = uboSecModalidad.value
    const horaValor = uboSecHora.value

    const itemBase = {
        ubo: uboValor,
        modalidad: modalidadValor,
        hora_inicio: horaValor,
        dias,
        todos_dias: todosDias
    }
    const oldSeccion = editSedeUboIndex >= 0
        ? String(cursoSedesUbo[editSedeUboIndex]?.seccion || "").trim().toUpperCase()
        : null

    if (editSedeUboIndex < 0) {
        const repetidas = seccionesObjetivo.filter(sec => cursoSedesUbo.some(x => String(x.seccion || "").toUpperCase() === sec))
        if (repetidas.length) {
            const msg = esTodasSecciones
                ? `Ya existen ${repetidas.length} sección(es) con sede UBO. ¿Deseas reemplazarlas?`
                : `La Sección ${seccionValor} ya tiene UBO sede. ¿Deseas reemplazarla?`
            if (!confirm(msg)) return
        }
    }

    let persistioEnDb = false
    let erroresGuardado = 0
    try {
        if (oldSeccion && !seccionesObjetivo.includes(oldSeccion)) {
            let qSede = withTenantScope(supabaseClient.from("curso_sedes_ubo").delete())
            await qSede.eq("curso_id", 1)
                .eq("seccion", oldSeccion)
        }

        for (const sec of seccionesObjetivo) {
            let qActSede = withTenantScope(supabaseClient.from("curso_sedes_ubo").delete())
            const { error: errorDeleteActual } = await qActSede
                .eq("curso_id", 1)
                .eq("seccion", sec)
            if (errorDeleteActual && !esTablaNoExiste(errorDeleteActual)) {
                throw errorDeleteActual
            }

            const payloadSede = withTenantPayload({
                curso_id: 1,
                seccion: sec,
                ubo: uboValor,
                modalidad: modalidadValor,
                hora_inicio: horaValor,
                dias,
                todos_dias: todosDias
            })

            let { error } = await supabaseClient
                .from("curso_sedes_ubo")
                .insert([payloadSede])

            if (error && /(dias|todos_dias)/i.test(String(error.message || ""))) {
                ({ error } = await supabaseClient
                    .from("curso_sedes_ubo")
                    .insert([withTenantPayload({
                        curso_id: 1,
                        seccion: sec,
                        ubo: uboValor,
                        modalidad: modalidadValor,
                        hora_inicio: horaValor
                    })]))
            }

            if (error) {
                erroresGuardado += 1
                if (!esTablaNoExiste(error)) {
                    console.warn("No se pudo guardar curso_sedes_ubo:", error.message)
                }
            } else {
                persistioEnDb = true
            }
        }
    } catch (e) {
        console.warn("No se pudo persistir sede UBO en Supabase:", e)
        mostrarMsgCursoModulo(
            "msgCursoSede",
            "No se pudo guardar la sede UBO. Revisa la conexión o los permisos de Supabase.",
            "error"
        )
    }

    if (persistioEnDb) {
        const sedesDb = await cargarSedesCursoDesdeSupabase()
        if (Array.isArray(sedesDb)) cursoSedesUbo = sedesDb

        guardarEstructuraCursoLocal()
        renderSedesUbo()
        limpiarFormSedeUbo()
    }
    if (erroresGuardado > 0) {
        mostrarMsgCursoModulo(
            "msgCursoSede",
            `Se aplicó solo en parte: ${erroresGuardado} sección(es) no pudieron guardarse en el servidor.`,
            "error"
        )
    } else if (persistioEnDb) {
        mostrarMsgCursoModulo(
            "msgCursoSede",
            fueEdicionSede ? "Cambios en sede UBO guardados correctamente." : "Sede UBO registrada correctamente.",
            "ok"
        )
    }
    registrarActividad(accion, {
        secciones: seccionesObjetivo,
        ubo: uboValor,
        modalidad: modalidadValor,
        horaInicio: horaValor,
        todosDias
    }, { tenantId: tenantActivoId })
}

function editarSedeUbo(idx) {
    const item = cursoSedesUbo[idx]
    if (!item) return
    uboSecNombre.value = item.seccion
    uboSecUbo.value = item.ubo
    uboSecModalidad.value = item.modalidad
    uboSecHora.value = item.hora_inicio
    uboSecTodosDias.checked = !!item.todos_dias
    marcarValoresMultiSelect("uboSecDiasSelect", item.dias || [])
    actualizarEstadoDiasSede()
    editSedeUboIndex = idx
    mostrarMsgCursoModulo("msgCursoSede", "", "")
    actualizarUIModoEdicionSede()
}

async function eliminarSedeUbo(idx) {
    if (!confirm("¿Eliminar esta sede UBO?")) return
    const seccion = cursoSedesUbo[idx]?.seccion
    if (editSedeUboIndex === idx) {
        limpiarFormSedeUbo()
    } else if (editSedeUboIndex > idx) {
        editSedeUboIndex--
    }
    cursoSedesUbo.splice(idx, 1)

    try {
        if (seccion) {
            let qDelSede = withTenantScope(supabaseClient.from("curso_sedes_ubo").delete())
            const { error } = await qDelSede
                .eq("seccion", seccion)

            if (error && !esTablaNoExiste(error)) {
                console.warn("No se pudo eliminar sede UBO de Supabase:", error.message)
            }
        }
    } catch (e) {
        console.warn("No se pudo eliminar sede UBO en Supabase:", e)
    }

    guardarEstructuraCursoLocal()
    renderSedesUbo()
    if (editSedeUboIndex >= 0) {
        actualizarUIModoEdicionSede()
    }
    registrarActividad("sede_ubo_eliminada", {
        seccion: String(seccion || "")
    }, { tenantId: tenantActivoId })
}

function renderSedesUbo() {
    if (!cursoSedesUbo.length) {
        tablaSedesUbo.innerHTML = `<tr><td colspan="6">Sin UBOs sede creadas.</td></tr>`
        return
    }

    let html = ""
    cursoSedesUbo.forEach((s, idx) => {
        html += `
      <tr>
        <td>Sección ${s.seccion}</td>
        <td>${s.ubo}</td>
        <td>${s.modalidad}</td>
        <td>${s.hora_inicio || "-"}</td>
        <td>${s.todos_dias ? "Todos" : diasTexto(s.dias)}</td>
        <td>
          <div class="table-actions">
            <button onclick="editarSedeUbo(${idx})">Modificar</button>
            <button class="secondary" onclick="eliminarSedeUbo(${idx})">Eliminar</button>
          </div>
        </td>
      </tr>
    `
    })

    tablaSedesUbo.innerHTML = html
}

function limpiarDashboard() {
    const { from, to } = obtenerRangoMesActual()
    dashDesde.value = from
    dashHasta.value = to
    dashUbo.value = ""
    if (dashSeccion) dashSeccion.value = ""

    // 🔥 reset KPIs
    kpiTotal.innerText = "0"
    kpiAsistencia.innerText = "0%"
    kpiInasistencia.innerText = "0"
    kpiCobertura.innerText = "0%"

    verdeCount.innerText = "0"
    amarilloCount.innerText = "0"
    rojoCount.innerText = "0"
    kpiRojoTardanza.innerText = "0"
    kpiRojoFueraDia.innerText = "0"
    kpiDispNoHabitual.innerText = "0"
    kpiDispCard.style.opacity = "0.75"

    topUbo.innerHTML = ""
    semaforoInfo.innerText = "Semáforo: primera marcación del último día vs hora/días de su sección."
    riesgoInfo.innerText = "Riesgo UBO: cantidad de aspirantes en rojo por UBO según horario/días."

    // limpiar memoria
    window.detalleSemaforo = {
        verde: [],
        amarillo: [],
        rojo: []
    }
    window.detalleAlertasDispositivo = []

}

function limpiarRetiro() {
    filtroUboConfig.value = ""
    if (filtroTextoRetiro) filtroTextoRetiro.value = ""
    listaAspirantes.innerHTML = ""
}

async function limpiarCurso() {
    if (!haySupabase()) {
        mostrarMsgCursoModulo(
            "msgCursoFooter",
            "Sin conexión a Supabase. No se puede completar la operación.",
            "error"
        )
        return
    }

    try {
        let qClrSec = withTenantScope(supabaseClient.from("curso_secciones").delete())
        const { error } = await qClrSec.neq("seccion", "DUMMY_HACK_DELETE_ALL")
        if (error && !esTablaNoExiste(error)) {
            console.warn("No se pudo limpiar curso_secciones:", error.message)
            mostrarMsgCursoModulo(
                "msgCursoFooter",
                "Error al eliminar en servidor. Intente nuevamente.",
                "error"
            )
            return
        }
    } catch (e) {
        console.warn("No se pudo limpiar curso_secciones:", e)
        mostrarMsgCursoModulo(
            "msgCursoFooter",
            "Error al eliminar en servidor. Intente nuevamente.",
            "error"
        )
        return
    }

    try {
        let qClrSede = withTenantScope(supabaseClient.from("curso_sedes_ubo").delete())
        const { error } = await qClrSede.neq("seccion", "DUMMY_HACK_DELETE_ALL")
        if (error && !esTablaNoExiste(error)) {
            console.warn("No se pudo limpiar curso_sedes_ubo:", error.message)
            mostrarMsgCursoModulo(
                "msgCursoFooter",
                "Error al eliminar en servidor. Intente nuevamente.",
                "error"
            )
            await cargarConfigCurso()
            limpiarFormSeccionCurso()
            limpiarFormSedeUbo()
            return
        }
    } catch (e) {
        console.warn("No se pudo limpiar curso_sedes_ubo:", e)
        mostrarMsgCursoModulo(
            "msgCursoFooter",
            "Error al eliminar en servidor. Intente nuevamente.",
            "error"
        )
        await cargarConfigCurso()
        limpiarFormSeccionCurso()
        limpiarFormSedeUbo()
        return
    }

    await cargarConfigCurso()
    limpiarFormSeccionCurso()
    limpiarFormSedeUbo()
    mostrarMsgCursoModulo(
        "msgCursoFooter",
        "Secciones y sedes eliminadas correctamente.",
        "ok"
    )
}

async function cargarRetirados() {

    const ubo = filtroRetirados.value
    const texto = String(filtroTextoRetirados?.value || "").trim().toLowerCase()

    let q = withTenantScope(supabaseClient
        .from("asistencias")
        .select("dni,nombre,ubo,tenant_id")
        .eq("estado", "retirado"))

    if (ubo) {
        q = q.eq("ubo", ubo)
    }

    const { data } = await q
    const scopedData = filtrarDataTenantActivo(data)
    const dedupe = new Map()

        ; (scopedData || []).forEach(a => {
            const dni = String(a?.dni || "").trim()
            const nombre = String(a?.nombre || "").trim()
            const matchTexto = !texto ||
                dni.toLowerCase().includes(texto) ||
                nombre.toLowerCase().includes(texto)
            if (!matchTexto) return
            if (!dni || dedupe.has(dni)) return
            dedupe.set(dni, {
                dni,
                nombre: nombre || "Sin nombre",
                ubo: String(a?.ubo || "").trim()
            })
        })

    let html = ""

    Array.from(dedupe.values()).forEach(a => {
        html += `
      <p style="display:flex; justify-content:space-between; align-items:center;">
        <span>${a.nombre} (${a.dni}) - UBO ${a.ubo}</span>
        <button onclick="reactivar('${a.dni}')" style="height:30px;">Reactivar</button>
      </p>
    `
    })

    listaRetirados.innerHTML = html || `<p class="hint">No hay aspirantes retirados para el filtro seleccionado.</p>`
}

function limpiarRetirados() {
    filtroRetirados.value = ""
    if (filtroTextoRetirados) filtroTextoRetirados.value = ""
    listaRetirados.innerHTML = ""
}

async function reactivar(dni) {

    await withTenantScope(supabaseClient
        .from("asistencias")
        .update({ estado: null })
        .eq("dni", dni))

    cargarRetirados()
    registrarActividad("aspirante_reactivado", {
        dni: String(dni || "").trim()
    }, { tenantId: tenantActivoId })
}

loginPass?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
        login()
    }
})

tenantAdminPass?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
        loginAccesoAdminInstitucional()
    }
})

tenantAdminUser?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
        loginAccesoAdminInstitucional()
    }
})

let debounceTimerAutocompletar = null;

async function procesarAutocompletadoDni(dniValue) {
    const dniLimpio = (dniValue || "").replace(/\D/g, "").slice(0, 8);
    if (dniLimpio.length === 8) {
        clearTimeout(debounceTimerAutocompletar);
        debounceTimerAutocompletar = setTimeout(async () => {
            if (!haySupabase() || !tenantActivoId) return;
            try {
                const { data, error } = await supabaseClient
                    .from('aspirantes')
                    .select('nombres, apellidos, ubo')
                    .eq('dni', dniLimpio)
                    .eq('tenant_id', tenantActivoId)
                    .single();

                if (data && !error) {
                    nombres.value = data.nombres || "";
                    apellidos.value = data.apellidos || "";
                    ubo.value = data.ubo || "";

                    nombres.readOnly = true;
                    apellidos.readOnly = true;
                    ubo.readOnly = true;
                    if (ubo.tagName === "SELECT") ubo.disabled = true;

                    nombres.style.backgroundColor = "#f0f4f8";
                    apellidos.style.backgroundColor = "#f0f4f8";
                    ubo.style.backgroundColor = "#f0f4f8";
                    setMensaje("");
                } else {
                    limpiarCamposAspirante();
                    setMensaje("⚠ El DNI ingresado no existe en el padrón de la institución.", "warning");
                }
            } catch (e) {
                console.error("Error al autocompletar aspirante:", e);
                limpiarCamposAspirante();
            }
        }, 300);
    } else {
        limpiarCamposAspirante();
        setMensaje("");
    }
}

function limpiarCamposAspirante() {
    nombres.value = "";
    apellidos.value = "";
    ubo.value = "";

    nombres.readOnly = false;
    apellidos.readOnly = false;
    ubo.readOnly = false;
    if (ubo.tagName === "SELECT") ubo.disabled = false;

    nombres.style.backgroundColor = "";
    apellidos.style.backgroundColor = "";
    ubo.style.backgroundColor = "";
}

mobileDni?.addEventListener("input", () => {
    mobileDni.value = mobileDni.value.replace(/\D/g, "").slice(0, 8)
    procesarAutocompletadoDni(mobileDni.value)
})

mobileDniInicio?.addEventListener("input", () => {
    mobileDniInicio.value = mobileDniInicio.value.replace(/\D/g, "").slice(0, 8)
    procesarAutocompletadoDni(mobileDniInicio.value)
})

mobileDni?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
        ingresarMovil()
    }
})

mobileDniInicio?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
        ingresarMovilInicio()
    }
})

ubo?.addEventListener("input", () => {
    ubo.value = ubo.value.replace(/\D/g, "")
})

cursoNombre?.addEventListener("input", () => {
    cursoNombre.value = cursoNombre.value.toUpperCase()
})

secCursoNombre?.addEventListener("input", () => {
    secCursoNombre.value = secCursoNombre.value.toUpperCase().replace(/\s+/g, "")
})

window.addEventListener("resize", () => {
    clearTimeout(resizeTimer)
    resizeTimer = setTimeout(aplicarLayout, 160)
})

window.addEventListener("orientationchange", () => {
    clearTimeout(resizeTimer)
    resizeTimer = setTimeout(aplicarLayout, 120)
})

window.detalleSemaforo = {
    verde: [],
    amarillo: [],
    rojo: []
}

window.detalleAlertasDispositivo = []

document.addEventListener("change", (e) => {
    if (e.target.matches(".mode-options input")) {
        actualizarEstadoChecks()
    }
    if (e.target.id === "uboSecTodosDias") {
        actualizarEstadoDiasSede()
    }
})
