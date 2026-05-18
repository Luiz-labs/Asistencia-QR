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

function esErrorConexionAsistIA(error) {
    const texto = String(error?.message || error || "").toLowerCase();
    return /failed to fetch|fetch failed|networkerror|network request failed|load failed|timeout|temporarily unavailable|connection|offline/i.test(texto);
}

function esErrorSesionAsistIA(error) {
    const texto = String(error?.message || error || "").toLowerCase();
    return /jwt|session|auth session missing|refresh token|token/i.test(texto);
}

function mensajeUsuarioAsistIA(error, fallback = "Ocurrió un problema al procesar la solicitud.") {
    if (esErrorSesionAsistIA(error)) return "La sesión expiró. Vuelve a iniciar sesión.";
    if (esErrorConexionAsistIA(error)) return "No se pudo conectar con asistIA. Verifica tu conexión e inténtalo nuevamente.";
    return fallback;
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

function buildEmptyStateHTML(title, text, icon = "○", compact = false) {
    return `
      <div class="empty-state${compact ? " empty-state-compact" : ""}">
        <div class="empty-state-icon" aria-hidden="true">${icon}</div>
        <div class="empty-state-title">${title}</div>
        <div class="empty-state-text">${text}</div>
      </div>
    `
}

function buildEmptyTableRow(colspan, title, text, icon = "○") {
    return `
      <tr class="empty-state-row">
        <td colspan="${colspan}">${buildEmptyStateHTML(title, text, icon, true)}</td>
      </tr>
    `
}

function limpiarCurrentProfileVisual() {
    window.currentProfile = null
}

function resolverDatosVisualesSesionActual() {
    const sesion = obtenerSesionAdminActiva()
    const usuario = String(sesion?.usuario || "").trim().toLowerCase()
    const vacio = {
        usuario,
        nombreCompleto: usuario || "",
        rolTecnico: sesion?.rol || "",
        perfilFuncional: esSuperusuarioActivo() ? "Acceso total" : (obtenerPerfilUsuarioActivo()?.nombre || ""),
        tenantNombre: obtenerNombreTenantUI(sesion?.tenantId || ""),
        tenantId: String(sesion?.tenantId || "").trim()
    }
    if (!usuario) return vacio

    const usuarioInstitucional = (usuariosAdmin || []).find(u => String(u.usuario || "").toLowerCase() === usuario)
    const usuarioLuiz = (usuariosAdminLuiz || []).find(u => String(u.usuario || "").toLowerCase() === usuario)
    const fuente = usuarioInstitucional || usuarioLuiz || null
    const nombres = String(fuente?.nombres || fuente?.nombre || "").trim()
    const apellidos = String(fuente?.apellidos || "").trim()
    const nombreCompleto = `${nombres} ${apellidos}`.replace(/\s+/g, " ").trim() || usuario
    const perfilNombre = esSuperusuarioActivo()
        ? "Acceso total"
        : (obtenerPerfilUsuarioActivo()?.nombre || "Administrador")

    return {
        usuario,
        nombreCompleto,
        rolTecnico: sesion?.rol || "",
        perfilFuncional: perfilNombre,
        tenantNombre: obtenerNombreTenantUI(sesion?.tenantId || ""),
        tenantId: String(sesion?.tenantId || "").trim()
    }
}

function renderCurrentUserInfo() {
    const ids = [
        { name: 'currentUserName', role: 'currentUserRole' },
        { name: 'currentUserNameLuiz', role: 'currentUserRoleLuiz' }
    ];

    const datosSesion = resolverDatosVisualesSesionActual()
    const nombre = datosSesion.nombreCompleto || datosSesion.usuario || ""
    const rol = datosSesion.rolTecnico || ""

    ids.forEach(set => {
        const nameEl = document.getElementById(set.name);
        const roleEl = document.getElementById(set.role);
        if (nameEl) nameEl.textContent = nombre;
        if (roleEl) roleEl.textContent = obtenerNombreRolUI(rol);
    });
}

function enlazarAccionesCuentaHeader() {
    const btnCuenta = document.getElementById("btnAbrirCuenta")
    const btnCuentaLuiz = document.getElementById("btnAbrirCuentaLuiz")
    const btnLogout = document.getElementById("btnHeaderLogout")
    const btnLogoutLuiz = document.getElementById("btnHeaderLogoutLuiz")
    const btnCuentaLogout = document.getElementById("btnCuentaLogout")

    if (btnCuenta) btnCuenta.onclick = abrirCuentaModal
    if (btnCuentaLuiz) btnCuentaLuiz.onclick = abrirCuentaModal
    if (btnLogout) btnLogout.onclick = logout
    if (btnLogoutLuiz) btnLogoutLuiz.onclick = logout
    if (btnCuentaLogout) btnCuentaLogout.onclick = logout
}

async function bootstrapAuthorizedApp() {
    sincronizarPermisosPanelInstitucional()
    await loadCurrentProfile();
    applyRolePermissions();
    aplicarRestriccionesPanelPorContexto()
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
let editUsuarioIndex = null
let usuariosAdmin = []
let cacheReportes = []
let cacheReportesStaff = []
let cacheDashboard = []
let cacheRiesgoUbo = []
let staffInstruccionCache = []
let cacheDashboardStaff = []
let staffReportExpandedKey = ""
let editStaffInstruccionId = null
let vistaAdminActual = "reportes"
let vistaLuizLabsActual = "instituciones"
const HISTORICAL_IMPORT_FIELDS = Object.freeze([
    { key: "timestamp", label: "Timestamp", help: "Marca temporal o fecha y hora del registro." },
    { key: "dni", label: "DNI", help: "Requerido para importar a asistencias en Fase 2.", optional: true },
    { key: "ubo", label: "UBO", help: "Código UBO; se conservarán solo números." },
    { key: "nombres", label: "Nombres", help: "Nombres del aspirante." },
    { key: "apellidos", label: "Apellidos", help: "Apellidos del aspirante." },
    { key: "seccion", label: "Sección", help: "Sección del curso o grupo." }
])
const HISTORICAL_IMPORT_ALIASES = Object.freeze({
    timestamp: ["marca temporal", "timestamp", "fecha y hora", "fecha hora", "fecha de envio", "hora de envio"],
    dni: ["dni", "documento", "n documento", "numero de documento", "num documento"],
    ubo: ["ubo", "ubo colocar solo numero", "codigo ubo", "codigo de ubo", "nro ubo", "numero ubo"],
    nombres: ["nombres", "nombre", "nombres y apellidos"],
    apellidos: ["apellidos", "apellido", "apellidos y nombres"],
    seccion: ["seccion", "sección", "seccion a/b/c", "seccion a b c", "sec", "grupo", "aula"]
})
let historicalImportState = createHistoricalImportState()
const VISTA_MODO_KEY = "vistaModoManual"
const ADMIN_SESSION_KEY = "asistia_admin_session_v1"
const COURSE_QR_BASE_URL = "https://asistia.pages.dev"
let cursoQrState = {
    token: "",
    aspirantesUrl: "",
    staffUrl: ""
}
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
    return Object.values(TENANTS)
        .filter(t => {
            const slug = String(t.id || "").trim().toLowerCase();
            return slug !== "esbas-24-demo" && t.habilitado !== false;
        })
        .sort((a, b) =>
            String(a.nombre || "").localeCompare(String(b.nombre || ""), "es")
        )
}

function primerTenantFallback() {
    const vals = Object.values(TENANTS).filter(t => {
        const slug = String(t.id || "").trim().toLowerCase();
        return slug !== "esbas-24-demo" && t.habilitado !== false;
    })
    return vals.length ? vals[0] : null
}
let tenantActivoId = ""
function normalizarTenantId(id) {
    return String(id || "").trim().toLowerCase()
}
let esModoStaff = true
let accesoDirectoInstitucion = false
let mostrarSelectorStaff = false
let sesionAdminActiva = crearSesionAdminVacia()
let institucionesLuiz = []
let usuariosAdminLuiz = []
let perfilesLuiz = []
let perfilesUsuariosLocales = {}
let permisosPanelInstitucionalResueltos = false
let editUsuarioAdminLuizIndex = null
let editUsuarioGlobalLuizIndex = null
let editPerfilLuizIndex = -1
let soporteLuizLabsSupabase = null
let soporteActividadLogsSupabase = null
let soporteUsuariosLuizSupabase = null

/* UI HELPERS USUARIOS PRO */
function toggleDetallesUsuario(rowId) {
    const row = document.getElementById(rowId)
    if (!row) return
    const isExpanded = row.classList.contains('expanded')

    // Opcional: Cerrar otros rows expandidos en la misma tabla
    const table = row.closest('table')
    if (table) {
        table.querySelectorAll('.user-details-row.expanded').forEach(r => {
            if (r.id !== rowId) r.classList.remove('expanded')
        })
    }

    row.classList.toggle('expanded', !isExpanded)
}

function renderBadgePerfil(perfilId) {
    const pId = String(perfilId || "").toLowerCase()
    const perfil = obtenerPerfilPorId(pId)
    const nombre = perfil?.nombre || (pId === 'superusuario' ? 'Superusuario' : 'Administrador')

    if (pId === 'superusuario' || pId === 'administrador' || pId.includes('admin')) {
        return `<span class="badge badge-profile-admin">👑 ${nombre}</span>`
    }
    return `<span class="badge badge-profile-staff">👤 ${nombre}</span>`
}

function renderBadgeEstado(activo) {
    if (activo) {
        return `<span class="badge badge-status-active">Activo</span>`
    }
    return `<span class="badge badge-status-inactive">Inactivo</span>`
}
let soporteCursosSupabase = null
let syncLuizLabsEnCurso = null
let cursoActualId = 1
let cursoBaseActual = null
let cursoQRValido = false
let validacionCursoAspirante = { dni: "", permitido: true, legacy: false, bloqueado: false }
let perfilAspiranteActual = { dni: "", seccion: "" }
let inputDniFocusLockUntil = 0
const SYSTEM_USERS = []

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

function normalizarCorreoProvisionAdmin(usuario, correo = "") {
    const correoLimpio = String(correo || "").trim().toLowerCase()
    if (correoLimpio && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correoLimpio)) {
        return correoLimpio
    }
    const usuarioLimpio = String(usuario || "").trim().toLowerCase()
    return usuarioLimpio ? `${usuarioLimpio}@asistia.local` : ""
}

function obtenerValorEdicion(inputValue, originalValue, normalizer = value => String(value || "").trim()) {
    const valorInput = normalizer(inputValue)
    if (valorInput) return valorInput
    return normalizer(originalValue)
}

function obtenerClaveUsuario(user) {
    return String(user?.password || user?.clave || "").trim()
}

function resolverPerfilUsuario(usuario, perfilActual = "") {
    const usuarioKey = String(usuario || "").trim().toLowerCase()
    const perfilMapeado = normalizarPerfilId(perfilesUsuariosLocales?.[usuarioKey] || "")
    if (perfilMapeado && obtenerPerfilPorId(perfilMapeado)) return perfilMapeado
    const perfilNormalizado = normalizarPerfilId(perfilActual || "")
    if (perfilNormalizado && obtenerPerfilPorId(perfilNormalizado)) return perfilNormalizado
    return "administrador"
}

function hidratarUsuariosLuizConPerfiles(items = []) {
    return (items || []).map(u => Object.assign({}, u, {
        perfilId: resolverPerfilUsuario(u?.usuario, u?.perfilId)
    }))
}

async function tieneSesionSupabaseActiva() {
    if (!haySupabase()) return false
    const { data, error } = await supabaseClient.auth.getSession()
    return !error && !!data?.session?.access_token && !!data?.session?.user
}

function resetEstadoSesionAdminUI() {
    cerrarCuentaModal()
    if (typeof cerrarTutorial === "function") cerrarTutorial()
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

    // Agresivamente limpiar todas las claves de sesión locales y de Supabase
    try {
        const storageKeys = []
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i)
            if (key && (key.includes("asistia") || key.includes("sb-") || key.includes("supabase") || key.includes("auth") || key.includes("token"))) {
                storageKeys.push(key)
            }
        }
        storageKeys.forEach(k => localStorage.removeItem(k))
    } catch (e) {
        console.warn("Error al limpiar localStorage de sesión:", e)
    }

    try {
        const sessionKeys = []
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i)
            if (key && (key.includes("asistia") || key.includes("sb-") || key.includes("supabase") || key.includes("auth") || key.includes("token"))) {
                sessionKeys.push(key)
            }
        }
        sessionKeys.forEach(k => sessionStorage.removeItem(k))
    } catch (e) {
        console.warn("Error al limpiar sessionStorage de sesión:", e)
    }
}

async function asegurarSesionSupabaseValida() {
    if (!haySupabase()) return false

    const { data: sessionWrap, error: sessionError } = await supabaseClient.auth.getSession()
    const session = sessionWrap?.session || null
    if (!sessionError && session?.access_token) {
        return true
    }

    try {
        await supabaseClient.auth.signOut()
    } catch (_) { }

    resetEstadoSesionAdminUI()
    alert("Tu sesión expiró. Vuelve a iniciar sesión para continuar.")

    const accesoRuta = resolverAccesoDesdeRuta()
    const tenantDestino = String(accesoRuta?.tenantId || tenantActivoId || obtenerSesionAdminActiva()?.tenantId || "").trim()
    const destino = accesoRuta?.staff ? "/" : obtenerRutaTenantBackoffice(tenantDestino)
    window.location.replace(destino)
    return false
}

async function provisionarUsuarioAdminSeguro(payload = {}) {
    if (!haySupabase()) {
        throw new Error("Supabase no está disponible.")
    }
    const sesionValida = await asegurarSesionSupabaseValida()
    if (!sesionValida) {
        throw new Error("SESSION_EXPIRED")
    }

    const body = {
        usuario: String(payload.usuario || "").trim().toLowerCase(),
        clave: String(payload.clave || "").trim(),
        correo: normalizarCorreoProvisionAdmin(payload.usuario, payload.correo),
        tenant_id: String(payload.tenant_id || "").trim().toLowerCase(),
        rol: normalizarRolUsuario(payload.rol || ROLES_ADMIN.ADMINISTRADOR),
        nombres: String(payload.nombres || "").trim(),
        apellidos: String(payload.apellidos || "").trim(),
        dni: String(payload.dni || "").replace(/\D/g, ""),
        celular: String(payload.celular || "").replace(/\D/g, ""),
        perfil_id: normalizarPerfilId(payload.perfil_id || "administrador") || "administrador",
        previous_usuario: String(payload.previous_usuario || "").trim().toLowerCase(),
        activo: payload.activo !== false
    }

    const { data, error } = await supabaseClient.functions.invoke("provision-admin-user", {
        body
    })

    if (error) {
        throw new Error(error.message || "No se pudo provisionar el usuario.")
    }
    if (!data?.ok) {
        throw new Error(data?.error || "No se pudo provisionar el usuario.")
    }
    return data
}

async function actualizarUsuarioAdminExistenteEnSupabase(payload = {}) {
    if (!haySupabase()) {
        throw new Error("Supabase no está disponible.")
    }

    const usuario = String(payload.usuario || "").trim().toLowerCase()
    const previousUsuario = String(payload.previous_usuario || "").trim().toLowerCase() || usuario
    if (!usuario || !previousUsuario) {
        throw new Error("Usuario inválido para actualización.")
    }

    let { data: existente, error: findError } = await supabaseClient
        .from("usuarios_admin")
        .select("id,clave,auth_user_id")
        .eq("usuario", previousUsuario)
        .limit(1)

    if (findError && /auth_user_id/i.test(String(findError.message || ""))) {
        const fallback = await supabaseClient
            .from("usuarios_admin")
            .select("id,clave")
            .eq("usuario", previousUsuario)
            .limit(1)
        existente = (fallback.data || []).map(row => Object.assign({}, row, { auth_user_id: null }))
        findError = fallback.error
    }

    if (findError) {
        throw new Error(findError.message || "No se pudo localizar el usuario.")
    }

    const actual = Array.isArray(existente) ? existente[0] : null
    if (!actual?.id) {
        throw new Error("No se encontró el usuario a editar.")
    }

    const claveActual = String(actual.clave || "").trim()
    const claveNueva = String(payload.clave || "").trim()
    const updatePayload = {
        nombre: `${String(payload.nombres || "").trim()} ${String(payload.apellidos || "").trim()}`.trim() || usuario,
        nombres: String(payload.nombres || "").trim(),
        apellidos: String(payload.apellidos || "").trim(),
        dni: String(payload.dni || "").replace(/\D/g, ""),
        correo: normalizarCorreoProvisionAdmin(usuario, payload.correo),
        celular: String(payload.celular || "").replace(/\D/g, ""),
        usuario,
        clave: claveNueva || claveActual,
        rol: rolUsuarioSupabaseDesdeApp(payload.rol || ROLES_ADMIN.ADMINISTRADOR),
        activo: payload.activo !== false,
        tenant_id: String(payload.tenant_id || "").trim().toLowerCase() || null
    }

    let { error: updateError } = await supabaseClient
        .from("usuarios_admin")
        .update(updatePayload)
        .eq("id", actual.id)

    if (updateError && /(tenant_id|nombres|apellidos|dni|correo|celular)/i.test(String(updateError.message || ""))) {
        const fallback = await supabaseClient
            .from("usuarios_admin")
            .update({
                nombre: updatePayload.nombre,
                usuario: updatePayload.usuario,
                clave: updatePayload.clave,
                rol: updatePayload.rol,
                activo: updatePayload.activo
            })
            .eq("id", actual.id)
        updateError = fallback.error
    }

    if (updateError) {
        throw new Error(updateError.message || "No se pudo actualizar el usuario.")
    }

    return {
        ok: true,
        authUserId: String(actual.auth_user_id || "").trim(),
        clave: updatePayload.clave
    }
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
    // Solo sube logs locales sin sincronizar si los hay (modo offline contingency buffer)
    // Pero NO descarga los logs de Supabase a LocalStorage para evitar consumo de memoria.
    const logsLocales = leerActividadLogs()
    if (logsLocales.length) {
        for (const entry of logsLocales.slice(0, 10).reverse()) {
            await insertarActividadLogEnSupabase(entry)
        }
    }
}

// Variables de paginación para Actividad Reciente
let offsetActividadTenant = 0
let offsetActividadGlobal = 0
const PAGINA_LOGS_TAMANIO = 50
let logsTenantActuales = []
let logsGlobalActuales = []

async function consultarActividadLogsSupabase(opts = {}) {
    if (!haySupabase()) return { data: [], total: 0 }
    const limit = opts.limit || PAGINA_LOGS_TAMANIO
    const offset = opts.offset || 0
    
    let query = supabaseClient.from("actividad_logs").select("*", { count: "exact" })
    
    // Filtro de aislamiento Multitenant y Scopes
    if (opts.esGlobal) {
        if (opts.tenantId) {
            query = query.eq("tenant_id", normalizarTenantId(opts.tenantId))
        }
    } else {
        query = withTenantScope(query)
        // Soporte para logs del curso activo o globales de administración (curso_id is null)
        const cId = Number(cursoActualId || 1) || 1
        query = query.or(`curso_id.eq.${cId},curso_id.is.null`)
    }
    
    // Rango de fechas
    if (opts.desde) {
        query = query.gte("fecha", `${opts.desde}T00:00:00-05:00`)
    }
    if (opts.hasta) {
        query = query.lte("fecha", `${opts.hasta}T23:59:59-05:00`)
    }
    
    // Búsqueda de texto (Or indexado rápido sobre columnas clave)
    if (opts.texto) {
        const txt = opts.texto.trim()
        query = query.or(`accion.ilike.%${txt}%,usuario.ilike.%${txt}%,rol.ilike.%${txt}%,device_label.ilike.%${txt}%,device_id.ilike.%${txt}%,ruta.ilike.%${txt}%`)
    }
    
    query = query.order("fecha", { ascending: false })
                 .range(offset, offset + limit - 1)
                 
    const { data, error, count } = await query
    
    if (error) {
        console.warn("No se pudo consultar actividad_logs:", error.message)
        return { data: [], total: 0 }
    }
    
    const mapped = (data || []).map(mapearActividadSupabaseALocal)
    return { data: mapped, total: count || 0 }
}

async function cargarMasActividadTenant() {
    offsetActividadTenant += PAGINA_LOGS_TAMANIO
    const texto = document.getElementById("filtroActividadTenantTexto")?.value || ""
    const desde = document.getElementById("filtroActividadTenantDesde")?.value || ""
    const hasta = document.getElementById("filtroActividadTenantHasta")?.value || ""
    
    const res = await consultarActividadLogsSupabase({
        esGlobal: false,
        texto,
        desde,
        hasta,
        offset: offsetActividadTenant,
        limit: PAGINA_LOGS_TAMANIO
    })
    
    logsTenantActuales = logsTenantActuales.concat(res.data)
    renderTablaActividadTenant(logsTenantActuales, logsTenantActuales.length < res.total)
}

async function cargarMasActividadGlobal() {
    offsetActividadGlobal += PAGINA_LOGS_TAMANIO
    const texto = document.getElementById("filtroActividadGlobalTexto")?.value || ""
    const desde = document.getElementById("filtroActividadGlobalDesde")?.value || ""
    const hasta = document.getElementById("filtroActividadGlobalHasta")?.value || ""
    const tenantId = document.getElementById("filtroActividadGlobalTenant")?.value || ""
    
    const res = await consultarActividadLogsSupabase({
        esGlobal: true,
        texto,
        desde,
        hasta,
        tenantId,
        offset: offsetActividadGlobal,
        limit: PAGINA_LOGS_TAMANIO
    })
    
    logsGlobalActuales = logsGlobalActuales.concat(res.data)
    renderTablaActividadGlobal(logsGlobalActuales, logsGlobalActuales.length < res.total)
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
    return insertarActividadLogEnSupabase(entry)
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

function renderTablaActividadTenant(rows = [], hasMore = false) {
    const tbody = document.getElementById("tablaActividadTenant")
    if (!tbody) return
    if (!rows.length) {
        tbody.innerHTML = buildEmptyTableRow(
            6,
            "Sin actividad registrada",
            "Sin actividad registrada en este rango.",
            "🧾"
        )
        const btnContainer = document.getElementById("btnCargarMasLogsTenantContainer")
        if (btnContainer) btnContainer.style.display = "none"
        return
    }
    let html = ""
    rows.forEach(item => {
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

    // Inyección dinámica y control de display del botón "Cargar más"
    const wrapper = tbody.closest(".table-wrap")
    if (wrapper) {
        let btnContainer = document.getElementById("btnCargarMasLogsTenantContainer")
        if (!btnContainer) {
            btnContainer = document.createElement("div")
            btnContainer.id = "btnCargarMasLogsTenantContainer"
            btnContainer.className = "logs-load-more-container"
            btnContainer.style.textAlign = "center"
            btnContainer.style.marginTop = "15px"
            btnContainer.style.marginBottom = "15px"
            btnContainer.innerHTML = `<button class="secondary" onclick="cargarMasActividadTenant()">Cargar más registros</button>`
            wrapper.parentNode.insertBefore(btnContainer, wrapper.nextSibling)
        }
        btnContainer.style.display = hasMore ? "block" : "none"
    }
}

function renderTablaActividadGlobal(rows = [], hasMore = false) {
    const tbody = document.getElementById("tablaActividadGlobal")
    if (!tbody) return
    if (!rows.length) {
        tbody.innerHTML = buildEmptyTableRow(
            7,
            "Sin actividad registrada",
            "Sin actividad registrada en este rango.",
            "🧾"
        )
        const btnContainer = document.getElementById("btnCargarMasLogsGlobalContainer")
        if (btnContainer) btnContainer.style.display = "none"
        return
    }
    let html = ""
    rows.forEach(item => {
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

    // Inyección dinámica y control de display del botón "Cargar más"
    const wrapper = tbody.closest(".table-wrap")
    if (wrapper) {
        let btnContainer = document.getElementById("btnCargarMasLogsGlobalContainer")
        if (!btnContainer) {
            btnContainer = document.createElement("div")
            btnContainer.id = "btnCargarMasLogsGlobalContainer"
            btnContainer.className = "logs-load-more-container"
            btnContainer.style.textAlign = "center"
            btnContainer.style.marginTop = "15px"
            btnContainer.style.marginBottom = "15px"
            btnContainer.innerHTML = `<button class="secondary" onclick="cargarMasActividadGlobal()">Cargar más registros</button>`
            wrapper.parentNode.insertBefore(btnContainer, wrapper.nextSibling)
        }
        btnContainer.style.display = hasMore ? "block" : "none"
    }
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

async function cargarActividadTenant() {
    offsetActividadTenant = 0
    logsTenantActuales = []
    
    const texto = document.getElementById("filtroActividadTenantTexto")?.value || ""
    const desde = document.getElementById("filtroActividadTenantDesde")?.value || ""
    const hasta = document.getElementById("filtroActividadTenantHasta")?.value || ""
    
    const res = await consultarActividadLogsSupabase({
        esGlobal: false,
        texto,
        desde,
        hasta,
        offset: 0,
        limit: PAGINA_LOGS_TAMANIO
    })
    
    logsTenantActuales = res.data
    renderTablaActividadTenant(logsTenantActuales, logsTenantActuales.length < res.total)
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
    void cargarActividadTenant()
}

async function cargarActividadGlobal() {
    offsetActividadGlobal = 0
    logsGlobalActuales = []
    
    const texto = document.getElementById("filtroActividadGlobalTexto")?.value || ""
    const desde = document.getElementById("filtroActividadGlobalDesde")?.value || ""
    const hasta = document.getElementById("filtroActividadGlobalHasta")?.value || ""
    const tenantId = document.getElementById("filtroActividadGlobalTenant")?.value || ""
    
    const res = await consultarActividadLogsSupabase({
        esGlobal: true,
        texto,
        desde,
        hasta,
        tenantId,
        offset: 0,
        limit: PAGINA_LOGS_TAMANIO
    })
    
    logsGlobalActuales = res.data
    renderTablaActividadGlobal(logsGlobalActuales, logsGlobalActuales.length < res.total)
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
    void cargarActividadGlobal()
}

async function exportarActividadCSV(scope = "tenant") {
    const esGlobal = scope === "global"
    const texto = document.getElementById(esGlobal ? "filtroActividadGlobalTexto" : "filtroActividadTenantTexto")?.value || ""
    const desde = document.getElementById(esGlobal ? "filtroActividadGlobalDesde" : "filtroActividadTenantDesde")?.value || ""
    const hasta = document.getElementById(esGlobal ? "filtroActividadGlobalHasta" : "filtroActividadTenantHasta")?.value || ""
    const tenantId = esGlobal ? (document.getElementById("filtroActividadGlobalTenant")?.value || "") : ""
    
    // Consulta dinámica y directa de Supabase con un límite amplio de exportación de seguridad (10,000 registros)
    const res = await consultarActividadLogsSupabase({
        esGlobal,
        texto,
        desde,
        hasta,
        tenantId,
        offset: 0,
        limit: 10000
    })
    const rows = res.data

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
            permisosPanelInstitucionalResueltos = false
            sincronizarEstadoLegacyAdmin()
            return sesionAdminActiva
        }
        sesionAdminActiva = normalizarSesionAdmin(JSON.parse(raw))
    } catch (e) {
        console.warn("No se pudo leer sesión admin:", e)
        sesionAdminActiva = crearSesionAdminVacia()
        permisosPanelInstitucionalResueltos = false
    }
    sincronizarPermisosPanelInstitucional()
    sincronizarEstadoLegacyAdmin()
    return sesionAdminActiva
}

function sincronizarEstadoLegacyAdmin() {
    adminAutenticado = !!sesionAdminActiva?.autenticado
}

function setSesionAdminActiva(sesion) {
    const usuarioPrevio = String(sesionAdminActiva?.usuario || "").trim().toLowerCase()
    const siguienteSesion = normalizarSesionAdmin(sesion)
    const usuarioNuevo = String(siguienteSesion?.usuario || "").trim().toLowerCase()
    if (usuarioPrevio !== usuarioNuevo) {
        limpiarCurrentProfileVisual()
    }
    sesionAdminActiva = siguienteSesion
    guardarSesionAdminEnStorage()
    sincronizarPermisosPanelInstitucional()
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
    permisosPanelInstitucionalResueltos = false
    limpiarCurrentProfileVisual()
    guardarSesionAdminEnStorage()
    sincronizarEstadoLegacyAdmin()
    if (!logoutInProgress) {
        actualizarInfoSesionHeader()
    }
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

function resolverPerfilActivoId() {
    if (!haySesionAdminActiva() || esSuperusuarioActivo()) return ""
    const sesion = obtenerSesionAdminActiva()
    const usuario = String(sesion.usuario || "").trim().toLowerCase()
    if (!usuario) return ""

    const perfilMapeado = normalizarPerfilId(perfilesUsuariosLocales?.[usuario] || "")
    if (perfilMapeado && obtenerPerfilPorId(perfilMapeado)) {
        return perfilMapeado
    }

    const userLuiz = (usuariosAdminLuiz || []).find(u => String(u.usuario || "").toLowerCase() === usuario)
    const perfilUsuario = normalizarPerfilId(userLuiz?.perfilId || "")
    if (perfilUsuario && obtenerPerfilPorId(perfilUsuario)) {
        return perfilUsuario
    }

    const perfilSesion = normalizarPerfilId(sesion.perfilId || "")
    if (perfilSesion && obtenerPerfilPorId(perfilSesion)) {
        return perfilSesion
    }

    // Fallback por defecto si es administrador institucional y no tiene perfil explícito asignado
    const sesionRol = normalizarRolUsuario(sesion.rol || "")
    if (sesionRol === ROLES_ADMIN.ADMINISTRADOR) {
        if (obtenerPerfilPorId("administrador")) {
            return "administrador"
        }
    }

    return ""
}

function sincronizarPermisosPanelInstitucional() {
    if (!haySesionAdminActiva()) {
        permisosPanelInstitucionalResueltos = false
        return false
    }
    if (esSuperusuarioActivo()) {
        permisosPanelInstitucionalResueltos = true
        return true
    }

    const perfilId = resolverPerfilActivoId()
    if (!perfilId) {
        permisosPanelInstitucionalResueltos = false
        return false
    }

    const perfil = obtenerPerfilPorId(perfilId)
    if (!perfil || String(perfil.estado || "activo") !== "activo") {
        permisosPanelInstitucionalResueltos = false
        return false
    }

    if (String(sesionAdminActiva?.perfilId || "") !== perfilId) {
        actualizarSesionAdmin({ perfilId })
    }
    permisosPanelInstitucionalResueltos = true
    return true
}

function obtenerPerfilUsuarioActivo() {
    if (!haySesionAdminActiva()) return null
    if (esSuperusuarioActivo()) return null
    const perfilId = resolverPerfilActivoId()
    if (!perfilId) return null
    return obtenerPerfilPorId(perfilId) || null
}

function usuarioPuedeVerVista(vista) {
    const key = String(vista || "").trim()
    if (!key) return true
    if (esSuperusuarioActivo()) return true
    if (!permisosPanelInstitucionalResueltos) return key === "dashboard"
    const perfil = obtenerPerfilUsuarioActivo()
    if (!perfil || String(perfil.estado || "activo") !== "activo") return key === "dashboard"
    const permisos = normalizarPermisosPerfil(perfil.permisos || {})
    if (!(key in permisos)) return true
    return !!permisos[key]
}

function aplicarPermisosVistasPorPerfil(vista) {
    if (!esSuperusuarioActivo() && !permisosPanelInstitucionalResueltos) return "dashboard"
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
    const perfilesActivos = (perfilesLuiz || [])
        .filter(p => p.estado === "activo")
        .sort((a, b) => String(a.nombre || "").localeCompare(String(b.nombre || "")))
    const html = perfilesActivos
        .map(p => `<option value="${p.id}">${p.nombre}</option>`)
        .join("")
    el.innerHTML = html
    el.value = perfilesActivos.some(p => p.id === prev) ? prev : "administrador"
}

function actualizarBotonCuentaSidebar() {
    // Obsoleto: el acceso a cuenta ahora está unificado en el header
}

function renderCuentaModalDetalle() {
    if (!cuentaModalBody) return
    if (!haySesionAdminActiva()) {
        cuentaModalBody.innerHTML = `<p class="hint">Sin sesión activa.</p>`
        return
    }

    const sesion = obtenerSesionAdminActiva()
    const datosSesion = resolverDatosVisualesSesionActual()
    const usuario = String(datosSesion.usuario || sesion.usuario || "").trim() || "-"
    const nombre = String(datosSesion.nombreCompleto || usuario).trim() || usuario
    const rolUI = obtenerNombreRolUI(datosSesion.rolTecnico || sesion.rol)
    const tenantUI = datosSesion.tenantNombre || obtenerNombreTenantUI(sesion.tenantId)
    const perfilUI = datosSesion.perfilFuncional || (esSuperusuarioActivo()
        ? "Acceso total"
        : (obtenerPerfilUsuarioActivo()?.nombre || "Administrador"))

    cuentaModalBody.innerHTML = `
    <div style="text-align:center; margin-bottom: 20px;">
        <div style="width: 60px; height: 60px; background: #f0f4ff; color: #2563eb; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 10px; font-size: 24px; font-weight: 700;">
            ${nombre.charAt(0).toUpperCase()}
        </div>
        <h4 style="margin:0; font-size: 16px; color: #1d1d1f;">${nombre}</h4>
        ${nombre !== usuario ? `<p style="margin:2px 0 0; font-size: 13px; color: #86868b;">${usuario}</p>` : ""}
    </div>

    <div class="cuenta-row">
      <span class="cuenta-key">🔐 Rol Técnico</span>
      <span class="cuenta-value">${rolUI}</span>
    </div>
    <div class="cuenta-row">
      <span class="cuenta-key">🛡️ Perfil Funcional</span>
      <span class="cuenta-value">${perfilUI}</span>
    </div>
    <div class="cuenta-row">
      <span class="cuenta-key">🏢 Institución</span>
      <span class="cuenta-value">${tenantUI}</span>
    </div>

    <div class="cuenta-separator"></div>

    <button id="btnCuentaLogout" class="cuenta-logout-btn" onclick="logout()">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
        Cerrar sesión
    </button>
  `
    enlazarAccionesCuentaHeader()
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
    renderCurrentUserInfo()
    enlazarAccionesCuentaHeader()
    actualizarBotonCuentaSidebar()
    if (cuentaModal?.style?.display === "flex") {
        renderCuentaModalDetalle()
    }
}

function loginExitoso(sesion) {
    if (!sesion) return
    adminAutenticado = true
    guardarSesionAdminEnStorage(sesion)
    renderAdminView()
}

function actualizarInfoSesionHeader() {
    renderInfoSesionHeader()
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
        authUserId: String(u?.auth_user_id || "").trim(),
        estado: u?.activo === false ? "inactivo" : "activo",
        fecha_creacion: String(u?.created_at || u?.fecha_creacion || new Date().toISOString()),
        perfilId: resolverPerfilUsuario(u?.usuario, u?.perfil_id || "")
    }
}

async function cargarUsuariosLuizDesdeSupabase() {
    if (!haySupabase()) return null
    if (soporteUsuariosLuizSupabase === false) return null
    let data = []
    let error = null

        ; ({ data, error } = await supabaseClient
            .from("usuarios_admin")
            .select("id,nombre,nombres,apellidos,dni,correo,celular,usuario,clave,rol,activo,tenant_id,auth_user_id")
            .order("id", { ascending: true }))

    if (error && /(nombres|apellidos|dni|correo|celular|auth_user_id)/i.test(String(error.message || ""))) {
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
            celular: "",
            auth_user_id: null
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
            tenant_id: null,
            auth_user_id: null
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
    return hidratarUsuariosLuizConPerfiles((data || []).map(mapearUsuarioLuizDesdeSupabase))
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
            authUserId: String(u.authUserId || u.auth_user_id || "").trim(),
            estado: String(u.estado || "activo") === "inactivo" ? "inactivo" : "activo",
            fecha_creacion: u.fecha_creacion || new Date().toISOString(),
            perfilId: resolverPerfilUsuario(u.usuario, u.perfilId || "")
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
    usuariosAdminLuiz = hidratarUsuariosLuizConPerfiles(usuariosAdminLuiz).map(u => {
        if (normalizarRolUsuario(u.rol) !== ROLES_ADMIN.ADMINISTRADOR) return u
        const perfil = normalizarPerfilId(u.perfilId || "")
        if (perfil && obtenerPerfilPorId(perfil)) return u
        return Object.assign({}, u, { perfilId: "administrador" })
    })
    sincronizarPermisosPanelInstitucional()
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
    const slug = String(tenantId || "").trim().toLowerCase()
    return institucionesLuiz.find(x => String(x.slug || "").trim().toLowerCase() === slug)
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
        const institucionesActivas = institucionesLuiz.filter(i => i.estado === "activo" && String(i.slug || "").toLowerCase() !== "esbas-24-demo")
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
        tablaInst.innerHTML = buildEmptyTableRow(
            5,
            "Sin instituciones",
            "Todavia no hay instituciones registradas en la plataforma.",
            "🏢"
        )
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

    // --- BLOQUE 1: USUARIOS GLOBALES ---
    const searchGlobal = String(document.getElementById("inputBusquedaGlobal")?.value || "").toLowerCase()

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

    const usuariosGlobalesRaw = usuariosGlobalesLocales.concat(usuariosGlobalesSupabase)
    const usuariosGlobales = usuariosGlobalesRaw.filter(({ u }) => {
        const full = `${u.nombres} ${u.apellidos} ${u.usuario}`.toLowerCase()
        return !searchGlobal || full.includes(searchGlobal)
    })

    const elContadorGlobal = document.getElementById("contadorGlobal")
    if (elContadorGlobal) elContadorGlobal.innerText = `Mostrando ${usuariosGlobales.length} usuarios globales`

    if (!usuariosGlobales.length) {
        tablaGlobal.innerHTML = buildEmptyTableRow(
            5,
            "Sin usuarios globales",
            "No se encontraron cuentas globales para mostrar en este momento.",
            "👥"
        )
    } else {
        let globalHtml = ""
        usuariosGlobales.forEach(({ u, idx, source }) => {
            const estadoUser = u.estado === "activo"
            const fechaUser = String(u.fecha_creacion || "").slice(0, 10)
            const protegido = esUsuarioProtegidoLuiz(u.usuario)
            const esSupabase = source === "supabase"
            const rowId = `global-user-${idx}-${source}`

            globalHtml += `
        <tr class="user-row" onclick="toggleDetallesUsuario('${rowId}')">
          <td>${u.usuario || ""}${protegido ? ` <span class="tag-system">PROTEGIDO</span>` : ""}${esSupabase ? ` <span class="tag-system">SUPABASE</span>` : ""}</td>
          <td>${u.nombres || u.nombre || ""} ${u.apellidos || ""}</td>
          <td>${renderBadgePerfil(normalizarRolUsuario(u.rol))}</td>
          <td>${renderBadgeEstado(estadoUser)}</td>
          <td>
            <div class="user-actions">
               <button class="btn-action btn-details">Ver detalles</button>
            </div>
          </td>
        </tr>
        <tr id="${rowId}" class="user-details-row">
          <td colspan="5">
            <div class="user-details-content">
              <div class="detail-item">
                <span class="detail-label">DNI</span>
                <span class="detail-value">${u.dni || "-"}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">Correo</span>
                <span class="detail-value">${u.correo || "-"}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">Celular</span>
                <span class="detail-value">${u.celular || "-"}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">Rol Técnico</span>
                <span class="detail-value">${normalizarRolUsuario(u.rol)}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">Fecha Creación</span>
                <span class="detail-value">${fechaUser || "-"}</span>
              </div>
              <div class="detail-item" style="grid-column: 1 / -1; margin-top: 10px;">
                <span class="detail-label">Acciones de gestión</span>
                <div class="table-actions luiz-actions" style="margin-top:5px; justify-content: flex-start;">
                   ${protegido
                    ? `
                      <button onclick="event.stopPropagation(); editarUsuarioGlobalLuiz(${idx})">Editar</button>
                      <span class="hint">Protegido</span>
                    `
                    : esSupabase
                        ? `<span class="hint">Gestionado por Supabase</span>`
                        : `
                      <button onclick="event.stopPropagation(); editarUsuarioGlobalLuiz(${idx})">Editar</button>
                      <button class="secondary" onclick="event.stopPropagation(); regenerarClaveUsuarioAdminLuiz(${idx})" title="Regenerar clave temporal">Reset</button>
                      <button
                        class="state-toggle ${estadoUser ? "active" : ""}"
                        onclick="event.stopPropagation(); toggleEstadoUsuarioGlobalLuiz(${idx})"
                        title="${estadoUser ? "Desactivar usuario" : "Activar usuario"}"
                        aria-label="${estadoUser ? "Desactivar usuario" : "Activar usuario"}">
                        <span class="dot"></span>
                      </button>
                      <button class="secondary" onclick="event.stopPropagation(); eliminarUsuarioGlobalLuiz(${idx})">Eliminar</button>
                    `
                }
                </div>
              </div>
            </div>
          </td>
        </tr>
      `
        })
        tablaGlobal.innerHTML = globalHtml
    }

    // --- BLOQUE 2: USUARIOS ADMIN POR INSTITUCIÓN ---
    const searchAdmin = String(document.getElementById("inputBusquedaAdminLuiz")?.value || "").toLowerCase()
    const filterPerfilAdmin = String(document.getElementById("filtroPerfilAdminLuiz")?.value || "todos").toLowerCase()

    const usuariosInstitucionalesRaw = (usuariosAdminLuiz || [])
        .map((u, idx) => ({ u, idx }))
        .filter(({ u }) => esUsuarioInstitucionalLuiz(u))

    const usuariosInstitucionales = usuariosInstitucionalesRaw.filter(({ u }) => {
        const full = `${u.nombres} ${u.apellidos} ${u.usuario}`.toLowerCase()
        const matchesSearch = !searchAdmin || full.includes(searchAdmin)

        const perfilId = String(u.perfilId || "administrador").toLowerCase()
        let matchesPerfil = true
        if (filterPerfilAdmin !== "todos") {
            matchesPerfil = perfilId.includes(filterPerfil)
        }

        return matchesSearch && matchesPerfil
    })

    const elContadorAdminLuiz = document.getElementById("contadorAdminLuiz")
    if (elContadorAdminLuiz) elContadorAdminLuiz.innerText = `Mostrando ${usuariosInstitucionales.length} usuarios`

    if (!usuariosInstitucionales.length) {
        tablaUsers.innerHTML = buildEmptyTableRow(
            6,
            "Sin usuarios institucionales",
            "No se encontraron usuarios administradores por institucion.",
            "👤"
        )
    } else {
        let usersHtml = ""
        usuariosInstitucionales.forEach(({ u, idx }) => {
            const inst = obtenerInstitucionLuiz(u.tenantId)
            const instNombre = inst?.nombre || u.tenantId || "-"
            const estadoUser = u.estado === "activo"
            const fechaUser = String(u.fecha_creacion || "").slice(0, 10)
            const protegido = esUsuarioProtegidoLuiz(u.usuario)
            const perfilId = u.perfilId || "administrador"
            const perfilNombre = obtenerPerfilPorId(perfilId)?.nombre || "Administrador"
            const rowId = `luiz-inst-user-${idx}`

            usersHtml += `
        <tr class="user-row" onclick="toggleDetallesUsuario('${rowId}')">
          <td>${u.usuario || ""}${protegido ? ` <span class="tag-system">PROTEGIDO</span>` : ""}</td>
          <td>${u.nombres || u.nombre || ""} ${u.apellidos || ""}</td>
          <td>${instNombre}</td>
          <td>${renderBadgePerfil(perfilId)}</td>
          <td>${renderBadgeEstado(estadoUser)}</td>
          <td>
            <div class="user-actions">
               <button class="btn-action btn-details">Ver detalles</button>
            </div>
          </td>
        </tr>
        <tr id="${rowId}" class="user-details-row">
          <td colspan="6">
            <div class="user-details-content">
              <div class="detail-item">
                <span class="detail-label">DNI</span>
                <span class="detail-value">${u.dni || "-"}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">Correo</span>
                <span class="detail-value">${u.correo || "-"}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">Celular</span>
                <span class="detail-value">${u.celular || "-"}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">Rol Técnico</span>
                <span class="detail-value">${u.rol || ""}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">Fecha Creación</span>
                <span class="detail-value">${fechaUser || "-"}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">Estado Institución</span>
                <span class="detail-value">${inst?.estado === "activo" ? "Activa" : "Inactiva"}</span>
              </div>
              <div class="detail-item" style="grid-column: 1 / -1; margin-top: 10px;">
                <span class="detail-label">Acciones de gestión</span>
                <div class="table-actions luiz-actions" style="margin-top:5px; justify-content: flex-start;">
                   ${protegido
                    ? `<span class="hint">Protegido</span>`
                    : `
                      <button onclick="event.stopPropagation(); editarUsuarioAdminLuiz(${idx})">Editar</button>
                      <button class="secondary" onclick="event.stopPropagation(); regenerarClaveUsuarioAdminLuiz(${idx})" title="Regenerar clave temporal">Reset</button>
                      <button
                        class="state-toggle ${estadoUser ? "active" : ""}"
                        onclick="event.stopPropagation(); toggleEstadoUsuarioAdminLuiz(${idx})"
                        title="${estadoUser ? "Desactivar usuario" : "Activar usuario"}"
                        aria-label="${estadoUser ? "Desactivar usuario" : "Activar usuario"}">
                        <span class="dot"></span>
                      </button>
                      <button class="secondary" onclick="event.stopPropagation(); eliminarUsuarioAdminLuiz(${idx})">Eliminar</button>
                    `
                }
                </div>
              </div>
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
            tablaPerfiles.innerHTML = buildEmptyTableRow(
                5,
                "Sin perfiles de acceso",
                "Aun no hay perfiles creados para esta vista de gestion.",
                "🛡️"
            )
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
    if (!esModoStaff) return false
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
    window.location.href = obtenerRutaTenantBackoffice(slug)
}

async function copiarEnlaceInstitucionLuizLabs(slug) {
    if (!puedeEntrarPanelLuizLabs()) return
    const ruta = obtenerRutaTenantBackoffice(slug)
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

function actualizarBotonCopiado(btnId) {
    const btn = document.getElementById(btnId)
    if (!btn) return
    const span = btn.querySelector("span")
    if (!span) return
    const originalText = span.innerText
    span.innerText = "Copiado ✓"
    btn.classList.add("btn-copied")
    setTimeout(() => {
        span.innerText = originalText
        btn.classList.remove("btn-copied")
    }, 1500)
}

function generarClaveUsuarioAdmin() {
    const pass = Math.random().toString(36).slice(-8)
    if (userPass) {
        userPass.value = pass
        userPass.type = "text"
    }
}

async function copiarClaveUsuarioAdmin() {
    const pass = String(userPass?.value || "").trim()
    if (!pass) return
    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(pass)
            actualizarBotonCopiado("btnCopiarClaveAdmin")
            return
        }
    } catch (e) {
        console.warn(e)
    }
    window.prompt("Copia la clave:", pass)
}

function limpiarUsuarioGlobalLuizForm() {
    if (luizGlobalNombres) luizGlobalNombres.value = ""
    if (luizGlobalApellidos) luizGlobalApellidos.value = ""
    if (luizGlobalDni) luizGlobalDni.value = ""
    if (luizGlobalCorreo) luizGlobalCorreo.value = ""
    if (luizGlobalCelular) luizGlobalCelular.value = ""
    if (luizGlobalUserNombre) luizGlobalUserNombre.value = ""
    if (luizGlobalUserPass) luizGlobalUserPass.value = ""
    if (luizGlobalUserRol) luizGlobalUserRol.value = "superusuario"
    editUsuarioGlobalLuizIndex = null

    // UI Reset
    const card = document.getElementById("formUsuarioGlobalLuiz")
    if (card) card.classList.remove("edit-mode")
    const badge = document.getElementById("badgeEditUsuarioGlobal")
    if (badge) badge.style.display = "none"
    const sub = document.getElementById("subtituloFormUsuarioGlobal")
    if (sub) sub.innerText = "Define credenciales de superusuario para LuizLabs"
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
    if (!clave) return
    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(clave)
            actualizarBotonCopiado("btnCopiarClaveGlobal")
            return
        }
    } catch (e) {
        console.warn("No se pudo copiar clave global:", e)
    }
    const soporte = window.prompt("Copia esta clave:", clave)
    if (soporte !== null) {
        // alert ya no es necesario con el feedback visual
    }
}

function editarUsuarioGlobalLuiz(idx) {
    if (!puedeEntrarPanelLuizLabs()) return
    const u = (usuariosAdminLuiz || [])[idx]
    if (!u || !esUsuarioGlobalAsistIA(u)) return
    const protegidoEditable = esUsuarioProtegidoLuiz(u.usuario) && puedeEditarDatosUsuarioProtegido(u)
    if (esUsuarioProtegidoLuiz(u.usuario) && !protegidoEditable) {
        alert("Usuario protegido.")
        return
    }

    if (luizGlobalNombres) luizGlobalNombres.value = u.nombres || u.nombre || ""
    if (luizGlobalApellidos) luizGlobalApellidos.value = u.apellidos || ""
    if (luizGlobalDni) luizGlobalDni.value = u.dni || ""
    if (luizGlobalCorreo) luizGlobalCorreo.value = u.correo || ""
    if (luizGlobalCelular) luizGlobalCelular.value = u.celular || ""
    if (luizGlobalUserNombre) luizGlobalUserNombre.value = u.usuario || ""
    if (luizGlobalUserPass) luizGlobalUserPass.value = obtenerClaveUsuario(u)
    if (luizGlobalUserRol) luizGlobalUserRol.value = normalizarRolUsuario(u.rol)
    editUsuarioGlobalLuizIndex = idx

    // UI Edit Mode
    const card = document.getElementById("formUsuarioGlobalLuiz")
    if (card) card.classList.add("edit-mode")
    const badge = document.getElementById("badgeEditUsuarioGlobal")
    if (badge) badge.style.display = "inline-block"
    const sub = document.getElementById("subtituloFormUsuarioGlobal")
    if (sub) sub.innerText = `Modificando datos de superusuario: ${u.usuario}`
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
    const usuarioActualEdicion = editUsuarioGlobalLuizIndex !== null
        ? String(usuariosAdminLuiz?.[editUsuarioGlobalLuizIndex]?.usuario || "").toLowerCase()
        : ""
    const usuarioSupabase = (usuariosAdmin || []).some(u => {
        const userDb = String(u.usuario || "").toLowerCase()
        if (editUsuarioGlobalLuizIndex !== null && userDb === usuarioActualEdicion) {
            return false
        }
        return userDb === usuario
    })
    if (usuarioSupabase) {
        alert("Ese usuario ya existe en el panel de usuarios.")
        return
    }

    let accion = "usuario_global_creado"
    if (editUsuarioGlobalLuizIndex !== null) {
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
    if (luizUserNombres) luizUserNombres.value = ""
    if (luizUserApellidos) luizUserApellidos.value = ""
    if (luizUserDni) luizUserDni.value = ""
    if (luizUserCorreo) luizUserCorreo.value = ""
    if (luizUserCelular) luizUserCelular.value = ""
    if (luizUserNombre) luizUserNombre.value = ""
    if (luizUserPass) luizUserPass.value = ""
    if (luizUserTenant) luizUserTenant.value = ""
    if (luizUserRol) luizUserRol.value = "administrador"
    if (luizUserPerfil) luizUserPerfil.value = "administrador"
    editUsuarioAdminLuizIndex = null

    // UI Reset
    const card = document.getElementById("formUsuarioAdminLuiz")
    if (card) card.classList.remove("edit-mode")
    const badge = document.getElementById("badgeEditUsuarioAdminLuiz")
    if (badge) badge.style.display = "none"
    const sub = document.getElementById("subtituloFormUsuarioAdminLuiz")
    if (sub) sub.innerText = "Asigna un administrador a una institución específica"
}

function cancelarEdicionUsuarioAdminLuiz() {
    limpiarUsuarioAdminLuizForm()
}

function generarClaveUsuarioLuiz() {
    const pass = Math.random().toString(36).slice(-8)
    if (luizUserPass) {
        luizUserPass.value = pass
        luizUserPass.type = "text"
    }
}

async function copiarClaveUsuarioLuiz() {
    const clave = String(luizUserPass?.value || "").trim()
    if (!clave) return
    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(clave)
            actualizarBotonCopiado("btnCopiarClaveLuiz")
            return
        }
    } catch (e) {
        console.warn(e)
    }
    window.prompt("Copia la clave:", clave)
}

function editarUsuarioAdminLuiz(idx) {
    if (!puedeEntrarPanelLuizLabs()) return
    const u = (usuariosAdminLuiz || [])[idx]
    if (!u) return
    if (!esUsuarioInstitucionalLuiz(u)) return
    if (esUsuarioProtegidoLuiz(u.usuario)) {
        alert("El usuario legacy está protegido y no se edita desde este módulo.")
        return
    }

    if (luizUserNombres) luizUserNombres.value = u.nombres || u.nombre || ""
    if (luizUserApellidos) luizUserApellidos.value = u.apellidos || ""
    if (luizUserDni) luizUserDni.value = u.dni || ""
    if (luizUserCorreo) luizUserCorreo.value = u.correo || ""
    if (luizUserCelular) luizUserCelular.value = u.celular || ""
    if (luizUserNombre) luizUserNombre.value = u.usuario || ""
    if (luizUserPass) luizUserPass.value = obtenerClaveUsuario(u)
    if (luizUserTenant) luizUserTenant.value = u.tenantId || ""
    if (luizUserRol) luizUserRol.value = normalizarRolUsuario(u.rol)
    if (luizUserPerfil) luizUserPerfil.value = u.perfilId || "administrador"
    editUsuarioAdminLuizIndex = idx

    // UI Edit Mode
    const card = document.getElementById("formUsuarioAdminLuiz")
    if (card) card.classList.add("edit-mode")
    const badge = document.getElementById("badgeEditUsuarioAdminLuiz")
    if (badge) badge.style.display = "inline-block"
    const sub = document.getElementById("subtituloFormUsuarioAdminLuiz")
    if (sub) sub.innerText = `Modificando datos de: ${u.usuario}`
}

async function guardarUsuarioAdminLuiz() {
    if (!puedeEntrarPanelLuizLabs()) return
    const actual = editUsuarioAdminLuizIndex !== null ? usuariosAdminLuiz[editUsuarioAdminLuizIndex] : null
    const esEdicion = editUsuarioAdminLuizIndex !== null
    const previousUsuario = String(actual?.usuario || "").trim().toLowerCase()
    const claveOriginal = obtenerClaveUsuario(actual)
    const nombres = obtenerValorEdicion(luizUserNombres?.value, actual?.nombres || actual?.nombre)
    const apellidos = obtenerValorEdicion(luizUserApellidos?.value, actual?.apellidos)
    const dni = obtenerValorEdicion(luizUserDni?.value, actual?.dni, value => String(value || "").replace(/\D/g, ""))
    const correo = obtenerValorEdicion(luizUserCorreo?.value, actual?.correo, value => String(value || "").trim().toLowerCase())
    const celular = obtenerValorEdicion(luizUserCelular?.value, actual?.celular, value => String(value || "").replace(/\D/g, ""))
    const usuario = obtenerValorEdicion(luizUserNombre?.value, actual?.usuario, value => String(value || "").trim().toLowerCase())
    const rol = normalizarRolUsuario(luizUserRol?.value || actual?.rol || ROLES_ADMIN.ADMINISTRADOR)
    const tenantId = obtenerValorEdicion(luizUserTenant?.value, actual?.tenantId)
    const passwordIngresado = String(luizUserPass?.value || "").trim()
    const password = passwordIngresado || claveOriginal
    const perfilId = normalizarPerfilId(luizUserPerfil?.value || actual?.perfilId || "administrador") || "administrador"

    if (!nombres || !apellidos || !dni || !usuario || !tenantId || (!esEdicion && !password)) {
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
    const usuarioActualEdicion = editUsuarioAdminLuizIndex !== null
        ? String(usuariosAdminLuiz?.[editUsuarioAdminLuizIndex]?.usuario || "").toLowerCase()
        : ""
    const usuarioSupabase = (usuariosAdmin || []).some(u => {
        const userDb = String(u.usuario || "").toLowerCase()
        if (editUsuarioAdminLuizIndex !== null && userDb === usuarioActualEdicion) {
            return false
        }
        return userDb === usuario
    })
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
    if (esEdicion) {
        if (!actual) {
            limpiarUsuarioAdminLuizForm()
            return
        }
        if (esUsuarioProtegidoLuiz(actual.usuario)) {
            alert("El usuario legacy está protegido.")
            limpiarUsuarioAdminLuizForm()
            return
        }

        const duplicado = usuariosAdminLuiz.some((u, i) => i !== editUsuarioAdminLuizIndex && u.usuario === usuario)
        if (duplicado) {
            alert("Ya existe un usuario con ese nombre.")
            return
        }
        accion = "usuario_admin_luiz_editado"
    } else {
        const existe = usuariosAdminLuiz.some(u => u.usuario === usuario)
        if (existe) {
            alert("Ese usuario ya existe.")
            return
        }
    }

    try {
        const cambioClaveReal = !!passwordIngresado && passwordIngresado !== claveOriginal
        if (!esEdicion || cambioClaveReal) {
            if (!await tieneSesionSupabaseActiva()) {
                alert(esEdicion
                    ? "Para cambiar la clave de este usuario debes iniciar sesión institucional con JWT activo."
                    : "Para crear usuarios desde este módulo debes iniciar sesión institucional con JWT activo.")
                return
            }
            await provisionarUsuarioAdminSeguro({
                usuario,
                clave: password,
                correo,
                tenant_id: tenantId,
                rol,
                nombres,
                apellidos,
                dni,
                celular,
                perfil_id: perfilId,
                previous_usuario: previousUsuario,
                activo: true
            })
        } else {
            await actualizarUsuarioAdminExistenteEnSupabase({
                usuario,
                clave: password,
                correo,
                tenant_id: tenantId,
                rol,
                nombres,
                apellidos,
                dni,
                celular,
                perfil_id: perfilId,
                previous_usuario: previousUsuario,
                activo: true
            })
        }
    } catch (error) {
        if (error?.message === "SESSION_EXPIRED") return
        alert(`No se pudo provisionar usuario: ${error.message}`)
        return
    }

    const draftUser = {
        nombres,
        apellidos,
        dni,
        correo: normalizarCorreoProvisionAdmin(usuario, correo),
        celular,
        usuario,
        password,
        rol,
        tenantId,
        perfilId,
        estado: "activo",
        fecha_creacion: actual?.fecha_creacion || new Date().toISOString()
    }

    if (esEdicion) {
        usuariosAdminLuiz[editUsuarioAdminLuizIndex] = draftUser
    } else {
        usuariosAdminLuiz.push(draftUser)
    }

    if (previousUsuario && previousUsuario !== usuario) {
        delete perfilesUsuariosLocales[previousUsuario]
    }
    perfilesUsuariosLocales[usuario] = perfilId
    sincronizarPermisosPanelInstitucional()
    guardarLuizLabsEnStorage()
    await cargarUsuariosAdminDesdeSupabase()
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
    const permisosResueltos = sincronizarPermisosPanelInstitucional()
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

    if (navReportes) navReportes.style.display = permisosResueltos && puedeReportes ? "" : "none"
    if (navDashboard) navDashboard.style.display = permisosResueltos && puedeDashboard ? "" : "none"
    if (navConfig) navConfig.style.display = permisosResueltos && (!limitado && puedeConfig) ? "" : "none"
    if (navUsuarios) navUsuarios.style.display = permisosResueltos && (!limitado && puedeUsuarios) ? "" : "none"
    if (navActividad) navActividad.style.display = permisosResueltos && (!limitado && puedeActividad) ? "" : "none"
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
    if (!permisosResueltos && !esSuperusuarioActivo()) {
        if (vistaAdminActual !== "dashboard") {
            mostrarVista("dashboard")
        }
        return
    }
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

function resolverRutaPublicaModerna() {
    const path = normalizarPathname(window.location.pathname)
    const segments = path.replace(/^\/|\/$/g, "").split("/").filter(Boolean)
    const slug = String(segments[0] || "").trim().toLowerCase()
    const subruta = String(segments[1] || "").trim().toLowerCase()

    if (!slug || !esSlugTenantRuteable(slug)) return null
    if (subruta !== "asistencia" && subruta !== "staff-asistencia") return null

    const params = new URLSearchParams(window.location.search || "")
    if (!params.get("tenant")) {
        params.set("tenant", slug)
    }

    const destinoBase = subruta === "staff-asistencia"
        ? "/staff-asistencia/index.html"
        : "/asistencia/index.html"
    const qs = params.toString()
    return qs ? `${destinoBase}?${qs}` : destinoBase
}

function redirigirRutaPublicaModernaSiCorresponde() {
    const destino = resolverRutaPublicaModerna()
    if (!destino) return false
    window.location.replace(destino)
    return true
}

function esSlugTenantRuteable(slug) {
    const limpio = String(slug || "").trim().toLowerCase()
    if (!limpio) return false
    if (!/^[a-z0-9][a-z0-9-]*$/i.test(limpio)) return false
    return !["asistencia", "staff-asistencia", "backoffice", "index.html"].includes(limpio)
}

function construirTenantProvisional(slug) {
    const limpio = String(slug || "").trim().toLowerCase()
    if (!esSlugTenantRuteable(limpio)) return null

    const institucion = obtenerInstitucionLuiz(limpio)
    return {
        id: limpio,
        nombre: institucion?.nombre || limpio,
        linea: "Módulo institucional",
        curso: "Instrucción asistIA",
        logo: obtenerLogoInstitucion(institucion),
        habilitado: institucion ? institucion.estado === "activo" : true,
        usuariosSistema: []
    }
}

function asegurarTenantDisponible(id) {
    const limpio = String(id || "").trim().toLowerCase()
    if (!esSlugTenantRuteable(limpio)) return null
    if (!TENANTS[limpio]) {
        const provisional = construirTenantProvisional(limpio)
        if (!provisional) return null
        TENANTS[limpio] = provisional
    }
    return TENANTS[limpio] || null
}

function obtenerRutaTenant(id) {
    const clean = String(id || "").trim().replace(/^\/+|\/+$/g, "")
    return clean ? `/${clean}/` : "/"
}

function obtenerRutaTenantBackoffice(id) {
    const clean = String(id || "").trim().replace(/^\/+|\/+$/g, "")
    return clean ? `/${clean}/backoffice/` : "/"
}

function resolverAccesoDesdeRuta() {
    const path = normalizarPathname(window.location.pathname)
    if (path !== "/") {
        const segments = path.replace(/^\/|\/$/g, "").split("/").filter(Boolean)
        const slug = String(segments[0] || "").trim()
        const subruta = String(segments[1] || "").trim().toLowerCase()
        const tenant = asegurarTenantDisponible(slug)
        if (tenant && (!subruta || subruta === "backoffice")) {
            return { staff: false, tenantId: tenant.id }
        }
    }
    return { staff: true, tenantId: "" }
}

function redirigirRutaPublicaLegadaCurso() {
    const path = normalizarPathname(window.location.pathname)
    const params = new URLSearchParams(window.location.search || "")
    const cursoToken = String(params.get("curso") || "").trim()
    if (!cursoToken) return false
    if (path === "/" || /\/asistencia\/|\/backoffice\//i.test(path)) return false

    const slug = path.replace(/^\/|\/$/g, "")
    if (!esSlugTenantRuteable(slug)) return false
    asegurarTenantDisponible(slug)

    const destino = `/${slug}/asistencia/${window.location.search || ""}`
    window.location.replace(destino)
    return true
}

function redirigirRutaBackofficeLegada() {
    const path = normalizarPathname(window.location.pathname)
    if (path === "/" || /\/asistencia\/|\/backoffice\//i.test(path)) return false

    const slug = path.replace(/^\/|\/$/g, "")
    if (!esSlugTenantRuteable(slug)) return false
    asegurarTenantDisponible(slug)

    window.location.replace(obtenerRutaTenantBackoffice(slug))
    return true
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
    return id ? asegurarTenantDisponible(id) : null
}

function asignarTenantActivo(id) {
    tenantActivoId = String(id || "").trim().toLowerCase()
    if (tenantActivoId) {
        asegurarTenantDisponible(tenantActivoId)
    }
    aplicarTenantEnUI()
    actualizarInfoSesionHeader()
}

function aplicarTenantEnUI() {
    const tenant = obtenerTenantActivo() || primerTenantFallback()
    const titulo = "asistIA"
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
        tenantSubtituloLogin.style.display = "none"
    }
    if (tenantCursoLogin) {
        tenantCursoLogin.innerText = curso
        tenantCursoLogin.style.display = "none"
    }
    if (tenantCardTituloLogin) tenantCardTituloLogin.innerText = tituloCard
    if (loginCardCaption) {
        loginCardCaption.innerText = "Control Inteligente de Asistencia"
        loginCardCaption.style.display = esModoStaff ? "none" : "block"
    }

    if (tenantPanelTitulo) tenantPanelTitulo.innerText = `asistIA Panel Administrativo - ${titulo}`
    if (tenantLogoLoginCard) tenantLogoLoginCard.src = logoRuta
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
    window.location.href = obtenerRutaTenantBackoffice(id)
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
    const tid = normalizarTenantId(tenantActivoId)
    if (esTenantConDatosLegacy(tid)) {
        return query.or(`tenant_id.eq.${tid},tenant_id.is.null`)
    }
    return query.eq("tenant_id", tid)
}

function withTenantPayload(payload) {
    if (!MULTITENANT_MODE || !tenantActivoId) return payload
    const tid = normalizarTenantId(tenantActivoId)
    return Object.assign({}, payload, { tenant_id: tid })
}

function withTenantPayloadList(items) {
    return (items || []).map(withTenantPayload)
}

function filtrarDataTenantActivo(rows) {
    if (!MULTITENANT_MODE || !tenantActivoId) {
        return Array.isArray(rows) ? rows : []
    }
    const tenant = normalizarTenantId(tenantActivoId)
    return (rows || []).filter(r => {
        const tenantFila = normalizarTenantId(r?.tenant_id)
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
        "cursos",
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

function normalizarCursoBaseSupabase(row) {
    return {
        id: Number(row?.id || 1) || 1,
        nombre: String(row?.nombre || "").trim(),
        tenant_id: String(row?.tenant_id || "").trim().toLowerCase(),
        estado: String(row?.estado || "activo").trim().toLowerCase(),
        fecha_inicio: row?.fecha_inicio || null,
        fecha_fin: row?.fecha_fin || null,
        qr_token: String(row?.qr_token || "").trim()
    }
}

function normalizarSegmentoQrCurso(value = "") {
    return String(value || "")
        .trim()
        .toLowerCase()
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .replace(/[^a-z0-9]+/g, "")
}

function resolverAnioQrCurso(row = {}) {
    const fecha = String(row?.fecha_inicio || "").trim()
    const fromDate = fecha.match(/^(\d{4})-/)?.[1]
    if (fromDate) return fromDate
    return String(new Date().getFullYear())
}

function generarQrTokenCurso(tenantId = "", row = {}) {
    const tenant = normalizarSegmentoQrCurso(tenantId || row?.tenant_id || tenantActivoId) || "tenant"
    const year = resolverAnioQrCurso(row)
    const randomLeft = Math.random().toString(36).slice(2, 4)
    const randomRight = Math.random().toString(36).slice(2, 9)
    return `asistia_${tenant}_${year}_${randomLeft}-${randomRight}`
}

async function asegurarQrTokenCurso(row = null) {
    if (!haySupabase()) return row
    if (soporteCursosSupabase === false) return row

    const base = normalizarCursoBaseSupabase(row || cursoBaseActual || {})
    if (!base?.id || !base?.tenant_id) return row || cursoBaseActual || null
    if (base.qr_token) {
        cursoBaseActual = base
        cursoActualId = base.id || 1
        return base
    }

    const qrToken = generarQrTokenCurso(base.tenant_id, base)
    const { data, error } = await supabaseClient
        .from("cursos")
        .update({ qr_token: qrToken })
        .eq("tenant_id", base.tenant_id)
        .eq("id", base.id)
        .select("id,nombre,tenant_id,estado,fecha_inicio,fecha_fin,qr_token")
        .single()

    if (error) {
        console.warn("No se pudo asegurar qr_token del curso:", error.message || error)
        return base
    }

    cursoBaseActual = normalizarCursoBaseSupabase(data || Object.assign({}, base, { qr_token: qrToken }))
    cursoActualId = cursoBaseActual.id || 1
    return cursoBaseActual
}

async function cargarCursoBaseDesdeSupabase() {
    if (!haySupabase()) return null
    if (soporteCursosSupabase === false) return null

    let q = withTenantScope(
        supabaseClient
            .from("cursos")
            .select("id,nombre,tenant_id,estado,fecha_inicio,fecha_fin,qr_token")
    )

    const { data, error } = await q
        .eq("estado", "activo")
        .order("id", { ascending: true })
        .limit(1)

    if (error) {
        if (esTablaNoExiste(error)) {
            soporteCursosSupabase = false
            return null
        }
        console.warn("No se pudo cargar curso base desde cursos:", error.message)
        return null
    }

    soporteCursosSupabase = true
    const row = Array.isArray(data) ? data[0] : null
    if (!row) return null

    cursoBaseActual = normalizarCursoBaseSupabase(row)
    cursoActualId = cursoBaseActual.id || 1
    return asegurarQrTokenCurso(cursoBaseActual)
}

async function guardarCursoBaseEnSupabase(payload = {}) {
    if (!haySupabase()) return false
    if (soporteCursosSupabase === false) return false

    const qrTokenExistente = String(payload.qr_token || cursoBaseActual?.qr_token || "").trim()
    const payloadCurso = withTenantPayload({
        id: Number(payload.id || cursoActualId || 1) || 1,
        nombre: String(payload.nombre || "").trim() || null,
        fecha_inicio: payload.fecha_inicio || null,
        fecha_fin: payload.fecha_fin || null,
        estado: "activo",
        qr_token: qrTokenExistente || generarQrTokenCurso(tenantActivoId, payload)
    })

    const { data, error } = await supabaseClient
        .from("cursos")
        .upsert(payloadCurso, { onConflict: "tenant_id,id" })
        .select("id,nombre,tenant_id,estado,fecha_inicio,fecha_fin,qr_token")
        .single()

    if (error) {
        if (esTablaNoExiste(error)) {
            soporteCursosSupabase = false
            return false
        }
        console.warn("No se pudo guardar curso base en cursos:", error.message)
        return false
    }

    soporteCursosSupabase = true
    cursoBaseActual = normalizarCursoBaseSupabase(data || payloadCurso)
    cursoActualId = cursoBaseActual.id || 1
    await asegurarQrTokenCurso(cursoBaseActual)
    return true
}

function obtenerCursoTokenDesdeURL() {
    try {
        const params = new URLSearchParams(window.location.search || "")
        return String(params.get("curso") || "").trim()
    } catch (e) {
        return ""
    }
}

function obtenerCursoTokenDesdeTextoQR(raw) {
    const text = String(raw || "").trim()
    if (!text) return ""
    try {
        const url = new URL(text)
        return String(url.searchParams.get("curso") || "").trim()
    } catch (e) {
        const match = text.match(/[?&]curso=([^&#\s]+)/i)
        if (match?.[1]) {
            return decodeURIComponent(String(match[1] || "").trim())
        }
        return ""
    }
}

async function resolverCursoPorToken(token) {
    cursoQRValido = false
    if (!token || !haySupabase()) return false
    if (soporteCursosSupabase === false) return false

    try {
        const tenantLimpio = String(tenantActivoId || "").trim().replace(/\/$/, "")
        const { data, error } = await supabaseClient.rpc("rpc_validar_curso_qr", {
            p_qr_token: token,
            p_tenant_id: tenantLimpio
        })

        if (error) {
            console.warn("No se pudo validar curso por RPC:", error.message)
            cursoQRValido = false
            return false
        }

        if (!data?.success) {
            cursoQRValido = false
            return false
        }

        cursoActualId = Number(data.curso_id || 1) || 1
        cursoQRValido = true
        return true
    } catch (e) {
        console.warn("Error resolviendo curso por token:", e?.message || e)
        cursoQRValido = false
        return false
    }
}

async function resolverCursoDesdeURL() {
    const token = obtenerCursoTokenDesdeURL()
    if (!token) {
        cursoQRValido = false
        return false
    }
    const ok = await resolverCursoPorToken(token)
    if (!ok) {
        console.warn("No se pudo resolver curso desde URL.")
    }
    return ok
}

function obtenerHostPublicoCursoQr() {
    const origin = String(window.location.origin || "").trim()
    if (!origin) return COURSE_QR_BASE_URL
    if (/localhost|127\.0\.0\.1/i.test(origin)) return COURSE_QR_BASE_URL
    return origin.replace(/\/$/, "")
}

function obtenerTokenPersistenteCursoActual() {
    return String(cursoBaseActual?.qr_token || "").trim()
}

function construirUrlPublicaCurso(tipo, token) {
    const tenant = String(tenantActivoId || "").trim().toLowerCase()
    const tokenLimpio = String(token || "").trim()
    if (!tenant || !tokenLimpio) return ""
    const base = obtenerHostPublicoCursoQr()
    const path = tipo === "staff" ? "staff-asistencia" : "asistencia"
    return `${base}/${encodeURIComponent(tenant)}/${path}/?curso=${encodeURIComponent(tokenLimpio)}`
}

function obtenerNodoQrCurso(tipo) {
    return document.getElementById(tipo === "staff" ? "qrStaff" : "qrAspirantes")
}

function obtenerInputUrlQrCurso(tipo) {
    return document.getElementById(tipo === "staff" ? "urlQrStaff" : "urlQrAspirantes")
}

function obtenerUrlCursoQr(tipo) {
    return tipo === "staff" ? cursoQrState.staffUrl : cursoQrState.aspirantesUrl
}

function renderPlaceholderQrCurso(tipo, texto) {
    const mount = obtenerNodoQrCurso(tipo)
    if (!mount) return
    mount.innerHTML = `<p class="course-qr-placeholder">${texto}</p>`
}

function limpiarRenderQrCurso() {
    ;["aspirantes", "staff"].forEach(tipo => {
        const mount = obtenerNodoQrCurso(tipo)
        if (mount) mount.innerHTML = ""
        const input = obtenerInputUrlQrCurso(tipo)
        if (input) input.value = ""
    })
}

function renderQrCursoEnNodo(tipo, url) {
    const mount = obtenerNodoQrCurso(tipo)
    if (!mount) return
    mount.innerHTML = ""
    if (!url) {
        renderPlaceholderQrCurso(tipo, "No se pudo construir la URL pública del curso.")
        return
    }
    if (typeof window.QRCode !== "function") {
        renderPlaceholderQrCurso(tipo, "No se pudo cargar la librería QR en esta sesión.")
        return
    }
    new window.QRCode(mount, {
        text: url,
        width: 220,
        height: 220,
        correctLevel: window.QRCode.CorrectLevel ? window.QRCode.CorrectLevel.M : undefined
    })
}

function renderModuloQrCurso() {
    limpiarRenderQrCurso()
    cursoQrState = {
        token: "",
        aspirantesUrl: "",
        staffUrl: ""
    }

    const token = obtenerTokenPersistenteCursoActual()
    const mensajeId = "msgCursoQr"
    if (!tenantActivoId) {
        mostrarMsgCursoModulo(mensajeId, "No se pudo identificar el tenant activo para construir las URLs públicas.", "warning")
        renderPlaceholderQrCurso("aspirantes", "Tenant no disponible.")
        renderPlaceholderQrCurso("staff", "Tenant no disponible.")
        return
    }
    if (!token) {
        mostrarMsgCursoModulo(
            mensajeId,
            "Este curso aún no tiene qr_token configurado.",
            "warning"
        )
        renderPlaceholderQrCurso("aspirantes", "Este curso aún no tiene qr_token configurado.")
        renderPlaceholderQrCurso("staff", "Este curso aún no tiene qr_token configurado.")
        return
    }

    const aspirantesUrl = construirUrlPublicaCurso("aspirantes", token)
    const staffUrl = construirUrlPublicaCurso("staff", token)
    cursoQrState = {
        token,
        aspirantesUrl,
        staffUrl
    }

    const inputAspirantes = obtenerInputUrlQrCurso("aspirantes")
    const inputStaff = obtenerInputUrlQrCurso("staff")
    if (inputAspirantes) inputAspirantes.value = aspirantesUrl
    if (inputStaff) inputStaff.value = staffUrl

    renderQrCursoEnNodo("aspirantes", aspirantesUrl)
    renderQrCursoEnNodo("staff", staffUrl)
    mostrarMsgCursoModulo(mensajeId, "QRs públicos listos para copiar, descargar o imprimir.", "ok")
}

function obtenerDataUrlQrCurso(tipo) {
    const mount = obtenerNodoQrCurso(tipo)
    if (!mount) return ""
    const canvas = mount.querySelector("canvas")
    if (canvas?.toDataURL) return canvas.toDataURL("image/png")
    const img = mount.querySelector("img")
    return String(img?.src || "")
}

async function copiarUrlCursoQr(tipo) {
    const url = obtenerUrlCursoQr(tipo)
    if (!url) {
        mostrarMsgCursoModulo("msgCursoQr", "No hay URL pública disponible para copiar.", "warning")
        return
    }
    try {
        if (navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(url)
        } else {
            const input = obtenerInputUrlQrCurso(tipo)
            input?.focus()
            input?.select()
            document.execCommand("copy")
        }
        mostrarMsgCursoModulo("msgCursoQr", `URL de ${tipo === "staff" ? "Staff" : "Aspirantes"} copiada al portapapeles.`, "ok")
    } catch (e) {
        mostrarMsgCursoModulo("msgCursoQr", "No se pudo copiar la URL. Intenta copiarla manualmente.", "warning")
    }
}

function descargarQrCurso(tipo) {
    const dataUrl = obtenerDataUrlQrCurso(tipo)
    if (!dataUrl) {
        mostrarMsgCursoModulo("msgCursoQr", "No se pudo generar el PNG del QR.", "warning")
        return
    }
    const tenant = String(tenantActivoId || "tenant").trim().toLowerCase()
    const suffix = tipo === "staff" ? "staff" : "aspirantes"
    const link = document.createElement("a")
    link.href = dataUrl
    link.download = `qr-${tenant}-${suffix}.png`
    document.body.appendChild(link)
    link.click()
    link.remove()
    mostrarMsgCursoModulo("msgCursoQr", `PNG de ${tipo === "staff" ? "Staff" : "Aspirantes"} descargado.`, "ok")
}

function imprimirQrCurso(tipo) {
    const dataUrl = obtenerDataUrlQrCurso(tipo)
    const url = obtenerUrlCursoQr(tipo)
    if (!dataUrl || !url) {
        mostrarMsgCursoModulo("msgCursoQr", "No se pudo preparar la impresión del QR.", "warning")
        return
    }
    const titulo = tipo === "staff" ? "QR Staff" : "QR Aspirantes"
    const win = window.open("", "_blank", "noopener,noreferrer,width=720,height=860")
    if (!win) {
        mostrarMsgCursoModulo("msgCursoQr", "El navegador bloqueó la ventana de impresión.", "warning")
        return
    }
    win.document.write(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>${titulo}</title>
  <style>
    body { font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 32px; color: #172033; }
    .sheet { max-width: 520px; margin: 0 auto; text-align: center; }
    .sheet h1 { font-size: 24px; margin: 0 0 8px; }
    .sheet p { font-size: 13px; line-height: 1.5; color: #52627f; word-break: break-word; }
    .sheet img { width: 280px; height: 280px; display: block; margin: 22px auto; }
  </style>
</head>
<body>
  <div class="sheet">
    <h1>${titulo}</h1>
    <p>${url}</p>
    <img src="${dataUrl}" alt="${titulo}">
  </div>
</body>
</html>`)
    win.document.close()
    win.focus()
    win.print()
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
    setVistaManual("desktop")
    if (!haySesionAdminActiva()) {
        if (!esModoStaff) {
            aplicarLayout()
            return
        }
        if (elTenant) elTenant.style.display = "none"
        if (elLogin) elLogin.style.display = "flex"
        if (elDesktop) elDesktop.style.display = "none"
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
    const elStaffDesde = document.getElementById("staffReporteDesde")
    const elStaffHasta = document.getElementById("staffReporteHasta")
    if (elFechaDesde) elFechaDesde.value = from
    if (elFechaHasta) elFechaHasta.value = to
    if (elDashDesde) elDashDesde.value = from
    if (elDashHasta) elDashHasta.value = to
    if (elStaffDesde) elStaffDesde.value = from
    if (elStaffHasta) elStaffHasta.value = to
}

function mostrarPasoMovil(paso) {
    aplicarVisibilidadAccesoAdminInstitucional()
}

function seleccionarBotonSeccion(valor) {
    document.querySelectorAll(".mobile-section-btn").forEach(btn => {
        btn.classList.toggle("active", btn.dataset.seccion === valor)
    })
}

function setMensaje(texto, tipo = "") {
    if (!mensaje) return
    mensaje.className = ""
    mensaje.innerText = texto || ""
    if (!texto) return
    if (tipo) mensaje.classList.add(tipo)
}

function estaInputDniMovilActivo() {
    return false
}

function hayCampoEditableActivo() {
    const active = document.activeElement
    const tag = String(active?.tagName || "").toUpperCase()
    if (tag === "TEXTAREA" || tag === "SELECT") return true
    if (tag !== "INPUT") return false
    const type = String(active?.type || "").toLowerCase()
    return !["button", "submit", "reset", "checkbox", "radio", "file"].includes(type)
}

function estaEnFlujoMovilPublico() {
    return getVistaActiva() === "mobile" && !puedeEntrarPanelAdmin() && !puedeEntrarPanelLuizLabs()
}

function activarLockInputDniMovil(ms = 450) {
    inputDniFocusLockUntil = Date.now() + ms
}

function liberarLockInputDniMovilConEspera(ms = 180) {
    window.setTimeout(() => {
        inputDniFocusLockUntil = 0
    }, ms)
}

function esDomingoLima(fecha = new Date()) {
    try {
        const weekday = new Intl.DateTimeFormat("en-US", {
            timeZone: "America/Lima",
            weekday: "long"
        }).format(fecha)
        return String(weekday || "").toLowerCase() === "sunday"
    } catch (e) {
        return fecha.getDay() === 0
    }
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

function diasSemanaReglasTexto(dias = []) {
    const mapa = ["Domingo", "Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado"]
    const únicos = Array.from(new Set(
        (Array.isArray(dias) ? dias : [])
            .map(valor => Number(valor))
            .filter(valor => Number.isInteger(valor) && valor >= 0 && valor <= 6)
    ))
    únicos.sort((a, b) => a - b)
    return únicos.map(valor => mapa[valor]).filter(Boolean)
}

function deduplicarSeccionesDesdeReglas(rows = []) {
    const map = new Map()
    rows.forEach(item => {
        const seccion = normalizarCodigoSeccion(item?.seccion)
        if (!seccion) return

        if (!map.has(seccion)) {
            map.set(seccion, {
                seccion,
                modalidad: normalizarModalidad(item?.modalidad || "PRESENCIAL"),
                hora_inicio: item?.hora_inicio || "",
                dias: diasSemanaReglasTexto(item?.dias_semana),
                activa: item?.activa !== false
            })
            return
        }

        const actual = map.get(seccion)
        const dias = Array.from(new Set([...(actual.dias || []), ...diasSemanaReglasTexto(item?.dias_semana)]))
        actual.dias = dias
        actual.activa = actual.activa || item?.activa !== false
        if (!actual.hora_inicio && item?.hora_inicio) actual.hora_inicio = item.hora_inicio
        if (!actual.modalidad && item?.modalidad) actual.modalidad = normalizarModalidad(item.modalidad)
    })

    return Array.from(map.values()).sort((a, b) => {
        const secCmp = String(a.seccion || "").localeCompare(String(b.seccion || ""))
        if (secCmp !== 0) return secCmp
        return String(a.hora_inicio || "").localeCompare(String(b.hora_inicio || ""))
    })
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

function normalizarCodigoSeccion(valor) {
    return String(valor || "").trim().toUpperCase()
}

function esSeccionLegacy(valor) {
    const seccionNormalizada = normalizarCodigoSeccion(valor)
    return seccionNormalizada === "GENERAL" || seccionNormalizada === "DOMINICAL"
}

function normalizarModalidad(valor) {
    const modalidad = String(valor || "").trim().toUpperCase()
    if (modalidad === "VIRTUAL") return "VIRTUAL"
    return modalidad ? "PRESENCIAL" : ""
}

function normalizarTipoJornada(valor) {
    const jornada = String(valor || "").trim().toUpperCase()
    if (jornada === "DOMINICAL" || jornada === "DOMINICAL_GRUPAL") return "DOMINICAL_GRUPAL"
    if (jornada === "SECCION" || jornada === "SECCION_REGULAR") return "SECCION_REGULAR"
    if (jornada === "GENERAL") return "GENERAL_LEGACY"
    return jornada
}

function formatearTipoJornada(valor) {
    const jornada = normalizarTipoJornada(valor)
    if (jornada === "GENERAL_LEGACY") return "GENERAL (legacy)"
    return jornada || "SECCION_REGULAR"
}

function formatearTipoJornadaAmigable(valor) {
    const jornada = normalizarTipoJornada(valor)
    if (jornada === "DOMINICAL_GRUPAL") return "Dominical grupal"
    if (jornada === "SECCION_REGULAR") return "Regular de sección"
    if (jornada === "GENERAL_LEGACY") return "General (legacy)"
    return jornada || "Regular de sección"
}

function formatearModalidadAmigable(valor) {
    const modalidad = normalizarModalidad(valor)
    if (modalidad === "VIRTUAL") return "Virtual"
    if (modalidad === "PRESENCIAL") return "Presencial"
    return ""
}

function formatearSeccionRegistro(seccionValor, jornadaValor) {
    const seccionNormalizada = normalizarCodigoSeccion(seccionValor)
    if (!seccionNormalizada) return "-"
    if (esSeccionLegacy(seccionNormalizada)) {
        return normalizarTipoJornada(jornadaValor) === "DOMINICAL_GRUPAL"
            ? `${seccionNormalizada} (legacy dominical)`
            : `${seccionNormalizada} (legacy)`
    }
    return seccionNormalizada
}

function obtenerSeccionAspiranteDetectada() {
    return esSeccionLegacy(perfilAspiranteActual?.seccion) ? "" : normalizarCodigoSeccion(perfilAspiranteActual?.seccion)
}

function resolverContextoAsistencia(fecha = new Date(), seccionRegistro = "") {
    const esDomingo = esDomingoLima(fecha)
    const seccionReal = normalizarCodigoSeccion(seccionRegistro)
    const regla = obtenerReglaSeccion(seccionReal)
    return {
        esDomingo,
        seccion: seccionReal,
        tipo_jornada: esDomingo ? "DOMINICAL_GRUPAL" : "SECCION_REGULAR",
        modalidad: esDomingo ? "PRESENCIAL" : normalizarModalidad(regla?.modalidad),
        jornada_label: esDomingo ? "DOMINICAL_GRUPAL" : "SECCION_REGULAR"
    }
}

function resolverModalidadRegistro(row = {}) {
    const modalidadActual = normalizarModalidad(row.modalidad || "")
    if (modalidadActual) return modalidadActual
    const jornada = normalizarTipoJornada(row.tipo_jornada || row.jornada || "")
    if (jornada === "DOMINICAL_GRUPAL") return "PRESENCIAL"
    const regla = obtenerReglaSeccion(row.seccion || "")
    return normalizarModalidad(regla?.modalidad)
}

function normalizarEstadoAsistencia(valor) {
    const estado = String(valor || "").trim().toUpperCase()
    if (estado === "PUNTUAL") return "PUNTUAL"
    if (estado === "TARDANZA") return "TARDANZA"
    if (estado === "FUERA_DE_HORARIO") return "FUERA_DE_HORARIO"
    return ""
}

function formatearEstadoAsistenciaDashboard(valor) {
    const estado = normalizarEstadoAsistencia(valor)
    if (estado === "PUNTUAL") return "Puntual"
    if (estado === "TARDANZA") return "Tardanza"
    if (estado === "FUERA_DE_HORARIO") return "Fuera de horario"
    return "-"
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
    const sec = normalizarCodigoSeccion(seccion)
    if (!sec) return null
    const regla = (cursoSecciones || []).find(x => normalizarCodigoSeccion(x.seccion) === sec)
    if (!regla) return null
    return {
        seccion: sec,
        modalidad: normalizarModalidad(regla.modalidad),
        horaInicioMin: horaATotalMinutos(regla.hora_inicio),
        horaInicioTexto: String(regla.hora_inicio || "").slice(0, 5),
        dias: (regla.dias || []).map(normalizarTextoDia).filter(Boolean)
    }
}

function describirMotivoSemaforo(motivo) {
    const mapa = {
        estado_puntual: "Puntual",
        estado_tardanza: "Tardanza",
        estado_fuera_de_horario: "Fuera de horario",
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
    const seccionEvaluada = normalizarCodigoSeccion(primerMarcadoUltimoDia?.seccion)
    const jornadaEvaluada = normalizarTipoJornada(primerMarcadoUltimoDia?.tipo_jornada)
    const regla = obtenerReglaSeccion(seccionEvaluada)
    const horaMarcadaMin = horaATotalMinutos(primerMarcadoUltimoDia?.hora || "")
    const horaMarcadaTexto = String(primerMarcadoUltimoDia?.hora || "").slice(0, 5)

    if (!seccionEvaluada) {
        return { estado: "rojo", motivo: "sin_seccion", fecha: ultimaFecha, horaMarcada: horaMarcadaTexto, seccion: "-", horaInicio: "-" }
    }

    if (!regla || regla.horaInicioMin == null) {
        return { estado: "rojo", motivo: "sin_hora_configurada", fecha: ultimaFecha, horaMarcada: horaMarcadaTexto, seccion: seccionEvaluada, horaInicio: "-" }
    }

    if (regla.dias.length && jornadaEvaluada !== "DOMINICAL_GRUPAL") {
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

function evaluarSemaforoDashboard(registrosAlumno) {
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

    const estadoBackend = normalizarEstadoAsistencia(primerMarcadoUltimoDia?.estado_asistencia)
    const seccionEvaluada = normalizarCodigoSeccion(primerMarcadoUltimoDia?.seccion)
    const jornadaEvaluada = normalizarTipoJornada(primerMarcadoUltimoDia?.tipo_jornada)
    const modalidadEvaluada = resolverModalidadRegistro(primerMarcadoUltimoDia)
    const horaMarcadaTexto = String(primerMarcadoUltimoDia?.hora || "").slice(0, 5)

    if (estadoBackend === "PUNTUAL") {
        return {
            estado: "verde",
            motivo: "estado_puntual",
            fecha: ultimaFecha,
            horaMarcada: horaMarcadaTexto,
            seccion: seccionEvaluada || "-",
            horaInicio: "-",
            tipoJornada: jornadaEvaluada,
            modalidad: modalidadEvaluada,
            estadoAsistencia: estadoBackend
        }
    }

    if (estadoBackend === "TARDANZA") {
        return {
            estado: "amarillo",
            motivo: "estado_tardanza",
            fecha: ultimaFecha,
            horaMarcada: horaMarcadaTexto,
            seccion: seccionEvaluada || "-",
            horaInicio: "-",
            tipoJornada: jornadaEvaluada,
            modalidad: modalidadEvaluada,
            estadoAsistencia: estadoBackend
        }
    }

    if (estadoBackend === "FUERA_DE_HORARIO") {
        return {
            estado: "rojo",
            motivo: "estado_fuera_de_horario",
            fecha: ultimaFecha,
            horaMarcada: horaMarcadaTexto,
            seccion: seccionEvaluada || "-",
            horaInicio: "-",
            tipoJornada: jornadaEvaluada,
            modalidad: modalidadEvaluada,
            estadoAsistencia: estadoBackend
        }
    }

    const fallback = evaluarSemaforoPorRegla(registros)
    return {
        ...fallback,
        tipoJornada: jornadaEvaluada,
        modalidad: modalidadEvaluada,
        estadoAsistencia: ""
    }
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

function normalizarOrigenRegistroLabel(origen) {
    const raw = String(origen || "").trim().toLowerCase()
    if (!raw) return ""
    if (raw === "importacion_historica") return "Importado"
    if (raw === "qr" || raw === "qr_aspirantes" || raw === "qr_publico" || raw === "qr_staff") return "QR / Actual"
    if (raw.includes("offline")) return "Offline / Contingencia"
    return raw.replace(/_/g, " ").replace(/\b\w/g, char => char.toUpperCase())
}

function formatearHoraVisible(valor) {
    return String(valor || "").trim().slice(0, 8)
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
        Jornada: formatearTipoJornadaAmigable(r.jornada),
        Seccion_Aspirante: formatearSeccionRegistro(r.seccion, r.jornada),
        Modalidad: formatearModalidadAmigable(r.modalidad),
        Fecha: r.fecha || "",
        Hora: formatearHoraVisible(r.hora || ""),
        Origen: r.origen || "",
        Import_Batch_ID: r.import_batch_id || "",
        Fuente_Importacion: r.fuente_importacion || r.archivo_origen || "",
        Importado_En: r.importado_en || "",
        Importado_Por: r.importado_por || "",
        Alerta: r.alerta || ""
    }))

    descargarExcelDesdeJSON("reportes_asistencia.xlsx", rows)
}

function exportarReportesStaffExcel() {
    if (!cacheReportesStaff.length) {
        alert("No hay datos de staff para exportar")
        return
    }

    const rows = cacheReportesStaff.map(r => ({
        Fecha: r.fecha || "",
        Hora_Ingreso: r.hora_ingreso || "",
        Codigo: r.codigo_bombero || "",
        Nombre: r.nombre || "",
        Grado: r.grado || "",
        UBO_Origen: r.ubo_origen || "",
        Tipo_Staff: r.tipo_staff || "",
        Jornada: r.jornada || ""
    }))

    descargarExcelDesdeJSON("reportes_staff_asistencia.xlsx", rows)
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
        actualizarInfoSesionHeader()
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
    actualizarInfoSesionHeader()
}

function renderUsuariosAdmin() {
    if (!tablaUsuariosAdmin) return
    poblarPerfilesInstitucionales()
    const tenantActual = String(tenantActivoId || "").trim().toLowerCase()

    const search = String(document.getElementById("inputBusquedaUsuarios")?.value || "").toLowerCase()
    const filterPerfil = String(document.getElementById("filtroPerfilUsuarios")?.value || "todos").toLowerCase()

    const usuariosInstitucionalesRaw = usuariosAdmin
        .map((u, sourceIndex) => Object.assign({}, u, { sourceIndex }))
        .filter(u =>
            !SYSTEM_USERS.some(s => s.usuario === u.usuario) &&
            normalizarRolUsuario(u.rol) !== ROLES_ADMIN.SUPERUSUARIO &&
            (!tenantActual || !String(u.tenantId || "").trim() || String(u.tenantId || "").trim().toLowerCase() === tenantActual)
        )

    const dataRaw = SYSTEM_USERS.concat(usuariosInstitucionalesRaw)

    const data = dataRaw.filter(u => {
        const full = `${u.nombres || u.nombre} ${u.apellidos || ""} ${u.usuario}`.toLowerCase()
        const matchesSearch = !search || full.includes(search)

        const perfilId = String(perfilesUsuariosLocales?.[String(u.usuario || "").toLowerCase()] || "administrador").toLowerCase()
        let matchesPerfil = true
        if (filterPerfil !== "todos") {
            matchesPerfil = perfilId.includes(filterPerfil)
        }

        return matchesSearch && matchesPerfil
    })

    const elContador = document.getElementById("contadorUsuarios")
    if (elContador) elContador.innerText = `Mostrando ${data.length} usuarios`

    if (!data.length) {
        tablaUsuariosAdmin.innerHTML = buildEmptyTableRow(
            5,
            "Sin usuarios creados",
            "No se encontraron usuarios para los filtros aplicados.",
            "👥"
        )
        return
    }

    let html = ""
    data.forEach((u, idx) => {
        const isSystem = !!u.system
        const perfilId = String(perfilesUsuariosLocales?.[String(u.usuario || "").toLowerCase()] || "administrador")
        const rowId = `inst-user-${idx}`

        html += `
      <tr class="user-row" onclick="toggleDetallesUsuario('${rowId}')">
        <td>${u.usuario || ""}${isSystem ? `<span class="tag-system">SISTEMA</span>` : ""}</td>
        <td>${u.nombres || u.nombre || ""} ${u.apellidos || ""}</td>
        <td>${renderBadgePerfil(perfilId)}</td>
        <td>${renderBadgeEstado(u.activo !== false)}</td>
        <td>
           <div class="user-actions">
              <button class="btn-action btn-details">Ver detalles</button>
           </div>
        </td>
      </tr>
      <tr id="${rowId}" class="user-details-row">
        <td colspan="5">
          <div class="user-details-content">
            <div class="detail-item">
              <span class="detail-label">DNI</span>
              <span class="detail-value">${u.dni || "-"}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Correo</span>
              <span class="detail-value">${u.correo || "-"}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Celular</span>
              <span class="detail-value">${u.celular || "-"}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Rol Técnico</span>
              <span class="detail-value">${u.rol || ""}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Institución</span>
              <span class="detail-value">${u.tenantId || "Global"}</span>
            </div>
            <div class="detail-item" style="grid-column: 1 / -1; margin-top: 10px;">
              <span class="detail-label">Acciones de gestión</span>
              <div class="table-actions" style="margin-top:5px; justify-content: flex-start;">
                ${isSystem
                ? `<span class="hint">No editable</span>`
                : `<button onclick="event.stopPropagation(); editarUsuarioAdmin(${u.sourceIndex})">Modificar</button>
                   <button class="secondary" onclick="event.stopPropagation(); eliminarUsuarioAdmin(${u.sourceIndex})">Eliminar</button>`
            }
              </div>
            </div>
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
    if (userLogin) userLogin.value = ""
    if (userPass) userPass.value = ""
    if (userRol) userRol.value = "administrador"
    if (userPerfil) userPerfil.value = "administrador"
    editUsuarioIndex = null

    // UI Reset
    const card = document.getElementById("formUsuarioAdmin")
    if (card) card.classList.remove("edit-mode")
    const badge = document.getElementById("badgeEditUsuarioAdmin")
    if (badge) badge.style.display = "none"
    const sub = document.getElementById("subtituloFormUsuarioAdmin")
    if (sub) sub.innerText = "Define credenciales, perfil y datos de contacto"
}

function cancelarEdicionUsuarioAdmin() {
    limpiarUsuarioAdmin()
}

async function guardarUsuarioAdmin() {
    const original = editUsuarioIndex !== null ? usuariosAdmin[editUsuarioIndex] : null
    const esEdicion = editUsuarioIndex !== null
    const previousUsuario = String(original?.usuario || "").trim().toLowerCase()
    const claveOriginal = obtenerClaveUsuario(original)
    const nombres = obtenerValorEdicion(userNombres?.value, original?.nombres || original?.nombre)
    const apellidos = obtenerValorEdicion(userApellidos?.value, original?.apellidos)
    const dni = obtenerValorEdicion(userDni?.value, original?.dni, value => String(value || "").replace(/\D/g, ""))
    const correo = obtenerValorEdicion(userCorreo?.value, original?.correo, value => String(value || "").trim().toLowerCase())
    const celular = obtenerValorEdicion(userCelular?.value, original?.celular, value => String(value || "").replace(/\D/g, ""))
    const usuario = obtenerValorEdicion(userLogin?.value, original?.usuario, value => String(value || "").trim().toLowerCase())
    const claveIngresada = String(userPass?.value || "").trim()
    const clave = claveIngresada || claveOriginal
    const rol = normalizarRolUsuario(userRol?.value || original?.rol || ROLES_ADMIN.ADMINISTRADOR)
    const perfilId = normalizarPerfilId(userPerfil?.value || resolverPerfilUsuario(original?.usuario, original?.perfilId) || "administrador") || "administrador"

    if (!nombres || !apellidos || !dni || !usuario || (!esEdicion && !clave)) {
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

    const perfil = obtenerPerfilPorId(perfilId)
    if (!perfil || perfil.estado !== "activo") {
        alert("Selecciona un perfil activo.")
        return
    }
    if (rol === ROLES_ADMIN.SUPERUSUARIO) {
        alert("El rol superusuario es global y no se gestiona en este módulo institucional.")
        return
    }
    if (!tenantActivoId) {
        alert("No hay institución activa para asignar el usuario.")
        return
    }
    let accion = "usuario_admin_institucional_creado"
    if (esEdicion) {
        if (!original?.id) {
            alert("No se encontró el usuario a editar")
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
    }

    try {
        const cambioClaveReal = !!claveIngresada && claveIngresada !== claveOriginal
        if (!esEdicion || cambioClaveReal) {
            if (!await tieneSesionSupabaseActiva()) {
                alert(esEdicion
                    ? "Para cambiar la clave de este usuario debes iniciar sesión institucional con JWT activo."
                    : "Para crear usuarios desde este módulo debes iniciar sesión institucional con JWT activo.")
                return
            }
            await provisionarUsuarioAdminSeguro({
                usuario,
                clave,
                correo,
                tenant_id: tenantActivoId,
                rol,
                nombres,
                apellidos,
                dni,
                celular,
                perfil_id: perfilId,
                previous_usuario: previousUsuario,
                activo: true
            })
        } else {
            await actualizarUsuarioAdminExistenteEnSupabase({
                usuario,
                clave,
                correo,
                tenant_id: tenantActivoId,
                rol,
                nombres,
                apellidos,
                dni,
                celular,
                perfil_id: perfilId,
                previous_usuario: previousUsuario,
                activo: true
            })
        }
    } catch (error) {
        if (error?.message === "SESSION_EXPIRED") return
        alert(`No se pudo provisionar usuario: ${error.message}`)
        return
    }

    await cargarUsuariosAdminDesdeSupabase()
    if (previousUsuario && previousUsuario !== usuario) {
        delete perfilesUsuariosLocales[previousUsuario]
    }
    perfilesUsuariosLocales[usuario] = perfilId
    sincronizarPermisosPanelInstitucional()
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
    userPass.value = obtenerClaveUsuario(u)
    userRol.value = normalizarRolUsuario(u.rol)
    if (userPerfil) {
        const perfil = String(perfilesUsuariosLocales?.[String(u.usuario || "").toLowerCase()] || "administrador")
        userPerfil.value = perfil
    }
    editUsuarioIndex = idx

    // UI Edit Mode
    const card = document.getElementById("formUsuarioAdmin")
    if (card) card.classList.add("edit-mode")
    const badge = document.getElementById("badgeEditUsuarioAdmin")
    if (badge) badge.style.display = "inline-block"
    const sub = document.getElementById("subtituloFormUsuarioAdmin")
    if (sub) sub.innerText = `Modificando datos de: ${u.usuario}`
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

function createHistoricalImportState() {
    return {
        file: null,
        headers: [],
        rows: [],
        mapping: {},
        autoDetected: {},
        preview: [],
        aspirantesCache: {
            rows: [],
            index: null
        },
        manualResolution: {
            rowIndex: null,
            searchTerm: "",
            searchResults: []
        },
        importing: false,
        importSummary: {
            imported: 0,
            duplicate: 0,
            skippedNotConciliated: 0,
            skippedObserved: 0,
            failed: 0,
            batchId: ""
        },
        stats: {
            total: 0,
            valid: 0,
            duplicates: 0,
            invalidDates: 0,
            missingUbo: 0,
            incompleteName: 0,
            observed: 0
        },
        reconciliation: {
            conciliated: 0,
            automatic: 0,
            manual: 0,
            noMatch: 0,
            multiple: 0,
            pendingReview: 0,
            loaded: false,
            available: false
        },
        validated: false
    }
}

function getHistoricalImportElements() {
    return {
        fileInput: document.getElementById("historicalImportFile"),
        dropzone: document.getElementById("historicalImportDropzone"),
        fileMeta: document.getElementById("historicalImportFileMeta"),
        message: document.getElementById("historicalImportMessage"),
        mapping: document.getElementById("historicalImportMapping"),
        previewBody: document.getElementById("historicalImportPreviewBody"),
        previewCount: document.getElementById("historicalImportPreviewCount"),
        reconciliationStatus: document.getElementById("historicalReconciliationStatus"),
        reconciliationLabel: document.getElementById("historicalConciliationLabel"),
        reconciliationConciliated: document.getElementById("historicalConciliationConciliated"),
        reconciliationNoMatch: document.getElementById("historicalConciliationNoMatch"),
        reconciliationMultiple: document.getElementById("historicalConciliationMultiple"),
        reconciliationPending: document.getElementById("historicalConciliationPending"),
        prepareButton: document.getElementById("historicalPrepareButton"),
        prepareMessage: document.getElementById("historicalPrepareMessage"),
        actionHint: document.getElementById("historicalActionHint"),
        importResult: document.getElementById("historicalImportSummary"),
        importResultImported: document.getElementById("historicalImportSummaryImported"),
        importResultDuplicate: document.getElementById("historicalImportSummaryDuplicate"),
        importResultSkippedNotConciliated: document.getElementById("historicalImportSummarySkippedNotConciliated"),
        importResultSkippedObserved: document.getElementById("historicalImportSummarySkippedObserved"),
        importResultFailed: document.getElementById("historicalImportSummaryFailed"),
        importResultBatchId: document.getElementById("historicalImportSummaryBatchId"),
        reportsButton: document.getElementById("historicalReportsButton")
    }
}

function normalizeHistoricalHeader(value) {
    return String(value || "")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .replace(/[_\-]+/g, " ")
        .replace(/[^\w\s/]/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .toLowerCase()
}

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;")
}

function setHistoricalImportMessage(text, tone = "info") {
    const { message } = getHistoricalImportElements()
    if (!message) return
    message.className = `course-inline-msg course-inline-msg--${tone}`
    message.innerText = text
}

function setHistoricalPrepareMessage(text, tone = "info") {
    const { prepareMessage } = getHistoricalImportElements()
    if (!prepareMessage) return
    prepareMessage.className = `course-inline-msg course-inline-msg--${tone}`
    prepareMessage.innerText = text
}

function resetHistoricalReconciliation() {
    historicalImportState.reconciliation = {
        conciliated: 0,
        automatic: 0,
        manual: 0,
        noMatch: 0,
        multiple: 0,
        pendingReview: 0,
        loaded: false,
        available: false
    }
    const {
        reconciliationStatus,
        reconciliationLabel,
        reconciliationConciliated,
        reconciliationNoMatch,
        reconciliationMultiple,
        reconciliationPending
    } = getHistoricalImportElements()
    if (reconciliationStatus) {
        reconciliationStatus.className = "course-inline-msg course-inline-msg--info"
        reconciliationStatus.innerText = "La conciliación se ejecutará después de validar el archivo."
    }
    if (reconciliationLabel) reconciliationLabel.innerText = "Conciliados"
    if (reconciliationConciliated) reconciliationConciliated.innerText = "0"
    if (reconciliationNoMatch) reconciliationNoMatch.innerText = "0"
    if (reconciliationMultiple) reconciliationMultiple.innerText = "0"
    if (reconciliationPending) reconciliationPending.innerText = "0"
}

function renderHistoricalReconciliation(summary = {}, tone = "info", message = "") {
    const {
        reconciliationStatus,
        reconciliationLabel,
        reconciliationConciliated,
        reconciliationNoMatch,
        reconciliationMultiple,
        reconciliationPending
    } = getHistoricalImportElements()
    if (reconciliationStatus) {
        reconciliationStatus.className = `course-inline-msg course-inline-msg--${tone}`
        reconciliationStatus.innerText = message || "Conciliación lista."
    }
    if (reconciliationLabel) {
        reconciliationLabel.innerText = summary.manual ? "Conciliados totales" : "Conciliados"
    }
    if (reconciliationConciliated) reconciliationConciliated.innerText = String(summary.conciliated || 0)
    if (reconciliationNoMatch) reconciliationNoMatch.innerText = String(summary.noMatch || 0)
    if (reconciliationMultiple) reconciliationMultiple.innerText = String(summary.multiple || 0)
    if (reconciliationPending) reconciliationPending.innerText = String(summary.pendingReview || 0)
}

function computeHistoricalReconciliationSummary(preview = [], available = false) {
    const summary = {
        conciliated: 0,
        automatic: 0,
        manual: 0,
        noMatch: 0,
        multiple: 0,
        pendingReview: 0,
        loaded: true,
        available: !!available
    }

    ;(preview || []).forEach(row => {
        if (row.conciliacionEstado === "conciliado") summary.automatic += 1
        if (row.conciliacionEstado === "manual") summary.manual += 1
        if (row.conciliacionEstado === "sin_coincidencia") summary.noMatch += 1
        if (row.conciliacionEstado === "multiple") summary.multiple += 1
    })

    summary.conciliated = summary.automatic + summary.manual
    summary.pendingReview = summary.noMatch + summary.multiple
    return summary
}

function syncHistoricalReconciliationUI() {
    const available = !!historicalImportState.reconciliation?.available
    const summary = computeHistoricalReconciliationSummary(historicalImportState.preview || [], available)
    historicalImportState.reconciliation = summary
    const tone = summary.pendingReview ? "warning" : "ok"
    const message = summary.conciliated
        ? summary.manual
            ? `Conciliación actualizada: ${summary.automatic} automática(s) y ${summary.manual} manual(es). Ya puedes importar los registros conciliados válidos.`
            : "Se encontraron coincidencias de aspirantes. Ya puedes importar los registros conciliados válidos."
        : "No se encontraron conciliaciones automáticas. La revisión manual quedará para la siguiente fase."
    renderHistoricalReconciliation(summary, tone, message)
    updateHistoricalActionState()
}

function hasHistoricalDniMapping() {
    return Number.isInteger(historicalImportState.mapping?.dni)
}

function getHistoricalValidPreviewRows() {
    return (historicalImportState.preview || []).filter(row => row.status === "valido")
}

function isHistoricalImportEligibleRow(row = {}) {
    return row.status === "valido" &&
        (row.conciliacionEstado === "conciliado" || row.conciliacionEstado === "manual") &&
        !!normalizeHistoricalDni(row.dniSugerido) &&
        !!String(row.fecha || "").trim() &&
        !!String(row.hora || "").trim() &&
        !!normalizeHistoricalUbo(row.ubo) &&
        !!String(row.aspiranteEncontrado || row.nombreCompleto || "").trim()
}

function getHistoricalImportableRows() {
    return (historicalImportState.preview || []).filter(isHistoricalImportEligibleRow)
}

function buildHistoricalImportSummaryBase() {
    const preview = historicalImportState.preview || []
    return {
        imported: 0,
        duplicate: 0,
        skippedNotConciliated: preview.filter(row =>
            row.status === "valido" && !isHistoricalImportEligibleRow(row)
        ).length,
        skippedObserved: preview.filter(row => row.status !== "valido").length,
        failed: 0,
        batchId: ""
    }
}

function resetHistoricalImportSummary() {
    historicalImportState.importSummary = {
        imported: 0,
        duplicate: 0,
        skippedNotConciliated: 0,
        skippedObserved: 0,
        failed: 0,
        batchId: ""
    }
    const {
        importResult,
        importResultImported,
        importResultDuplicate,
        importResultSkippedNotConciliated,
        importResultSkippedObserved,
        importResultFailed,
        importResultBatchId
    } = getHistoricalImportElements()
    if (importResult) importResult.hidden = true
    if (importResultImported) importResultImported.innerText = "0"
    if (importResultDuplicate) importResultDuplicate.innerText = "0"
    if (importResultSkippedNotConciliated) importResultSkippedNotConciliated.innerText = "0"
    if (importResultSkippedObserved) importResultSkippedObserved.innerText = "0"
    if (importResultFailed) importResultFailed.innerText = "0"
    if (importResultBatchId) importResultBatchId.innerText = "-"
}

function resetHistoricalImportModuleState() {
    const { fileInput, fileMeta } = getHistoricalImportElements()
    historicalImportState = createHistoricalImportState()
    if (fileInput) fileInput.value = ""
    if (fileMeta) fileMeta.innerText = "Ningún archivo seleccionado."
    resetHistoricalImportStats()
    resetHistoricalReconciliation()
    resetHistoricalImportSummary()
    renderHistoricalImportMapping()
    renderHistoricalPreview([])
    setHistoricalImportMessage("Carga un archivo para leer encabezados y preparar el mapeo.", "info")
    setHistoricalPrepareMessage("La acción se habilitará después de validar el archivo.", "info")
    updateHistoricalActionState()
}

function shortenHistoricalBatchId(batchId = "") {
    const value = String(batchId || "").trim()
    if (!value) return "-"
    if (value.length <= 16) return value
    return `${value.slice(0, 8)}...${value.slice(-8)}`
}

function abrirReportesImportacionHistorica() {
    mostrarVista("reportes")
}

function abrirModalExitoImportacionHistorica(summary = {}) {
    modalTitulo.innerText = "Importación completada"
    modalContenido.innerHTML = `
      <div class="historical-success-modal">
        <div class="historical-success-badge">✔ Proceso finalizado</div>
        <p class="historical-success-copy">Importación histórica completada correctamente</p>
        <div class="historical-success-grid">
          <div><strong>Importados</strong><span>${escapeHtml(summary.imported || 0)}</span></div>
          <div><strong>Duplicados</strong><span>${escapeHtml(summary.duplicate || 0)}</span></div>
          <div><strong>Observados</strong><span>${escapeHtml(summary.skippedObserved || 0)}</span></div>
          <div><strong>Batch ID</strong><span class="historical-success-batch">${escapeHtml(shortenHistoricalBatchId(summary.batchId || ""))}</span></div>
        </div>
        <div class="tenant-admin-modal-actions">
          <button type="button" onclick="cerrarModal(); resetHistoricalImportModuleState()">Nueva carga</button>
          <button type="button" class="secondary" onclick="cerrarModal(); abrirReportesImportacionHistorica()">Ver reportes</button>
        </div>
      </div>
    `
    modal.style.display = "flex"
}

function renderHistoricalImportSummary(summary = {}) {
    const {
        importResult,
        importResultImported,
        importResultDuplicate,
        importResultSkippedNotConciliated,
        importResultSkippedObserved,
        importResultFailed,
        importResultBatchId
    } = getHistoricalImportElements()
    if (!importResult) return
    importResult.hidden = false
    if (importResultImported) importResultImported.innerText = String(summary.imported || 0)
    if (importResultDuplicate) importResultDuplicate.innerText = String(summary.duplicate || 0)
    if (importResultSkippedNotConciliated) importResultSkippedNotConciliated.innerText = String(summary.skippedNotConciliated || 0)
    if (importResultSkippedObserved) importResultSkippedObserved.innerText = String(summary.skippedObserved || 0)
    if (importResultFailed) importResultFailed.innerText = String(summary.failed || 0)
    if (importResultBatchId) importResultBatchId.innerText = String(summary.batchId || "-")
}

function updateHistoricalActionState() {
    const { prepareButton, actionHint, reportsButton } = getHistoricalImportElements()
    if (!prepareButton || !actionHint) return
    const canValidate = !!(historicalImportState.validated && historicalImportState.preview.length)
    const importableRows = getHistoricalImportableRows()
    const importDone = !!historicalImportState.importSummary?.imported

    if (!canValidate) {
        prepareButton.disabled = true
        prepareButton.innerText = "Preparar importación"
        actionHint.innerText = "La importación histórica insertará registros conciliados en asistencias solo después de validar el archivo y confirmar la acción."
        if (reportsButton) reportsButton.hidden = true
        return
    }

    if (historicalImportState.importing) {
        prepareButton.disabled = true
        prepareButton.innerText = "Importando..."
        actionHint.innerText = "La importación histórica está en progreso. Los registros importados quedarán integrados en reportes y exportaciones con trazabilidad."
        if (reportsButton) reportsButton.hidden = true
        return
    }

    if (importDone) {
        prepareButton.disabled = false
        prepareButton.innerText = "Nueva carga"
        actionHint.innerText = "Importación histórica completada correctamente. Los registros ya forman parte de reportes y exportaciones con trazabilidad."
        if (reportsButton) reportsButton.hidden = false
        return
    }

    prepareButton.disabled = false
    prepareButton.innerText = importableRows.length ? "Importar registros conciliados" : "Preparar importación"
    actionHint.innerText = importableRows.length
        ? `Hay ${importableRows.length} registro(s) conciliado(s) listos para insertarse en asistencias con trazabilidad y sin sobrescribir datos existentes.`
        : "La importación real requiere filas válidas, conciliadas y con DNI sugerido antes de confirmar la inserción."
    if (reportsButton) reportsButton.hidden = true
}

function resetHistoricalImportStats() {
    const stats = {
        total: 0,
        valid: 0,
        duplicates: 0,
        invalidDates: 0,
        missingUbo: 0,
        incompleteName: 0,
        observed: 0
    }
    historicalImportState.stats = stats
    const map = {
        historicalKpiTotal: stats.total,
        historicalKpiValid: stats.valid,
        historicalKpiDuplicates: stats.duplicates,
        historicalKpiInvalidDates: stats.invalidDates,
        historicalKpiMissingUbo: stats.missingUbo,
        historicalKpiIncompleteName: stats.incompleteName,
        historicalKpiObserved: stats.observed
    }
    Object.entries(map).forEach(([id, value]) => {
        const el = document.getElementById(id)
        if (el) el.innerText = String(value)
    })
}

function canResolveHistoricalRow(row = {}) {
    return row.conciliacionEstado === "sin_coincidencia" ||
        row.conciliacionEstado === "multiple" ||
        row.conciliacionEstado === "manual" ||
        row.resolvedManually === true
}

function getHistoricalResolveButtonLabel(row = {}) {
    if (row.conciliacionEstado === "manual" || row.resolvedManually) return "Cambiar aspirante"
    if (row.conciliacionEstado === "multiple") return "Seleccionar aspirante"
    return "Resolver"
}

function renderHistoricalResolveAction(row = {}) {
    if (!canResolveHistoricalRow(row)) {
        return `<span class="hint historical-resolve-empty">-</span>`
    }
    return `<button type="button" class="secondary historical-resolve-button" onclick="abrirResolucionManualHistorica(${Number(row.index) || 0})">${escapeHtml(getHistoricalResolveButtonLabel(row))}</button>`
}

function renderHistoricalPreviewRow(row = {}) {
    const stateClass = row.status === "valido"
        ? "is-valid"
        : row.status === "observado"
            ? "is-observed"
            : "is-error"
    return `
      <tr class="historical-preview-row ${stateClass}" data-historical-preview-index="${Number(row.index) || 0}">
        <td><span class="historical-row-state ${stateClass}">${escapeHtml(row.status)}</span></td>
        <td>${escapeHtml(row.fecha || "-")}</td>
        <td>${escapeHtml(row.hora || "-")}</td>
        <td>${escapeHtml(row.ubo || "-")}</td>
        <td>${escapeHtml(row.nombreCompleto || "-")}</td>
        <td>${escapeHtml(row.seccion || "-")}</td>
        <td><span class="historical-reconciliation-state ${row.conciliacionClase || "is-pending"}">${escapeHtml(row.conciliacionLabel || "Pendiente")}</span></td>
        <td>${escapeHtml(row.dniSugerido || row.dni || "-")}</td>
        <td>${escapeHtml(row.aspiranteEncontrado || "-")}</td>
        <td>${renderHistoricalResolveAction(row)}</td>
        <td class="historical-observation">${escapeHtml(row.observacion || "-")}</td>
      </tr>
    `
}

function renderHistoricalPreview(rows = []) {
    const { previewBody, previewCount } = getHistoricalImportElements()
    if (previewCount) previewCount.innerText = `${rows.length} registro${rows.length === 1 ? "" : "s"} listados`
    if (!previewBody) return

    if (!rows.length) {
        previewBody.innerHTML = buildEmptyTableRow(
            11,
            "Sin preview disponible",
            "Valida un archivo para revisar registros, observaciones y errores.",
            "🧪"
        )
        return
    }

    previewBody.innerHTML = rows.slice(0, 250).map(renderHistoricalPreviewRow).join("")
}

function patchHistoricalPreviewRow(row = {}) {
    const { previewBody } = getHistoricalImportElements()
    if (!previewBody) return
    const rowEl = previewBody.querySelector(`[data-historical-preview-index="${Number(row.index) || 0}"]`)
    if (!rowEl) return
    rowEl.outerHTML = renderHistoricalPreviewRow(row)
}

function renderHistoricalImportMapping() {
    const { mapping } = getHistoricalImportElements()
    if (!mapping) return

    if (!historicalImportState.headers.length) {
        mapping.innerHTML = buildEmptyStateHTML(
            "Sin encabezados detectados",
            "Carga un archivo para activar la detección automática y el mapeo manual.",
            "🧩",
            true
        )
        return
    }

    const options = historicalImportState.headers.map((header, index) =>
        `<option value="${index}">${escapeHtml(header)}</option>`
    ).join("")

    let html = ""
    HISTORICAL_IMPORT_FIELDS.forEach(field => {
        const detectedIndex = historicalImportState.mapping[field.key]
        const hasSelection = Number.isInteger(detectedIndex)
        const wasAutoDetected = !!historicalImportState.autoDetected[field.key] && hasSelection
        const statusText = wasAutoDetected
            ? "✔ Detectado automáticamente"
            : hasSelection
                ? "✔ Selección manual aplicada"
                : "⚠ Requiere selección manual"
        const detectedLabel = hasSelection
            ? historicalImportState.headers[detectedIndex]
            : "Selecciona manualmente una columna."
        html += `
      <div class="historical-mapping-card">
        <div class="historical-mapping-top">
          <div class="historical-mapping-label">
            <strong>${escapeHtml(field.label)}</strong>
            <span>${escapeHtml(field.help)}</span>
          </div>
          <span class="historical-status ${hasSelection ? "is-auto" : "is-manual"}">
            ${statusText}
          </span>
        </div>
        <div class="historical-detected-column ${hasSelection ? "" : "is-missing"}">
          Campo AsistIA → Columna Excel<br><strong>${escapeHtml(detectedLabel)}</strong>
        </div>
        <label for="historicalMap_${field.key}" class="hint">Mapeo manual</label>
        <select id="historicalMap_${field.key}" data-historical-map="${field.key}">
          <option value="">Seleccionar columna</option>
          ${options}
        </select>
      </div>
    `
    })

    mapping.innerHTML = html
    HISTORICAL_IMPORT_FIELDS.forEach(field => {
        const select = document.getElementById(`historicalMap_${field.key}`)
        if (!select) return
        select.value = Number.isInteger(historicalImportState.mapping[field.key])
            ? String(historicalImportState.mapping[field.key])
            : ""
    })
}

function detectHistoricalColumns(headers = []) {
    const normalizedHeaders = headers.map(normalizeHistoricalHeader)
    const mapping = {}
    const autoDetected = {}
    const used = new Set()

    HISTORICAL_IMPORT_FIELDS.forEach(field => {
        const aliases = HISTORICAL_IMPORT_ALIASES[field.key] || []
        let idx = normalizedHeaders.findIndex(header => aliases.includes(header))
        if (idx < 0) {
            idx = normalizedHeaders.findIndex(header =>
                aliases.some(alias => header.includes(alias) || alias.includes(header))
            )
        }
        if (idx >= 0 && !used.has(idx)) {
            mapping[field.key] = idx
            autoDetected[field.key] = true
            used.add(idx)
        } else {
            mapping[field.key] = null
            autoDetected[field.key] = false
        }
    })

    historicalImportState.mapping = mapping
    historicalImportState.autoDetected = autoDetected
}

function syncHistoricalMappingFromSelectors() {
    HISTORICAL_IMPORT_FIELDS.forEach(field => {
        const select = document.getElementById(`historicalMap_${field.key}`)
        if (!select) return
        historicalImportState.mapping[field.key] = select.value === "" ? null : Number(select.value)
    })
    historicalImportState.validated = false
    historicalImportState.preview = []
    renderHistoricalPreview([])
    resetHistoricalReconciliation()
    resetHistoricalImportSummary()
    setHistoricalPrepareMessage("La acción se habilitará después de validar el archivo.", "info")
    updateHistoricalActionState()
}

function normalizeHistoricalTimestamp(rawValue) {
    if (rawValue instanceof Date && !Number.isNaN(rawValue.getTime())) {
        const year = rawValue.getFullYear()
        const month = String(rawValue.getMonth() + 1).padStart(2, "0")
        const day = String(rawValue.getDate()).padStart(2, "0")
        const hour = String(rawValue.getHours()).padStart(2, "0")
        const minute = String(rawValue.getMinutes()).padStart(2, "0")
        const second = String(rawValue.getSeconds()).padStart(2, "0")
        return { fecha: `${year}-${month}-${day}`, hora: `${hour}:${minute}:${second}`, valido: true }
    }

    const value = String(rawValue || "").trim()
    if (!value) return { fecha: "", hora: "", valido: false }

    const match = value.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:\s+|T)(\d{1,2}):(\d{2})(?::(\d{2}))?$/)
    if (match) {
        const [, dd, mm, yyyy, hh, min, sec = "00"] = match
        const day = Number(dd)
        const month = Number(mm)
        const year = Number(yyyy)
        const hour = Number(hh)
        const minute = Number(min)
        const second = Number(sec)
        const date = new Date(year, month - 1, day, hour, minute, second)
        if (
            date.getFullYear() === year &&
            date.getMonth() === month - 1 &&
            date.getDate() === day &&
            hour <= 23 &&
            minute <= 59 &&
            second <= 59
        ) {
            return {
                fecha: `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`,
                hora: `${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}:${String(second).padStart(2, "0")}`,
                valido: true
            }
        }
    }

    const isoDate = new Date(value)
    if (!Number.isNaN(isoDate.getTime())) {
        return {
            fecha: isoDate.toISOString().slice(0, 10),
            hora: isoDate.toTimeString().slice(0, 8),
            valido: true
        }
    }

    return { fecha: "", hora: "", valido: false }
}

function normalizeHistoricalText(value) {
    return String(value || "").replace(/\s+/g, " ").trim()
}

function normalizeHistoricalUbo(value) {
    return String(value || "").replace(/\D/g, "").trim()
}

function normalizeHistoricalDni(value) {
    return String(value || "").replace(/\D/g, "").trim()
}

function normalizeHistoricalSection(value) {
    return normalizeHistoricalText(value).toUpperCase()
}

function normalizeHistoricalComparable(value) {
    return String(value || "")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .replace(/[^\w\s]/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .toUpperCase()
}

function normalizeHistoricalComparableCompact(value) {
    return normalizeHistoricalComparable(value).replace(/\s+/g, "")
}

function buildHistoricalFullName(apellidos, nombres) {
    return `${normalizeHistoricalText(apellidos)} ${normalizeHistoricalText(nombres)}`
        .replace(/\s+/g, " ")
        .trim()
}

function buildHistoricalAspiranteDisplayName(record = {}) {
    return normalizeHistoricalText(
        record.nombre ||
        record.nombreCompleto ||
        `${record.apellidos || ""} ${record.nombres || ""}`
    )
}

async function fetchHistoricalAspirantesTenant() {
    if (!haySupabase()) {
        return { available: false, rows: [], reason: "Supabase no está disponible para conciliar aspirantes." }
    }
    if (!tenantActivoId) {
        return { available: false, rows: [], reason: "No hay tenant activo para conciliar aspirantes." }
    }

    let data = []
    let error = null

    ; ({ data, error } = await withTenantScope(
        supabaseClient.from("aspirantes").select("dni,nombres,apellidos,tenant_id,ubo,curso_id")
    ))

    if (error && /tenant_id/i.test(String(error.message || ""))) {
        const fallback = await withTenantScope(
            supabaseClient.from("aspirantes").select("dni,nombres,apellidos,ubo,curso_id")
        )
        data = (fallback.data || []).map(item => Object.assign({}, item, { tenant_id: tenantActivoId }))
        error = fallback.error
    }

    if (error) {
        console.error("Error cargando aspirantes para conciliación:", error)
        return { available: false, rows: [], reason: error.message || "No se pudo consultar aspirantes." }
    }

    return { available: true, rows: filtrarDataTenantActivo(data || []), reason: "" }
}

function buildHistoricalAspirantesIndex(rows = []) {
    const byName = new Map()
    const byCompact = new Map()
    const all = []

    rows.forEach(item => {
        const nombre = buildHistoricalAspiranteDisplayName(item)
        const nombreNormalizado = normalizeHistoricalComparable(nombre)
        const nombreCompacto = normalizeHistoricalComparableCompact(nombre)
        const record = {
            dni: normalizeHistoricalDni(item?.dni),
            nombres: normalizeHistoricalText(item?.nombres),
            apellidos: normalizeHistoricalText(item?.apellidos),
            nombre,
            nombreNormalizado,
            nombreCompacto,
            ubo: normalizeHistoricalUbo(item?.ubo)
        }
        all.push(record)
        if (nombreNormalizado) {
            if (!byName.has(nombreNormalizado)) byName.set(nombreNormalizado, [])
            byName.get(nombreNormalizado).push(record)
        }
        if (nombreCompacto) {
            if (!byCompact.has(nombreCompacto)) byCompact.set(nombreCompacto, [])
            byCompact.get(nombreCompacto).push(record)
        }
    })

    return { byName, byCompact, all }
}

function stripHistoricalConciliationNotes(text = "") {
    return String(text || "")
        .split(" · ")
        .filter(part => part && !/Sin coincidencia en aspirantes|Múltiples candidatos en aspirantes|Resuelto manualmente/i.test(part))
        .join(" · ")
        .trim()
}

function buildHistoricalOfficialName(candidate = {}) {
    return buildHistoricalAspiranteDisplayName(candidate)
}

function getHistoricalCachedAspirantesIndex() {
    if (historicalImportState.aspirantesCache?.index) {
        return historicalImportState.aspirantesCache.index
    }
    const rows = historicalImportState.aspirantesCache?.rows || []
    const index = buildHistoricalAspirantesIndex(rows)
    historicalImportState.aspirantesCache.index = index
    return index
}

function searchHistoricalAspirantesLocal(term = "", row = {}) {
    const index = getHistoricalCachedAspirantesIndex()
    const all = index?.all || []
    const normalizedTerm = normalizeHistoricalComparable(term)
    const compactTerm = normalizeHistoricalComparableCompact(term)
    const digitsTerm = String(term || "").replace(/\D/g, "").trim()
    const rowUbo = normalizeHistoricalUbo(row.ubo)

    let results = all.map(candidate => {
        let score = 0
        if (rowUbo && candidate.ubo === rowUbo) score += 4
        if (!normalizedTerm) score += 1
        if (normalizedTerm && candidate.nombreNormalizado === normalizedTerm) score += 10
        if (compactTerm && candidate.nombreCompacto === compactTerm) score += 9
        if (normalizedTerm && candidate.nombreNormalizado.includes(normalizedTerm)) score += 6
        if (compactTerm && candidate.nombreCompacto.includes(compactTerm)) score += 5
        if (digitsTerm && candidate.dni.includes(digitsTerm)) score += 3
        if (digitsTerm && candidate.ubo.includes(digitsTerm)) score += 2
        if (compactTerm && historicalLimitedLevenshtein(candidate.nombreCompacto, compactTerm, 2) <= 2) score += 2
        return Object.assign({}, candidate, { score })
    })

    if (normalizedTerm) {
        results = results.filter(candidate => candidate.score > 0)
    }

    results.sort((a, b) => {
        if (b.score !== a.score) return b.score - a.score
        return String(a.nombre || "").localeCompare(String(b.nombre || ""), "es")
    })

    return results.slice(0, 24)
}

function getHistoricalPreviewRowByIndex(rowIndex) {
    return (historicalImportState.preview || []).find(row => Number(row.index) === Number(rowIndex)) || null
}

function renderHistoricalManualResolutionResults() {
    const searchResultsEl = document.getElementById("historicalResolutionResults")
    if (!searchResultsEl) return
    const currentRow = getHistoricalPreviewRowByIndex(historicalImportState.manualResolution.rowIndex)
    const results = historicalImportState.manualResolution.searchResults || []

    if (!currentRow) {
        searchResultsEl.innerHTML = buildEmptyStateHTML(
            "Fila no disponible",
            "Cierra el modal y vuelve a intentar la resolución manual.",
            "⚠️",
            true
        )
        return
    }

    if (!results.length) {
        searchResultsEl.innerHTML = buildEmptyStateHTML(
            "Sin resultados",
            "Ajusta la búsqueda para encontrar un aspirante local del tenant activo.",
            "🔎",
            true
        )
        return
    }

    searchResultsEl.innerHTML = results.map((candidate, idx) => `
      <div class="historical-resolution-result-card">
        <div class="historical-resolution-result-copy">
          <strong>${escapeHtml(candidate.nombre || "-")}</strong>
          <span>DNI: ${escapeHtml(candidate.dni || "-")}</span>
          <span>Apellidos: ${escapeHtml(candidate.apellidos || "-")}</span>
          <span>Nombres: ${escapeHtml(candidate.nombres || "-")}</span>
          <span>UBO: ${escapeHtml(candidate.ubo || "-")}</span>
        </div>
        <button type="button" onclick="seleccionarAspiranteHistoricoManual(${idx})">Seleccionar</button>
      </div>
    `).join("")
}

function handleHistoricalResolutionSearchInput(event) {
    const currentRow = getHistoricalPreviewRowByIndex(historicalImportState.manualResolution.rowIndex)
    if (!currentRow) return
    historicalImportState.manualResolution.searchTerm = String(event?.target?.value || "")
    historicalImportState.manualResolution.searchResults = searchHistoricalAspirantesLocal(
        historicalImportState.manualResolution.searchTerm,
        currentRow
    )
    renderHistoricalManualResolutionResults()
}

function abrirResolucionManualHistorica(rowIndex) {
    const row = getHistoricalPreviewRowByIndex(rowIndex)
    if (!row) return
    if (!historicalImportState.aspirantesCache?.rows?.length) {
        setHistoricalPrepareMessage("No hay aspirantes cargados en memoria para resolver manualmente.", "warning")
        return
    }

    historicalImportState.manualResolution = {
        rowIndex: Number(row.index),
        searchTerm: row.nombreCompleto || "",
        searchResults: searchHistoricalAspirantesLocal(row.nombreCompleto || "", row)
    }

    modalTitulo.innerText = row.resolvedManually ? "Cambiar aspirante" : "Resolución manual"
    modalContenido.innerHTML = `
      <div class="historical-resolution-modal">
        <div class="historical-resolution-panel">
          <span class="historical-resolution-label">Datos históricos</span>
          <div class="historical-resolution-grid">
            <div><strong>Nombre Excel</strong><span>${escapeHtml(row.nombresExcel || "-")}</span></div>
            <div><strong>Apellidos Excel</strong><span>${escapeHtml(row.apellidosExcel || "-")}</span></div>
            <div><strong>UBO Excel</strong><span>${escapeHtml(row.ubo || "-")}</span></div>
            <div><strong>Sección Excel</strong><span>${escapeHtml(row.seccion || "-")}</span></div>
            <div><strong>Fecha</strong><span>${escapeHtml(row.fecha || "-")}</span></div>
            <div><strong>Hora</strong><span>${escapeHtml(row.hora || "-")}</span></div>
          </div>
        </div>
        <div class="historical-resolution-panel">
          <label class="historical-resolution-label" for="historicalResolutionSearch">Buscar aspirante</label>
          <input id="historicalResolutionSearch" class="historical-resolution-input" type="search" placeholder="Buscar por nombre, DNI o UBO" value="${escapeHtml(historicalImportState.manualResolution.searchTerm)}">
          <div id="historicalResolutionResults" class="historical-resolution-results"></div>
        </div>
      </div>
    `
    modal.style.display = "flex"

    const input = document.getElementById("historicalResolutionSearch")
    if (input) {
        input.addEventListener("input", handleHistoricalResolutionSearchInput)
        setTimeout(() => input.focus(), 0)
    }
    renderHistoricalManualResolutionResults()
}

function seleccionarAspiranteHistoricoManual(resultIndex) {
    const row = getHistoricalPreviewRowByIndex(historicalImportState.manualResolution.rowIndex)
    const candidate = historicalImportState.manualResolution.searchResults?.[resultIndex]
    if (!row || !candidate) return

    const baseObservation = stripHistoricalConciliationNotes(row.observacion)
    row.conciliacionEstado = "manual"
    row.conciliacionLabel = "✔ Manual"
    row.conciliacionClase = "is-manual"
    row.dniSugerido = candidate.dni || ""
    row.aspiranteEncontrado = buildHistoricalOfficialName(candidate) || row.nombreCompleto || ""
    row.resolvedManually = true
    row.observacion = baseObservation
        ? `${baseObservation} · Resuelto manualmente`
        : "Resuelto manualmente"

    patchHistoricalPreviewRow(row)
    syncHistoricalReconciliationUI()
    resetHistoricalImportSummary()
    setHistoricalPrepareMessage("Se actualizó la fila manualmente. La importación podrá habilitarse en la siguiente fase.", "info")
    cerrarModal()
}

function resolveHistoricalImportBatchId() {
    if (window.crypto?.randomUUID) return window.crypto.randomUUID()
    return `hist_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`
}

function resolveHistoricalImportActor() {
    const profile = window.currentProfile || null
    const sesion = obtenerSesionAdminActiva?.() || null
    const visible = String(profile?.full_name || profile?.email || "").trim()
    if (visible) return visible
    const usuarioSesion = String(sesion?.usuario || "").trim()
    if (usuarioSesion) return usuarioSesion
    try {
        if (window.usuarioActual?.usuario) return String(window.usuarioActual.usuario).trim() || null
    } catch (_) { }
    return null
}

function resolveHistoricalTimestampLocal(fecha, hora) {
    const fechaOk = String(fecha || "").trim()
    const horaOk = String(hora || "").trim().slice(0, 8)
    if (!fechaOk || !horaOk) return null
    return `${fechaOk}T${horaOk}`
}

function resolveHistoricalTipoJornada(fecha) {
    return obtenerDiaSemanaEs(fecha) === "domingo" ? "DOMINICAL_GRUPAL" : "SECCION_REGULAR"
}

function buildHistoricalAttendancePayload(row, batchId, importMeta = {}) {
    const cursoId = Number.isFinite(Number(cursoBaseActual?.id)) ? Number(cursoBaseActual.id) : null
    return {
        dni: normalizeHistoricalDni(row.dniSugerido),
        nombre: String(row.aspiranteEncontrado || row.nombreCompleto || "").trim(),
        ubo: normalizeHistoricalUbo(row.ubo),
        fecha: String(row.fecha || "").trim(),
        hora: String(row.hora || "").trim().slice(0, 8),
        seccion: String(row.seccion || "").trim() || null,
        tenant_id: String(tenantActivoId || "").trim().toLowerCase(),
        estado: "registrado",
        curso_id: cursoId,
        tipo_jornada: resolveHistoricalTipoJornada(row.fecha),
        device_id: "importacion_historica",
        timestamp_local: resolveHistoricalTimestampLocal(row.fecha, row.hora),
        origen_registro: "importacion_historica",
        archivo_origen: importMeta.fileName || null,
        import_batch_id: batchId,
        importado_en: importMeta.importedAt || new Date().toISOString(),
        importado_por: importMeta.importedBy || null
    }
}

function isHistoricalDuplicateInsertError(error) {
    const message = String(error?.message || "")
    const code = String(error?.code || "")
    return code === "23505" || /duplicate key|unica_dni_por_dia|unique/i.test(message)
}

async function fetchHistoricalExistingAttendanceKeys(rows = []) {
    if (!rows.length) return new Set()

    const fechas = rows.map(row => String(row.fecha || "")).filter(Boolean).sort()
    const fechaMin = fechas[0] || ""
    const fechaMax = fechas[fechas.length - 1] || ""
    let data = []
    let error = null

    let query = withTenantScope(
        supabaseClient
            .from("asistencias")
            .select("dni,fecha,tenant_id")
            .gte("fecha", fechaMin)
            .lte("fecha", fechaMax)
    )

    ; ({ data, error } = await query)

    if (error && /tenant_id/i.test(String(error.message || ""))) {
        const fallback = await supabaseClient
            .from("asistencias")
            .select("dni,fecha")
            .gte("fecha", fechaMin)
            .lte("fecha", fechaMax)
        data = fallback.data || []
        error = fallback.error
    }

    if (error) throw error

    return new Set((filtrarDataTenantActivo(data) || []).map(item =>
        `${normalizeHistoricalDni(item?.dni)}|${String(item?.fecha || "").trim()}`
    ))
}

async function insertHistoricalImportChunk(rows = [], batchId, importMeta) {
    if (!rows.length) return { imported: 0, duplicate: 0, failed: 0 }

    const payload = rows.map(row => buildHistoricalAttendancePayload(row, batchId, importMeta))
    const { error } = await supabaseClient.from("asistencias").insert(payload)

    if (!error) {
        return { imported: rows.length, duplicate: 0, failed: 0 }
    }

    if (rows.length === 1) {
        return isHistoricalDuplicateInsertError(error)
            ? { imported: 0, duplicate: 1, failed: 0 }
            : { imported: 0, duplicate: 0, failed: 1 }
    }

    let summary = { imported: 0, duplicate: 0, failed: 0 }
    for (const row of rows) {
        const unit = await insertHistoricalImportChunk([row], batchId, importMeta)
        summary.imported += unit.imported
        summary.duplicate += unit.duplicate
        summary.failed += unit.failed
    }
    return summary
}

async function refreshHistoricalImportViews() {
    const jobs = []
    if (typeof cargarDatos === "function") jobs.push(Promise.resolve().then(() => cargarDatos()))
    if (typeof cargarDashboard === "function") jobs.push(Promise.resolve().then(() => cargarDashboard()))
    if (typeof cargarAlertasReporte === "function") jobs.push(Promise.resolve().then(() => cargarAlertasReporte()))
    if (!jobs.length) return
    await Promise.allSettled(jobs)
}

async function importarRegistrosHistoricosConciliados() {
    if (!haySupabase()) {
        setHistoricalPrepareMessage("No se pudo importar porque Supabase no está disponible.", "error")
        return
    }
    if (!tenantActivoId) {
        setHistoricalPrepareMessage("No hay tenant activo para ejecutar la importación histórica.", "error")
        return
    }

    const importableRows = getHistoricalImportableRows()
    if (!importableRows.length) {
        setHistoricalPrepareMessage("No hay registros conciliados válidos disponibles para importar.", "warning")
        return
    }

    const ok = confirm(
        `Se importarán ${importableRows.length} registros históricos conciliados.\n\n` +
        `Esta acción insertará filas reales en la tabla asistencias, quedarán visibles en reportes y saldrán en exportaciones Excel con trazabilidad del lote.\n\n` +
        `¿Deseas continuar con la importación?`
    )
    if (!ok) return

    historicalImportState.importing = true
    resetHistoricalImportSummary()
    updateHistoricalActionState()
    setHistoricalPrepareMessage("Importación histórica en progreso. Verificando duplicados existentes…", "info")

    const summary = buildHistoricalImportSummaryBase()
    const batchId = resolveHistoricalImportBatchId()
    summary.batchId = batchId

    const importMeta = {
        fileName: String(historicalImportState.file?.name || "").trim() || null,
        importedAt: new Date().toISOString(),
        importedBy: resolveHistoricalImportActor()
    }

    try {
        const existingKeys = await fetchHistoricalExistingAttendanceKeys(importableRows)
        const toInsert = []

        importableRows.forEach(row => {
            const key = `${normalizeHistoricalDni(row.dniSugerido)}|${String(row.fecha || "").trim()}`
            if (existingKeys.has(key)) {
                summary.duplicate += 1
                return
            }
            toInsert.push(row)
        })

        for (let index = 0; index < toInsert.length; index += 100) {
            const chunk = toInsert.slice(index, index + 100)
            const chunkSummary = await insertHistoricalImportChunk(chunk, batchId, importMeta)
            summary.imported += chunkSummary.imported
            summary.duplicate += chunkSummary.duplicate
            summary.failed += chunkSummary.failed
        }

        historicalImportState.importSummary = summary
        renderHistoricalImportSummary(summary)
        updateHistoricalActionState()

        registrarActividad("asistencias_importacion_historica", {
            archivo: importMeta.fileName,
            importados: summary.imported,
            duplicados: summary.duplicate,
            fallidos: summary.failed,
            import_batch_id: batchId
        }, { tenantId: tenantActivoId })

        await refreshHistoricalImportViews()

        setHistoricalPrepareMessage(
            `Importación histórica completada correctamente: ${summary.imported} importado(s), ${summary.duplicate} duplicado(s), ${summary.skippedObserved} observado(s) y batch ${shortenHistoricalBatchId(summary.batchId)}.`,
            summary.failed ? "warning" : "ok"
        )
        if (summary.imported > 0) {
            abrirModalExitoImportacionHistorica(summary)
        }
    } catch (error) {
        console.error("Error en importación histórica:", error)
        summary.failed += importableRows.length
        historicalImportState.importSummary = summary
        renderHistoricalImportSummary(summary)
        updateHistoricalActionState()
        setHistoricalPrepareMessage(`No se pudo completar la importación histórica: ${error.message || "error desconocido"}`, "error")
    } finally {
        historicalImportState.importing = false
        updateHistoricalActionState()
    }
}

function filterHistoricalCandidatesByContext(candidates = [], row = {}) {
    if (!candidates.length) return []
    const rowUbo = normalizeHistoricalUbo(row.ubo)

    let scoped = candidates
    if (rowUbo) {
        const sameUbo = scoped.filter(candidate => candidate.ubo && candidate.ubo === rowUbo)
        if (sameUbo.length) scoped = sameUbo
    }
    return scoped
}

function historicalLimitedLevenshtein(a = "", b = "", maxDistance = 2) {
    if (a === b) return 0
    if (!a || !b) return maxDistance + 1
    if (Math.abs(a.length - b.length) > maxDistance) return maxDistance + 1

    let previous = Array.from({ length: b.length + 1 }, (_, index) => index)
    for (let i = 1; i <= a.length; i += 1) {
        const current = [i]
        let minValue = current[0]
        for (let j = 1; j <= b.length; j += 1) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1
            const value = Math.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            current.push(value)
            if (value < minValue) minValue = value
        }
        if (minValue > maxDistance) return maxDistance + 1
        previous = current
    }
    return previous[b.length]
}

function findHistoricalAspiranteCandidates(row, aspirantesIndex) {
    const nombreNormalizado = normalizeHistoricalComparable(row.nombreCompleto)
    const nombreCompacto = normalizeHistoricalComparableCompact(row.nombreCompleto)

    const exactByName = filterHistoricalCandidatesByContext(
        aspirantesIndex.byName.get(nombreNormalizado) || [],
        row
    )
    if (exactByName.length) return exactByName

    const exactByCompact = filterHistoricalCandidatesByContext(
        aspirantesIndex.byCompact.get(nombreCompacto) || [],
        row
    )
    if (exactByCompact.length) return exactByCompact

    if (!row.ubo) return []

    return filterHistoricalCandidatesByContext(aspirantesIndex.all, row).filter(candidate =>
        historicalLimitedLevenshtein(candidate.nombreCompacto, nombreCompacto, 2) <= 2
    )
}

function buildHistoricalConciliationRow(row, aspirantesIndex) {
    const candidates = findHistoricalAspiranteCandidates(row, aspirantesIndex)

    if (candidates.length === 1) {
        const candidate = candidates[0]
        return Object.assign({}, row, {
            conciliacionEstado: "conciliado",
            conciliacionLabel: "✔ Automático",
            conciliacionClase: "is-conciliated",
            dniSugerido: candidate.dni || row.dni || "",
            aspiranteEncontrado: candidate.nombre || row.nombreCompleto || "",
            seccion: row.seccion || "",
            resolvedManually: false
        })
    }

    if (candidates.length > 1) {
        return Object.assign({}, row, {
            conciliacionEstado: "multiple",
            conciliacionLabel: "⚠ Múltiples candidatos",
            conciliacionClase: "is-multiple",
            dniSugerido: "",
            aspiranteEncontrado: `${candidates.length} candidatos`,
            resolvedManually: false,
            observacion: row.observacion === "Sin observaciones"
                ? "Múltiples candidatos en aspirantes"
                : `${row.observacion} · Múltiples candidatos en aspirantes`
        })
    }

    return Object.assign({}, row, {
        conciliacionEstado: "sin_coincidencia",
        conciliacionLabel: "⚠ Sin coincidencia",
        conciliacionClase: "is-no-match",
        dniSugerido: "",
        aspiranteEncontrado: "",
        resolvedManually: false,
        observacion: row.observacion === "Sin observaciones"
            ? "Sin coincidencia en aspirantes"
            : `${row.observacion} · Sin coincidencia en aspirantes`
    })
}

async function reconcileHistoricalPreviewRows(preview = []) {
    if (!preview.length) {
        resetHistoricalReconciliation()
        return preview
    }

    const aspirantesResponse = await fetchHistoricalAspirantesTenant()
    if (!aspirantesResponse.available) {
        historicalImportState.aspirantesCache = {
            rows: [],
            index: null
        }
        const untouched = preview.map(row => Object.assign({}, row, {
            conciliacionEstado: "pendiente",
            conciliacionLabel: "Pendiente",
            conciliacionClase: "is-pending",
            dniSugerido: row.dni || "",
            aspiranteEncontrado: "",
            resolvedManually: false
        }))
        historicalImportState.reconciliation = computeHistoricalReconciliationSummary(untouched, false)
        renderHistoricalReconciliation(
            historicalImportState.reconciliation,
            "warning",
            aspirantesResponse.reason || "No fue posible ejecutar la conciliación."
        )
        return untouched
    }

    const aspirantesIndex = buildHistoricalAspirantesIndex(aspirantesResponse.rows)
    historicalImportState.aspirantesCache = {
        rows: aspirantesResponse.rows || [],
        index: aspirantesIndex
    }

    const reconciled = preview.map(row => buildHistoricalConciliationRow(row, aspirantesIndex))
    const summary = computeHistoricalReconciliationSummary(reconciled, true)
    historicalImportState.reconciliation = summary
    renderHistoricalReconciliation(
        summary,
        summary.pendingReview ? "warning" : "ok",
        summary.conciliated
            ? `Se encontraron ${summary.conciliated} coincidencia(s) de aspirantes. La importación podrá habilitarse en la siguiente fase.`
            : "No se encontraron conciliaciones automáticas. La revisión manual quedará para la siguiente fase."
    )
    return reconciled
}

function parseHistoricalCsvLine(line, delimiter = ",") {
    const cells = []
    let current = ""
    let insideQuotes = false

    for (let i = 0; i < line.length; i += 1) {
        const char = line[i]
        const next = line[i + 1]
        if (char === '"') {
            if (insideQuotes && next === '"') {
                current += '"'
                i += 1
            } else {
                insideQuotes = !insideQuotes
            }
            continue
        }
        if (char === delimiter && !insideQuotes) {
            cells.push(current)
            current = ""
            continue
        }
        current += char
    }

    cells.push(current)
    return cells.map(cell => cell.trim())
}

function parseHistoricalCsv(text) {
    const lines = String(text || "")
        .replace(/^\uFEFF/, "")
        .split(/\r?\n/)
        .filter(line => line.trim() !== "")

    if (!lines.length) return { headers: [], rows: [] }
    const headerLine = lines[0]
    const delimiterCandidates = [",", ";", "\t"]
    const delimiter = delimiterCandidates
        .map(candidate => ({ candidate, count: headerLine.split(candidate).length - 1 }))
        .sort((a, b) => b.count - a.count)[0]?.candidate || ","
    const headers = parseHistoricalCsvLine(headerLine, delimiter)
    const rows = lines.slice(1).map(line => parseHistoricalCsvLine(line, delimiter))
    return { headers, rows }
}

async function readHistoricalImportFile(file) {
    const ext = String(file?.name || "").split(".").pop().toLowerCase()
    if (ext === "csv") {
        const text = await file.text()
        return parseHistoricalCsv(text)
    }

    if (!window.XLSX) {
        // Dependencia requerida para .xlsx/.xls: cargar SheetJS/XLSX antes de validar archivos Excel.
        throw new Error("No está disponible la librería XLSX para leer archivos Excel.")
    }

    const buffer = await file.arrayBuffer()
    const workbook = XLSX.read(buffer, { type: "array", cellDates: true })
    const worksheet = workbook.Sheets[workbook.SheetNames[0]]
    const matrix = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: "", raw: false })
    const headers = (matrix[0] || []).map(value => String(value || "").trim()).filter(Boolean)
    const rows = matrix.slice(1).filter(row =>
        Array.isArray(row) && row.some(cell => String(cell || "").trim() !== "")
    )
    return { headers, rows }
}

function getHistoricalCell(row, columnIndex) {
    if (!Array.isArray(row) || !Number.isInteger(columnIndex) || columnIndex < 0) return ""
    return row[columnIndex] ?? ""
}

async function validateHistoricalRows() {
    const missingFields = HISTORICAL_IMPORT_FIELDS
        .filter(field => !field.optional)
        .filter(field => !Number.isInteger(historicalImportState.mapping[field.key]))
        .map(field => field.label)

    if (missingFields.length) {
        setHistoricalImportMessage(`Completa el mapeo manual para: ${missingFields.join(", ")}.`, "warning")
        setHistoricalPrepareMessage("La acción se habilitará después de validar el archivo.", "info")
        return
    }

    const preview = []
    const stats = {
        total: historicalImportState.rows.length,
        valid: 0,
        duplicates: 0,
        invalidDates: 0,
        missingUbo: 0,
        incompleteName: 0,
        observed: 0
    }
    const dedupe = new Set()
    const dniMapped = hasHistoricalDniMapping()

    historicalImportState.rows.forEach((row, index) => {
        const timestampRaw = getHistoricalCell(row, historicalImportState.mapping.timestamp)
        const dniRaw = dniMapped ? normalizeHistoricalDni(getHistoricalCell(row, historicalImportState.mapping.dni)) : ""
        const nombresRaw = normalizeHistoricalText(getHistoricalCell(row, historicalImportState.mapping.nombres))
        const apellidosRaw = normalizeHistoricalText(getHistoricalCell(row, historicalImportState.mapping.apellidos))
        const uboRaw = normalizeHistoricalUbo(getHistoricalCell(row, historicalImportState.mapping.ubo))
        const seccionRaw = normalizeHistoricalSection(getHistoricalCell(row, historicalImportState.mapping.seccion))
        const timestamp = normalizeHistoricalTimestamp(timestampRaw)
        const nombreCompleto = buildHistoricalFullName(apellidosRaw, nombresRaw)
        const observations = []
        let status = "valido"

        if (!timestamp.valido) {
            observations.push("Fecha u hora inválida")
            stats.invalidDates += 1
            status = "error"
        }

        if (!uboRaw) {
            observations.push("UBO faltante")
            stats.missingUbo += 1
            status = "error"
        }

        if (!nombresRaw || !apellidosRaw) {
            observations.push("Nombres incompletos")
            stats.incompleteName += 1
            status = "error"
        }

        if (dniMapped && !dniRaw) {
            observations.push("DNI faltante")
            if (status !== "error") status = "observado"
        }

        const duplicateKey = dniMapped && dniRaw
            ? `${dniRaw}|${timestamp.fecha}`
            : `${nombreCompleto.toLowerCase()}|${timestamp.fecha}|${timestamp.hora}`
        if (nombreCompleto && timestamp.valido && dedupe.has(duplicateKey)) {
            observations.push(dniMapped && dniRaw ? "Duplicado interno por DNI y fecha" : "Duplicado interno")
            stats.duplicates += 1
            if (status !== "error") status = "observado"
        } else if ((dniMapped ? !!dniRaw : !!nombreCompleto) && timestamp.valido) {
            dedupe.add(duplicateKey)
        }

        if (!seccionRaw) {
            observations.push("Sección faltante")
            if (status !== "error") status = "observado"
        }

        if (status === "valido") stats.valid += 1
        if (status === "observado") stats.observed += 1

        preview.push({
            index: index + 1,
            status,
            fecha: timestamp.fecha,
            hora: timestamp.hora,
            dni: dniRaw,
            ubo: uboRaw,
            nombresExcel: nombresRaw,
            apellidosExcel: apellidosRaw,
            nombreCompleto,
            seccion: seccionRaw,
            conciliacionEstado: "pendiente",
            conciliacionLabel: "Pendiente",
            conciliacionClase: "is-pending",
            dniSugerido: "",
            aspiranteEncontrado: "",
            resolvedManually: false,
            observacion: observations.join(" · ") || "Sin observaciones"
        })
    })

    const previewWithConciliation = await reconcileHistoricalPreviewRows(preview)
    historicalImportState.preview = previewWithConciliation
    historicalImportState.stats = stats
    historicalImportState.validated = true

    resetHistoricalImportStats()
    document.getElementById("historicalKpiTotal").innerText = String(stats.total)
    document.getElementById("historicalKpiValid").innerText = String(stats.valid)
    document.getElementById("historicalKpiDuplicates").innerText = String(stats.duplicates)
    document.getElementById("historicalKpiInvalidDates").innerText = String(stats.invalidDates)
    document.getElementById("historicalKpiMissingUbo").innerText = String(stats.missingUbo)
    document.getElementById("historicalKpiIncompleteName").innerText = String(stats.incompleteName)
    document.getElementById("historicalKpiObserved").innerText = String(stats.observed)
    renderHistoricalPreview(previewWithConciliation)

    if (!previewWithConciliation.length) {
        setHistoricalImportMessage("El archivo no contiene filas utilizables para validar.", "warning")
        setHistoricalPrepareMessage("La acción se habilitará después de validar el archivo.", "info")
        return
    }

    setHistoricalImportMessage(
        `Validación completada: ${stats.valid} válido(s), ${stats.observed} observado(s) y ${previewWithConciliation.length - stats.valid - stats.observed} con error. Si confirmas la importación, los registros se insertarán en asistencias.`,
        stats.invalidDates || stats.missingUbo || stats.incompleteName ? "warning" : "ok"
    )
    setHistoricalPrepareMessage(
        getHistoricalImportableRows().length > 0
            ? `Hay ${getHistoricalImportableRows().length} registro(s) conciliado(s) listo(s) para insertarse en asistencias con trazabilidad.`
            : historicalImportState.reconciliation.conciliated > 0
                ? "Hay conciliaciones, pero todavía faltan campos obligatorios antes de insertar los registros."
                : "Preview validado. La importación real insertará registros en asistencias cuando haya conciliación previa.",
        getHistoricalImportableRows().length > 0 ? "info" : "warning"
    )
    updateHistoricalActionState()
}

async function cargarArchivoHistorico(file) {
    if (!file) return

    const { fileInput, fileMeta } = getHistoricalImportElements()
    historicalImportState = createHistoricalImportState()
    historicalImportState.file = file
    resetHistoricalImportStats()
    resetHistoricalReconciliation()
    resetHistoricalImportSummary()
    renderHistoricalPreview([])
    setHistoricalPrepareMessage("La acción se habilitará después de validar el archivo.", "info")
    updateHistoricalActionState()

    if (fileInput && fileInput.files?.[0] !== file) {
        try {
            const dt = new DataTransfer()
            dt.items.add(file)
            fileInput.files = dt.files
        } catch (_) { }
    }

    if (fileMeta) {
        const sizeKb = `${Math.max(1, Math.round(file.size / 1024))} KB`
        fileMeta.innerText = `${file.name} · ${sizeKb}`
    }

    try {
        const parsed = await readHistoricalImportFile(file)
        if (!parsed.headers.length) {
            setHistoricalImportMessage("No se encontraron encabezados en el archivo seleccionado.", "warning")
            renderHistoricalImportMapping()
            return
        }

        historicalImportState.headers = parsed.headers
        historicalImportState.rows = Array.isArray(parsed.rows) ? parsed.rows : []
        detectHistoricalColumns(parsed.headers)
        renderHistoricalImportMapping()
        updateHistoricalActionState()
        setHistoricalImportMessage(
            `Archivo cargado: ${parsed.headers.length} columna(s) detectadas y ${historicalImportState.rows.length} fila(s) listas para validar.`,
            "info"
        )
    } catch (error) {
        console.error("Error leyendo archivo histórico:", error)
        setHistoricalImportMessage(error.message || "No se pudo leer el archivo seleccionado.", "error")
        renderHistoricalImportMapping()
        updateHistoricalActionState()
    }
}

function abrirSelectorImportacionHistorica() {
    const { fileInput } = getHistoricalImportElements()
    if (fileInput) fileInput.click()
}

async function validarArchivoHistorico() {
    if (!historicalImportState.file) {
        setHistoricalImportMessage("Selecciona un archivo antes de validar.", "warning")
        return
    }
    syncHistoricalMappingFromSelectors()
    await validateHistoricalRows()
}

async function prepararImportacionHistorica() {
    if (!historicalImportState.validated || !historicalImportState.preview.length) {
        setHistoricalPrepareMessage("Primero valida un archivo con registros listos para revisión.", "warning")
        return
    }

    if (historicalImportState.importSummary?.imported > 0) {
        resetHistoricalImportModuleState()
        return
    }

    if (historicalImportState.importing) {
        setHistoricalPrepareMessage("La importación histórica ya está en progreso.", "warning")
        return
    }

    if (getHistoricalImportableRows().length > 0) {
        await importarRegistrosHistoricosConciliados()
        return
    }

    const { conciliated, pendingReview, available } = historicalImportState.reconciliation || {}
    if (!available) {
        setHistoricalPrepareMessage("La conciliación no quedó disponible en esta sesión. La importación sigue bloqueada hasta la siguiente fase.", "warning")
        return
    }
    if (conciliated > 0) {
        setHistoricalPrepareMessage("Se encontraron coincidencias de aspirantes. La importación podrá habilitarse en la siguiente fase.", "info")
        return
    }
    if (pendingReview > 0) {
        setHistoricalPrepareMessage("Hay filas pendientes de revisión por falta de coincidencia o múltiples candidatos. La importación sigue bloqueada.", "warning")
        return
    }
    setHistoricalPrepareMessage("El archivo quedó validado, pero la importación real aún no está habilitada en esta fase.", "info")
}

function bindHistoricalImportEvents() {
    const { fileInput, dropzone, mapping } = getHistoricalImportElements()
    if (!fileInput || !dropzone || !mapping) return

    fileInput.addEventListener("change", async (event) => {
        const file = event.target.files?.[0]
        await cargarArchivoHistorico(file)
    })

    dropzone.addEventListener("click", abrirSelectorImportacionHistorica)
    dropzone.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
            event.preventDefault()
            abrirSelectorImportacionHistorica()
        }
    })

    ;["dragenter", "dragover"].forEach(type => {
        dropzone.addEventListener(type, (event) => {
            event.preventDefault()
            dropzone.classList.add("is-dragover")
        })
    })

    ;["dragleave", "dragend", "drop"].forEach(type => {
        dropzone.addEventListener(type, (event) => {
            event.preventDefault()
            if (type === "drop") {
                const file = event.dataTransfer?.files?.[0]
                if (file) cargarArchivoHistorico(file)
            }
            dropzone.classList.remove("is-dragover")
        })
    })

    mapping.addEventListener("change", (event) => {
        if (!event.target.matches("[data-historical-map]")) return
        syncHistoricalMappingFromSelectors()
        renderHistoricalImportMapping()
        setHistoricalImportMessage("Mapeo actualizado. Vuelve a validar el archivo para refrescar el preview.", "info")
        updateHistoricalActionState()
    })
}

async function cargarAspirantesCargados() {
    const tablaEl = document.getElementById("tablaAspirantesCargados")
    const msgEl = document.getElementById("msgCargaAspirantes")
    if (!tablaEl) return
    try {
        if (!haySupabase()) {
            tablaEl.innerHTML = buildEmptyTableRow(
                5,
                "Sin conexion disponible",
                "No se pudo cargar el listado porque Supabase no esta disponible.",
                "☁️"
            )
            if (msgEl) msgEl.innerText = "No se pudo conectar con asistIA."
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
            console.error("Error cargando aspirantes desde Supabase:", errorAspirantes)
            tablaEl.innerHTML = buildEmptyTableRow(
                5,
                "No se pudo cargar el listado",
                "No se pudo cargar la información.",
                "⚠️"
            )
            if (msgEl) msgEl.innerText = mensajeUsuarioAsistIA(errorAspirantes, "No se pudo cargar la información.")
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
            tablaEl.innerHTML = buildEmptyTableRow(
                5,
                "Sin aspirantes cargados",
                "Todavia no hay aspirantes ni registros asociados para mostrar.",
                "📄"
            )
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
        tablaEl.innerHTML = buildEmptyTableRow(
            5,
            "Error cargando listado",
            "No se pudo completar la carga del listado de aspirantes.",
            "⚠️"
        )
        if (msgEl) msgEl.innerText = mensajeUsuarioAsistIA(e, "No se pudo cargar la información.")
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
    const tenantCursoId = normalizarTenantId(tenantActivoId)
    const cursoId = cursoActualId || 1
    let q = supabaseClient
        .from("curso_jornada_reglas")
        .select("tenant_id,curso_id,seccion,modalidad,dias_semana,hora_inicio,activa")
        .eq("tenant_id", tenantCursoId)
        .eq("curso_id", cursoId)
        .eq("activa", true)

    const { data, error } = await q
        .order("seccion", { ascending: true })
        .order("hora_inicio", { ascending: true })

    if (error) {
        if (esTablaNoExiste(error)) return null
        console.warn("No se pudo cargar curso_jornada_reglas:", error.message)
        return null
    }

    const secciones = deduplicarSeccionesDesdeReglas(data || [])
    console.debug("[asistIA-course-config-debug] cargarSeccionesCursoDesdeSupabase", {
        tenantActivoId: tenantCursoId,
        cursoActualId: cursoId,
        totalFilas: Array.isArray(data) ? data.length : 0,
        totalSecciones: secciones.length
    })
    return secciones
}

async function cargarSedesCursoDesdeSupabase() {
    let q = withTenantScope(supabaseClient.from("curso_sedes_ubo").select("*"))
    q = q.eq("curso_id", cursoActualId || 1)
    const { data, error } = await q
        .order("seccion", { ascending: true })

    if (error) {
        if (esTablaNoExiste(error)) return null
        console.warn("No se pudo cargar curso_sedes_ubo:", error.message)
        return null
    }

    return (data || []).map(x => ({
        seccion: normalizarCodigoSeccion(x.seccion),
        ubo: String(x.ubo || "").trim(),
        modalidad: normalizarModalidad(x.modalidad || "PRESENCIAL"),
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

function normalizarCodigoBombero(valor) {
    return String(valor || "").trim().toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 20)
}

function normalizarTextoSimple(valor) {
    return String(valor || "").trim()
}

function normalizarTextoTitulo(valor) {
    return String(valor || "")
        .trim()
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean)
        .map(parte => parte.charAt(0).toUpperCase() + parte.slice(1))
        .join(" ")
}

function normalizarSoloNumeros(valor) {
    return String(valor || "").replace(/\D/g, "")
}

const STAFF_GRADOS_VALIDOS = Object.freeze([
    "Seccionario",
    "Sub Teniente",
    "Teniente",
    "Capitán",
    "Teniente Brigadier",
    "Brigadier",
    "Brigadier Mayor",
    "Brigadier General"
])

function normalizarGradoStaff(valor) {
    const limpio = normalizarTextoSimple(valor)
    return STAFF_GRADOS_VALIDOS.includes(limpio) ? limpio : ""
}

function normalizarCampoStaffTitulo(input) {
    if (!input) return ""
    const valor = normalizarTextoTitulo(input.value)
    input.value = valor
    return valor
}

function normalizarCampoStaffSoloNumeros(input) {
    if (!input) return ""
    const valor = normalizarSoloNumeros(input.value)
    input.value = valor
    return valor
}

function normalizarStaffRow(row) {
    return {
        id: String(row?.id || "").trim(),
        tenant_id: String(row?.tenant_id || "").trim().toLowerCase(),
        curso_id: row?.curso_id == null ? null : Number(row.curso_id),
        codigo_bombero: normalizarCodigoBombero(row?.codigo_bombero),
        nombres: normalizarTextoTitulo(row?.nombres),
        apellidos: normalizarTextoTitulo(row?.apellidos),
        grado: normalizarGradoStaff(row?.grado),
        ubo_origen: normalizarSoloNumeros(row?.ubo_origen),
        tipo_staff: normalizarTextoSimple(row?.tipo_staff).toUpperCase() || "APOYO",
        celular: normalizarTextoSimple(row?.celular),
        correo: normalizarTextoSimple(row?.correo),
        foto_url: normalizarTextoSimple(row?.foto_url),
        activo: row?.activo !== false
    }
}

function obtenerNombreCompletoStaff(row) {
    return `${normalizarTextoSimple(row?.nombres)} ${normalizarTextoSimple(row?.apellidos)}`.replace(/\s+/g, " ").trim()
}

function obtenerInicialesStaff(row) {
    const nombre = obtenerNombreCompletoStaff(row)
    if (!nombre) return "ST"
    return nombre
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 2)
        .map(part => part[0] || "")
        .join("")
        .toUpperCase()
}

function renderBadgeTipoStaff(tipo) {
    const limpio = String(tipo || "").trim().toUpperCase()
    const cls = limpio === "ADJUNTO" ? "badge-staff-adjunto" : "badge-staff-apoyo"
    return `<span class="badge ${cls}">${limpio || "APOYO"}</span>`
}

function normalizarFechaLimaISO(fechaBase = new Date()) {
    return new Intl.DateTimeFormat("en-CA", {
        timeZone: "America/Lima",
        year: "numeric",
        month: "2-digit",
        day: "2-digit"
    }).format(fechaBase)
}

function obtenerRangoStaffDashboard() {
    const hoy = normalizarFechaLimaISO(new Date())
    const base = new Date(`${hoy}T12:00:00-05:00`)
    const day = base.getDay()
    const diffToMonday = day === 0 ? 6 : day - 1
    const mondayThisWeek = new Date(base)
    mondayThisWeek.setDate(base.getDate() - diffToMonday)
    const mondayLastWeek = new Date(mondayThisWeek)
    mondayLastWeek.setDate(mondayThisWeek.getDate() - 7)
    return {
        hoy,
        from: mondayLastWeek.toISOString().slice(0, 10),
        to: hoy
    }
}

function renderStaffAvatarCompact(row) {
    const foto = normalizarTextoSimple(row?.foto_url)
    const nombre = normalizarTextoSimple(row?.nombre) || obtenerNombreCompletoStaff(row) || "Staff"
    if (foto) return `<img src="${escapeHtml(foto)}" alt="${escapeHtml(nombre)}" class="staff-avatar">`
    return `<span class="staff-avatar-placeholder" aria-hidden="true">${escapeHtml(obtenerInicialesStaff(row))}</span>`
}

async function cargarFotosStaffPorCodigos(codigos = []) {
    const unicos = Array.from(new Set((codigos || []).map(c => normalizarCodigoBombero(c)).filter(Boolean)))
    if (!unicos.length || !haySupabase() || !tenantActivoId) return {}

    const { data, error } = await withTenantScope(
        supabaseClient
            .from("staff_instruccion")
            .select("codigo_bombero,foto_url,nombres,apellidos,grado,tipo_staff,ubo_origen")
            .in("codigo_bombero", unicos)
    )

    if (error) {
        console.warn("No se pudieron cargar fotos staff:", error.message)
        return {}
    }

    return (filtrarDataTenantActivo(data) || []).reduce((acc, item) => {
        const codigo = normalizarCodigoBombero(item.codigo_bombero)
        if (!codigo) return acc
        acc[codigo] = {
            foto_url: normalizarTextoSimple(item.foto_url),
            nombres: normalizarTextoSimple(item.nombres),
            apellidos: normalizarTextoSimple(item.apellidos),
            grado: normalizarTextoSimple(item.grado),
            tipo_staff: normalizarTextoSimple(item.tipo_staff).toUpperCase(),
            ubo_origen: normalizarTextoSimple(item.ubo_origen)
        }
        return acc
    }, {})
}

function toggleHistorialStaffReporte(key) {
    staffReportExpandedKey = staffReportExpandedKey === key ? "" : key
    renderReportesStaff(cacheReportesStaff)
}

function renderStaffAvatar(row) {
    const nombre = obtenerNombreCompletoStaff(row) || "Staff"
    const foto = normalizarTextoSimple(row?.foto_url)
    if (foto) {
        return `<img src="${escapeHtml(foto)}" alt="${escapeHtml(nombre)}" class="staff-avatar">`
    }
    return `<span class="staff-avatar-placeholder" aria-hidden="true">${escapeHtml(obtenerInicialesStaff(row))}</span>`
}

function actualizarPreviewStaffFormulario() {
    const preview = document.getElementById("staffPreviewMini")
    if (!preview) return

    const draft = {
        nombres: staffNombres?.value || "",
        apellidos: staffApellidos?.value || "",
        grado: staffGrado?.value || "",
        tipo_staff: staffTipo?.value || "APOYO"
    }
    const nombre = obtenerNombreCompletoStaff(draft)

    if (!nombre && !normalizarTextoSimple(draft.grado)) {
        preview.hidden = true
        preview.innerHTML = ""
        return
    }

    preview.hidden = false
    preview.innerHTML = `
      ${renderStaffAvatar(draft)}
      <div class="staff-cell-copy">
        <strong>${escapeHtml(nombre || "Nuevo staff")}</strong>
        <span>${escapeHtml(draft.grado || "Sin grado")} · ${escapeHtml(draft.tipo_staff || "APOYO")}</span>
      </div>
    `
}

function actualizarUIModoEdicionStaffInstruccion() {
    const banner = document.getElementById("staffEditBanner")
    const label = document.getElementById("staffEditLabel")
    const btnPrimary = document.getElementById("btnStaffPrimary")
    const btnCancel = document.getElementById("btnStaffCancel")
    const module = document.getElementById("staffModuleGestion")
    const item = staffInstruccionCache.find(row => row.id === editStaffInstruccionId)
    const editando = !!item

    if (banner) banner.hidden = !editando
    if (label) label.textContent = editando ? `${item.codigo_bombero} · ${obtenerNombreCompletoStaff(item)}` : ""
    if (btnPrimary) btnPrimary.textContent = editando ? "GUARDAR CAMBIOS" : "GUARDAR STAFF"
    if (btnCancel) btnCancel.textContent = editando ? "Cancelar edición" : "Limpiar formulario"
    if (module) module.classList.toggle("course-module--editing", editando)
}

function limpiarFormStaffInstruccion() {
    if (staffCodigoBombero) staffCodigoBombero.value = ""
    if (staffNombres) staffNombres.value = ""
    if (staffApellidos) staffApellidos.value = ""
    if (staffGrado) staffGrado.value = ""
    if (staffUboOrigen) staffUboOrigen.value = ""
    if (staffTipo) staffTipo.value = "APOYO"
    if (staffCelular) staffCelular.value = ""
    if (staffCorreo) staffCorreo.value = ""
    if (staffActivo) staffActivo.checked = true
    editStaffInstruccionId = null
    actualizarPreviewStaffFormulario()
    actualizarUIModoEdicionStaffInstruccion()
}

function cancelarEdicionStaffInstruccion() {
    limpiarFormStaffInstruccion()
    mostrarMsgCursoModulo("msgStaffInstruccion", "", "")
}

function poblarFormularioStaffInstruccion(item) {
    if (!item) return
    if (staffCodigoBombero) staffCodigoBombero.value = item.codigo_bombero || ""
    if (staffNombres) staffNombres.value = item.nombres || ""
    if (staffApellidos) staffApellidos.value = item.apellidos || ""
    if (staffGrado) staffGrado.value = normalizarGradoStaff(item.grado)
    if (staffUboOrigen) staffUboOrigen.value = item.ubo_origen || ""
    if (staffTipo) staffTipo.value = item.tipo_staff || "APOYO"
    if (staffCelular) staffCelular.value = item.celular || ""
    if (staffCorreo) staffCorreo.value = item.correo || ""
    if (staffActivo) staffActivo.checked = item.activo !== false
    editStaffInstruccionId = item.id
    actualizarPreviewStaffFormulario()
    actualizarUIModoEdicionStaffInstruccion()
}

function editarStaffInstruccion(id) {
    const item = staffInstruccionCache.find(row => row.id === id)
    if (!item) return
    poblarFormularioStaffInstruccion(item)
    mostrarMsgCursoModulo("msgStaffInstruccion", "", "")
}

function renderStaffInstruccion() {
    if (!tablaStaffInstruccion) return

    const filtroTexto = String(staffFiltroTexto?.value || "").trim().toLowerCase()
    const filtroTipo = String(staffFiltroTipo?.value || "").trim().toUpperCase()
    const filtroEstado = String(staffFiltroEstado?.value || "").trim().toLowerCase()

    const rows = staffInstruccionCache
        .filter(item => {
            if (filtroTipo && item.tipo_staff !== filtroTipo) return false
            if (filtroEstado === "activo" && item.activo !== true) return false
            if (filtroEstado === "inactivo" && item.activo !== false) return false
            if (!filtroTexto) return true
            const blob = [
                item.codigo_bombero,
                item.nombres,
                item.apellidos,
                item.grado,
                item.ubo_origen,
                item.celular,
                item.correo
            ].join(" ").toLowerCase()
            return blob.includes(filtroTexto)
        })
        .sort((a, b) => {
            if (a.activo !== b.activo) return a.activo ? -1 : 1
            return `${a.apellidos} ${a.nombres}`.localeCompare(`${b.apellidos} ${b.nombres}`, "es", { sensitivity: "base" })
        })

    if (!rows.length) {
        tablaStaffInstruccion.innerHTML = buildEmptyTableRow(
            9,
            "Sin staff registrado",
            "No hay resultados para el filtro aplicado o aun no se ha cargado personal de instruccion.",
            "🧑‍🚒"
        )
        return
    }

    let html = ""
    rows.forEach(item => {
        html += `
          <tr>
            <td>
              <div class="staff-cell">
                ${renderStaffAvatar(item)}
                <div class="staff-cell-copy">
                  <strong>${escapeHtml(obtenerNombreCompletoStaff(item) || "Sin nombre")}</strong>
                  <span>${escapeHtml(item.grado || "Sin grado")}</span>
                </div>
              </div>
            </td>
            <td>${escapeHtml(item.codigo_bombero || "-")}</td>
            <td>${escapeHtml(item.grado || "-")}</td>
            <td>${escapeHtml(item.ubo_origen || "-")}</td>
            <td>${renderBadgeTipoStaff(item.tipo_staff)}</td>
            <td>${escapeHtml(item.celular || "-")}</td>
            <td>${escapeHtml(item.correo || "-")}</td>
            <td>${renderBadgeEstado(item.activo !== false)}</td>
            <td>
              <div class="table-actions">
                <button type="button" onclick="editarStaffInstruccion('${item.id}')">Editar</button>
                <button type="button" class="secondary" onclick="toggleActivoStaffInstruccion('${item.id}', ${item.activo ? "false" : "true"})">
                  ${item.activo ? "Desactivar" : "Activar"}
                </button>
              </div>
            </td>
          </tr>
        `
    })

    tablaStaffInstruccion.innerHTML = html
}

async function cargarStaffInstruccion() {
    if (!tablaStaffInstruccion) return
    if (!haySupabase() || !tenantActivoId) {
        tablaStaffInstruccion.innerHTML = buildEmptyTableRow(
            9,
            "Sin conexión disponible",
            "No se pudo preparar el módulo staff porque falta Supabase o el tenant activo.",
            "⚠️"
        )
        return
    }

    const { data, error } = await withTenantScope(
        supabaseClient
            .from("staff_instruccion")
            .select("*")
            .order("activo", { ascending: false })
            .order("apellidos", { ascending: true })
            .order("nombres", { ascending: true })
    )

    if (error) {
        staffInstruccionCache = []
        tablaStaffInstruccion.innerHTML = buildEmptyTableRow(
            9,
            "Tabla staff_instruccion no disponible",
            esTablaNoExiste(error)
                ? "Aplica primero el SQL sugerido para habilitar este módulo."
                : `No se pudo cargar el staff: ${error.message || "error desconocido"}`,
            "⚠️"
        )
        return
    }

    staffInstruccionCache = filtrarDataTenantActivo(data).map(normalizarStaffRow)
    renderStaffInstruccion()
    actualizarUIModoEdicionStaffInstruccion()
}

async function guardarStaffInstruccion() {
    if (!haySupabase() || !tenantActivoId) {
        mostrarMsgCursoModulo("msgStaffInstruccion", "Sin conexión a Supabase o sin tenant activo.", "error")
        return
    }

    const codigo = normalizarCodigoBombero(staffCodigoBombero?.value)
    const nombresValor = normalizarCampoStaffTitulo(staffNombres)
    const apellidosValor = normalizarCampoStaffTitulo(staffApellidos)
    const gradoValor = normalizarGradoStaff(staffGrado?.value)
    const uboOrigenValor = normalizarCampoStaffSoloNumeros(staffUboOrigen)
    const tipoStaff = String(staffTipo?.value || "APOYO").trim().toUpperCase()
    const fueEdicion = !!editStaffInstruccionId

    if (staffCodigoBombero) staffCodigoBombero.value = codigo
    if (staffGrado) staffGrado.value = gradoValor

    if (!codigo) {
        mostrarMsgCursoModulo("msgStaffInstruccion", "Ingresa el Código de Bombero.", "error")
        return
    }
    if (!nombresValor || !apellidosValor) {
        mostrarMsgCursoModulo("msgStaffInstruccion", "Completa nombres y apellidos.", "error")
        return
    }
    if (!["APOYO", "ADJUNTO"].includes(tipoStaff)) {
        mostrarMsgCursoModulo("msgStaffInstruccion", "El tipo staff debe ser APOYO o ADJUNTO.", "error")
        return
    }
    if (staffGrado?.value && !gradoValor) {
        mostrarMsgCursoModulo("msgStaffInstruccion", "Selecciona un grado válido.", "error")
        return
    }
    if (staffUboOrigen?.value && !uboOrigenValor) {
        mostrarMsgCursoModulo("msgStaffInstruccion", "La UBO origen debe contener solo números.", "error")
        return
    }

    const duplicado = staffInstruccionCache.find(item =>
        item.codigo_bombero === codigo && item.id !== editStaffInstruccionId
    )
    if (duplicado) {
        mostrarMsgCursoModulo("msgStaffInstruccion", "Ya existe otro registro staff con ese Código de Bombero.", "error")
        return
    }

    const payload = withTenantPayload({
        curso_id: Number(cursoActualId || 1) || null,
        codigo_bombero: codigo,
        nombres: nombresValor,
        apellidos: apellidosValor,
        grado: gradoValor || null,
        ubo_origen: uboOrigenValor || null,
        tipo_staff: tipoStaff,
        celular: normalizarTextoSimple(staffCelular?.value) || null,
        correo: normalizarTextoSimple(staffCorreo?.value) || null,
        activo: staffActivo?.checked !== false,
        updated_at: new Date().toISOString()
    })

    let error = null
    if (fueEdicion) {
        ;({ error } = await withTenantScope(
            supabaseClient
                .from("staff_instruccion")
                .update(payload)
        ).eq("id", editStaffInstruccionId))
    } else {
        ;({ error } = await supabaseClient
            .from("staff_instruccion")
            .insert([payload]))
    }

    if (error) {
        mostrarMsgCursoModulo(
            "msgStaffInstruccion",
            /duplicate key|23505/i.test(String(error.message || ""))
                ? "Ya existe un staff con ese Código de Bombero en esta institución."
                : `No se pudo guardar el staff: ${error.message || "error desconocido"}`,
            "error"
        )
        return
    }

    await cargarStaffInstruccion()
    await cargarReportesStaff()
    limpiarFormStaffInstruccion()
    mostrarMsgCursoModulo(
        "msgStaffInstruccion",
        fueEdicion ? "Staff actualizado correctamente." : "Staff registrado correctamente.",
        "ok"
    )
    registrarActividad(
        fueEdicion ? "staff_instruccion_editado" : "staff_instruccion_creado",
        { codigoBombero: codigo, tipoStaff },
        { tenantId: tenantActivoId }
    )
}

async function toggleActivoStaffInstruccion(id, siguienteEstado) {
    if (!haySupabase() || !tenantActivoId) return
    const item = staffInstruccionCache.find(row => row.id === id)
    if (!item) return

    const { error } = await withTenantScope(
        supabaseClient
            .from("staff_instruccion")
            .update({
                activo: !!siguienteEstado,
                updated_at: new Date().toISOString()
            })
    ).eq("id", id)

    if (error) {
        mostrarMsgCursoModulo("msgStaffInstruccion", `No se pudo actualizar el estado: ${error.message || "error desconocido"}`, "error")
        return
    }

    await cargarStaffInstruccion()
    registrarActividad(
        siguienteEstado ? "staff_instruccion_activado" : "staff_instruccion_desactivado",
        { codigoBombero: item.codigo_bombero, tipoStaff: item.tipo_staff },
        { tenantId: tenantActivoId }
    )
}

function renderReportesStaff(data) {
    if (!tablaStaffReportes) return
    const rows = Array.isArray(data) ? data.slice() : []
    cacheReportesStaff = rows

    if (!rows.length) {
        tablaStaffReportes.innerHTML = buildEmptyStateHTML(
            "Sin registros de staff",
            "Ajusta el rango, el tipo o la UBO para consultar asistencias de APOYO y ADJUNTO.",
            "🗂️"
        )
        return
    }

    let html = `
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Fecha</th>
              <th>Hora ingreso</th>
              <th>Código</th>
              <th>Nombre</th>
              <th>Grado</th>
              <th>UBO origen</th>
              <th>Tipo staff</th>
              <th>Jornada</th>
              <th>Historial</th>
            </tr>
          </thead>
          <tbody>
    `

    const grupos = rows.reduce((acc, row) => {
        const key = normalizarCodigoBombero(row.codigo_bombero)
        if (!key) return acc
        if (!acc[key]) acc[key] = []
        acc[key].push(row)
        return acc
    }, {})

    rows.forEach((r, index) => {
        const codigoKey = normalizarCodigoBombero(r.codigo_bombero) || `staff_${index}`
        const rowKey = `${codigoKey}_${index}`
        const historial = (grupos[codigoKey] || []).slice().sort((a, b) => `${b.fecha || ""} ${b.hora_ingreso || ""}`.localeCompare(`${a.fecha || ""} ${a.hora_ingreso || ""}`))
        const expanded = staffReportExpandedKey === rowKey
        html += `
          <tr>
            <td>${escapeHtml(r.fecha || "")}</td>
            <td>${escapeHtml(r.hora_ingreso || "")}</td>
            <td>${escapeHtml(r.codigo_bombero || "")}</td>
            <td>${escapeHtml(r.nombre || "")}</td>
            <td>${escapeHtml(r.grado || "-")}</td>
            <td>${escapeHtml(r.ubo_origen || "-")}</td>
            <td>${renderBadgeTipoStaff(r.tipo_staff)}</td>
            <td>${escapeHtml(r.jornada || "-")}</td>
            <td>
              <button type="button" class="btn-link staff-history-toggle" onclick="toggleHistorialStaffReporte('${rowKey}')">
                ${expanded ? "▼ Ocultar historial" : "▶ Ver historial"}
              </button>
            </td>
          </tr>
        `
        if (expanded) {
            html += `
              <tr class="staff-history-row">
                <td colspan="9">
                  <div class="staff-history-card">
                    <div class="staff-history-head">
                      <div class="staff-cell">
                        ${renderStaffAvatarCompact(r)}
                        <div class="staff-cell-copy">
                          <strong>${escapeHtml(r.nombre || "Staff")}</strong>
                          <span>${escapeHtml(r.grado || "Sin grado")} · ${escapeHtml(r.codigo_bombero || "-")}</span>
                        </div>
                      </div>
                      <div class="staff-history-meta">
                        <div><strong>Tipo staff</strong><span>${escapeHtml(r.tipo_staff || "APOYO")}</span></div>
                        <div><strong>UBO origen</strong><span>${escapeHtml(r.ubo_origen || "-")}</span></div>
                        <div><strong>Total asistencias visibles</strong><span>${historial.length}</span></div>
                      </div>
                    </div>
                    <div class="staff-history-list">
                      ${historial.map(item => `
                        <div class="staff-history-item">
                          <strong>${escapeHtml(item.fecha || "-")}</strong>
                          <span>${escapeHtml(item.hora_ingreso || "--:--")} · ${escapeHtml(item.jornada || "-")}</span>
                        </div>
                      `).join("")}
                    </div>
                  </div>
                </td>
              </tr>
            `
        }
    })

    html += `
          </tbody>
        </table>
      </div>
      <div style="margin-top:10px;font-weight:bold;">Total registros staff: ${rows.length}</div>
    `

    tablaStaffReportes.innerHTML = html
}

async function cargarReportesStaff() {
    if (!tablaStaffReportes) return
    const tenantRuta = resolverAccesoDesdeRuta()
    const tenantReporteId = normalizarTenantId(tenantRuta?.tenantId || tenantActivoId || "")

    console.log("[asistIA-staff-report-debug] contexto tenant", {
        tenantActivoId,
        tenantRuta: tenantRuta?.tenantId || "",
        tenantReporteId
    })

    if (!haySupabase() || !tenantReporteId) {
        tablaStaffReportes.innerHTML = buildEmptyStateHTML(
            "Sin conexión disponible",
            "No se pudo cargar el reporte staff porque falta Supabase o el tenant activo.",
            "⚠️"
        )
        return
    }

    let q = supabaseClient
        .from("staff_asistencias")
        .select("fecha,hora_ingreso,codigo_bombero,nombre,grado,ubo_origen,tipo_staff,jornada,tenant_id")

    if (tenantReporteId) {
        q = q.eq("tenant_id", tenantReporteId)
    }

    if (staffReporteDesde?.value) q = q.gte("fecha", staffReporteDesde.value)
    if (staffReporteHasta?.value) q = q.lte("fecha", staffReporteHasta.value)
    if (staffReporteTipo?.value) q = q.eq("tipo_staff", staffReporteTipo.value)
    if (staffReporteUbo?.value) q = q.ilike("ubo_origen", `%${String(staffReporteUbo.value || "").trim()}%`)

    console.log("[asistIA-staff-report-debug] filtros", {
        desde: staffReporteDesde?.value || "",
        hasta: staffReporteHasta?.value || "",
        tipo: staffReporteTipo?.value || "",
        ubo: String(staffReporteUbo?.value || "").trim()
    })

    let data = []
    try {
        const response = await q
            .order("fecha", { ascending: false })
            .order("hora_ingreso", { ascending: false })
        data = response.data || []

        console.log("[asistIA-staff-report-debug] filas supabase", {
            total: data.length
        })

        if (response.error) {
            console.error("Error cargando reportes staff:", response.error)
            tablaStaffReportes.innerHTML = buildEmptyStateHTML(
                "No se pudo cargar el reporte",
                esTablaNoExiste(response.error)
                    ? "No se pudo cargar la información."
                    : mensajeUsuarioAsistIA(response.error, "No se pudo cargar la información."),
                "⚠️"
            )
            cacheReportesStaff = []
            return
        }
    } catch (error) {
        console.error("Error inesperado cargando reportes staff:", error)
        tablaStaffReportes.innerHTML = buildEmptyStateHTML(
            "No se pudo cargar el reporte",
            mensajeUsuarioAsistIA(error, "No se pudo cargar la información."),
            "⚠️"
        )
        cacheReportesStaff = []
        return
    }

    const rowsFiltradasTenant = (data || []).filter(item =>
        String(item?.tenant_id || "").trim().toLowerCase() === tenantReporteId
    )

    console.log("[asistIA-staff-report-debug] filas locales", {
        total: rowsFiltradasTenant.length
    })

    const baseRows = rowsFiltradasTenant.map(item => ({
        fecha: item.fecha || "",
        hora_ingreso: item.hora_ingreso || "",
        codigo_bombero: normalizarCodigoBombero(item.codigo_bombero),
        nombre: normalizarTextoSimple(item.nombre),
        grado: normalizarTextoSimple(item.grado),
        ubo_origen: normalizarTextoSimple(item.ubo_origen),
        tipo_staff: normalizarTextoSimple(item.tipo_staff).toUpperCase(),
        jornada: normalizarTextoSimple(item.jornada)
    }))
    let fotoMap = {}
    try {
        fotoMap = await cargarFotosStaffPorCodigos(baseRows.map(item => item.codigo_bombero))
    } catch (error) {
        console.error("Error cargando fotos staff para reportes:", error)
        fotoMap = {}
    }
    const rows = baseRows.map(item => ({
        ...item,
        foto_url: fotoMap[item.codigo_bombero]?.foto_url || ""
    }))
    renderReportesStaff(rows)
}

function limpiarFiltrosStaffReportes() {
    const { from, to } = obtenerRangoMesActual()
    if (staffReporteDesde) staffReporteDesde.value = from
    if (staffReporteHasta) staffReporteHasta.value = to
    if (staffReporteTipo) staffReporteTipo.value = ""
    if (staffReporteUbo) staffReporteUbo.value = ""
    staffReportExpandedKey = ""
    if (tablaStaffReportes) {
        tablaStaffReportes.innerHTML = buildEmptyStateHTML(
            "Filtros restablecidos",
            "Presiona Aplicar para consultar nuevamente el reporte staff.",
            "📋"
        )
    }
}

function limpiarCargaAspirantesUI() {
    if (archivoAspirantes) archivoAspirantes.value = ""
    if (msgCargaAspirantes) msgCargaAspirantes.innerText = ""
    if (tablaAspirantesCargados) {
        tablaAspirantesCargados.innerHTML = buildEmptyTableRow(
            5,
            "Vista limpiada",
            "La carga local y el preview del módulo fueron restablecidos. No se modificaron datos guardados.",
            "🧹"
        )
    }
}

function actualizarUIModoEdicionSeccion() {
    const btn = document.getElementById("btnSecCursoPrimary")
    const btnCancel = document.getElementById("btnSecCursoCancel")
    const banner = document.getElementById("courseSecEditBanner")
    const label = document.getElementById("courseSecEditLabel")
    const module = document.getElementById("courseModuleSecciones")
    const legacyDisabled = false
    const inputs = [
        document.getElementById("secCursoNombre"),
        document.getElementById("secCursoModalidad"),
        document.getElementById("secCursoHora"),
        document.getElementById("secCursoDiasSelect")
    ]
    const editing = editSeccionCursoIndex >= 0
    if (btn) {
        btn.textContent = editing ? "GUARDAR CAMBIOS" : "CREAR SECCIÓN"
        btn.disabled = false
        btn.title = ""
    }
    if (btnCancel) {
        btnCancel.textContent = editing ? "Cancelar edición" : "Limpiar formulario"
        btnCancel.disabled = false
    }
    inputs.forEach(input => {
        if (!input) return
        input.disabled = false
        input.title = ""
    })
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
    const upcomingDisabled = true
    const inputs = [
        document.getElementById("uboSecNombre"),
        document.getElementById("uboSecUbo"),
        document.getElementById("uboSecHora"),
        document.getElementById("uboSecModalidad"),
        document.getElementById("uboSecDiasSelect"),
        document.getElementById("uboSecTodosDias")
    ]
    const editing = editSedeUboIndex >= 0
    if (btn) {
        btn.textContent = "PRÓXIMAMENTE"
        btn.disabled = upcomingDisabled
        btn.title = "La activación de este módulo será revisada en una próxima versión."
    }
    if (btnCancel) {
        btnCancel.textContent = "Próximamente"
        btnCancel.disabled = upcomingDisabled
    }
    inputs.forEach(input => {
        if (!input) return
        input.disabled = upcomingDisabled
        input.title = "La activación de este módulo será revisada en una próxima versión."
    })
    if (banner) banner.hidden = true
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

function abrirInfoSedeUboProximamente(event) {
    if (event) {
        event.preventDefault()
        event.stopPropagation()
    }
    const m = document.getElementById("modal")
    const mT = document.getElementById("modalTitulo")
    const mC = document.getElementById("modalContenido")
    if (mT) mT.innerText = "Función próximamente"
    if (mC) {
        mC.innerHTML = buildEmptyStateHTML(
            "Función próximamente",
            "La asignación de UBO sede por sección será implementada en una próxima versión.",
            "🧭"
        )
    }
    if (m) m.style.display = "flex"
}

function activarInfoSedeUboProximamente(event) {
    if (!event) return
    if (event.key === "Enter" || event.key === " ") {
        abrirInfoSedeUboProximamente(event)
    }
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
    renderModuloQrCurso()
}

async function cargarConfigCurso() {
    const cursoBase = await cargarCursoBaseDesdeSupabase()
    let q = withTenantScope(supabaseClient.from("curso_configuracion").select("*"))
    const { data, error } = await q
        .maybeSingle()

    if (error) {
        console.warn("No se pudo cargar curso_configuracion:", error.message)
        cursoConfigCache = cursoBase ? {
            nombre_curso: cursoBase.nombre || "",
            fecha_inicio: cursoBase.fecha_inicio || null,
            fecha_fin: cursoBase.fecha_fin || null,
            radio_m: 50,
            gps_activo: false
        } : null
        await aplicarCursoEnUI(cursoConfigCache)
        return
    }

    cursoConfigCache = data
        ? Object.assign({}, data, {
            nombre_curso: data.nombre_curso || cursoBase?.nombre || ""
        })
        : (cursoBase ? {
            nombre_curso: cursoBase.nombre || "",
            fecha_inicio: cursoBase.fecha_inicio || null,
            fecha_fin: cursoBase.fecha_fin || null,
            radio_m: 50,
            gps_activo: false
        } : null)
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

function aplicarLayout() {
    console.trace("aplicarLayout ejecutado")
    if (estaInputDniMovilActivo()) {
        actualizarBotonesVista()
        return
    }
    const elTenant = document.getElementById("tenantScreen")
    const elLogin = document.getElementById("loginScreen")
    const elDesktop = document.getElementById("vistaDesktop")
    const elLuizLabs = document.getElementById("vistaLuizLabs")
    const elBtnInstitucion = document.getElementById("btnInstitucion")
    const elBtnVolverLuizLabs = document.getElementById("btnVolverLuizLabs")
    const vista = getVistaActiva()

    // --- Lógica de Title Dinámico ---
    if (!accesoDirectoInstitucion) {
        document.title = "asistIA - Panel Administrativo";
    } else {
        const t = obtenerInstitucionLuiz(tenantActivoId);
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
            if (elTenant) elTenant.style.display = "none"
            if (elLogin) elLogin.style.display = "none"
            if (elLuizLabs) elLuizLabs.style.display = "none"
            if (elDesktop) elDesktop.style.display = "block"
            aplicarRestriccionesPanelPorContexto()
            if (!vistaAdminActual) {
                mostrarVista("reportes")
            }
        } else {
            if (!esModoStaff) {
                if (elTenant) elTenant.style.display = "none"
                if (elLogin) elLogin.style.display = "flex"
                if (elDesktop) elDesktop.style.display = "none"
                if (elLuizLabs) elLuizLabs.style.display = "none"
                actualizarBotonesVista()
                aplicarVisibilidadAccesoAdminInstitucional()
                return
            }
            if (puedeEntrarPanelLuizLabs()) {
                if (elTenant) elTenant.style.display = "none"
                if (elLogin) elLogin.style.display = "none"
                if (elDesktop) elDesktop.style.display = "none"
                if (elLuizLabs) elLuizLabs.style.display = "block"
                renderPanelLuizLabs()
                return
            }
            if (elTenant) elTenant.style.display = "none"
            if (elLogin) elLogin.style.display = "none"
            if (elDesktop) elDesktop.style.display = "none"
            if (elLuizLabs) elLuizLabs.style.display = "none"
            if (elTenant) elTenant.style.display = "flex"
        }
    } else {
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
    if (typeof evaluarInicioTutorialAutomatico === "function") {
        evaluarInicioTutorialAutomatico()
    }
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
    if (redirigirRutaPublicaModernaSiCorresponde()) return
    if (redirigirRutaPublicaLegadaCurso()) return
    if (redirigirRutaBackofficeLegada()) return
    enlazarIdsGlobales()
    enlazarAccionesCuentaHeader()
    bindHistoricalImportEvents()
    renderHistoricalImportMapping()
    resetHistoricalImportStats()
    resetHistoricalReconciliation()
    resetHistoricalImportSummary()
    renderHistoricalPreview([])
    updateHistoricalActionState()
    await cargarLuizLabsDesdeStorage()
    renderTenantSelector()
    cargarSesionAdminDesdeStorage()
    sincronizarPermisosPanelInstitucional()
    aplicarAccesoDesdeRuta()
    await actualizarTenantScopeBackendReady()
    await resolverCursoDesdeURL()

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
        try {
            await cargarStaffInstruccion()
        } catch (e) {
            console.error("Error cargando staff de instruccion:", e)
        }
        try {
            await cargarReportesStaff()
        } catch (e) {
            console.error("Error cargando reportes staff:", e)
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
        if (estaEnFlujoMovilPublico()) {
            actualizarBotonesVista()
            aplicarVisibilidadAccesoAdminInstitucional()
            actualizarInfoSesionHeader()
        } else {
            aplicarLayout()
        }
    } catch (e) {
        console.error("Error aplicando layout final:", e)
    }

    if (supabaseClient) {
        const { data: authData } = await supabaseClient.auth.getUser();
        if (authData?.user) {
            await bootstrapAuthorizedApp();
        }
    }

    ;[
        "staffCodigoBombero",
        "staffNombres",
        "staffApellidos",
        "staffGrado",
        "staffUboOrigen",
        "staffTipo",
        "staffCelular",
        "staffCorreo",
        "staffActivo"
    ].forEach(id => {
        const handler = () => {
            if (id === "staffCodigoBombero" && staffCodigoBombero) {
                staffCodigoBombero.value = normalizarCodigoBombero(staffCodigoBombero.value)
            }
            if (id === "staffUboOrigen" && staffUboOrigen) {
                staffUboOrigen.value = normalizarSoloNumeros(staffUboOrigen.value)
            }
            actualizarPreviewStaffFormulario()
        }
        document.getElementById(id)?.addEventListener("input", handler)
        document.getElementById(id)?.addEventListener("change", handler)
    })

    staffNombres?.addEventListener("blur", () => {
        normalizarCampoStaffTitulo(staffNombres)
        actualizarPreviewStaffFormulario()
    })
    staffApellidos?.addEventListener("blur", () => {
        normalizarCampoStaffTitulo(staffApellidos)
        actualizarPreviewStaffFormulario()
    })
    staffUboOrigen?.addEventListener("blur", () => {
        normalizarCampoStaffSoloNumeros(staffUboOrigen)
        actualizarPreviewStaffFormulario()
    })

}

async function autenticarAdminConSupabaseAuth(usuario, clave) {
    if (!haySupabase()) return { ok: false, intentado: false }
    const userDb = (usuariosAdmin || []).find(u => u.usuario === usuario)

    const candidatos = []
    const correoDb = userDb ? String(userDb.correo || "").trim().toLowerCase() : ""
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
        try {
            const { data, error } = await supabaseClient.auth.signInWithPassword({
                email,
                password: clave
            })

            if (error || !data?.user || !data?.session) {
                try {
                    await supabaseClient.auth.signOut()
                } catch (_) { }
                continue
            }

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
        } catch (error) {
            console.error("Error autenticando con Supabase Auth:", error)
            try {
                await supabaseClient.auth.signOut()
            } catch (_) { }
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
    limpiarCurrentProfileVisual()
    actualizarInfoSesionHeader()
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
    sincronizarPermisosPanelInstitucional()
    registrarActividad("login_admin_institucional", {
        via: "acceso_administrativo_ruta",
        usuario: resultado.usuario,
        rol: resultado.rol
    }, { tenantId: tenant.id, usuario: resultado.usuario, rol: resultado.rol })

    cerrarAccesoAdminInstitucional()
    aplicarLayout()
    mostrarVista("reportes")
    cargarDatos()

    await bootstrapAuthorizedApp();
}

async function login() {
    try {
        const usuario = (loginUser.value || "").trim().toLowerCase()
        const clave = (loginPass.value || "").trim()
        await asegurarUsuariosAdminPrevioLogin(usuario)
        limpiarCurrentProfileVisual()
        actualizarInfoSesionHeader()
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
                loginMsg.innerText = "La sesión expiró. Vuelve a iniciar sesión."
                return
            }
        }

        if (resultado.valido) {
            if (esModoStaff) {
                if (resultado.rol !== ROLES_ADMIN.SUPERUSUARIO) {
                    loginMsg.innerText = "Solo superusuario puede ingresar desde esta ruta."
                    return
                }
                setSesionAdminActiva({
                    autenticado: true,
                    usuario: resultado.usuario,
                    rol: resultado.rol,
                    tenantId: "",
                    origen: "staff_root",
                    perfilId: resultado.perfilId || ""
                })
                sincronizarPermisosPanelInstitucional()
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
            sincronizarPermisosPanelInstitucional()
            registrarActividad("login_admin", {
                via: "tenant_login",
                usuario: resultado.usuario,
                rol: resultado.rol
            }, { usuario: resultado.usuario, rol: resultado.rol, tenantId: tenantActivoId })
            aplicarLayout()
            mostrarVista("reportes")
            cargarDatos()
            await bootstrapAuthorizedApp();
        } else {
            loginMsg.innerText = resultado.motivo === "perfil_inactivo"
                ? "Perfil inactivo. Contacta a Luiz Labs."
                : "Usuario o clave incorrecta"
        }
    } catch (error) {
        console.error("Error en login:", error)
        loginMsg.innerText = mensajeUsuarioAsistIA(error, "Ocurrió un problema al procesar la solicitud.")
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

function togglePasswordVisibility(inputId, triggerEl) {
    const input = document.getElementById(inputId)
    if (!input || !triggerEl) return

    const visible = input.type === "text"
    input.type = visible ? "password" : "text"
    triggerEl.classList.toggle("is-visible", !visible)
    triggerEl.setAttribute("aria-label", visible ? "Mostrar clave" : "Ocultar clave")
    triggerEl.setAttribute("title", visible ? "Mostrar clave" : "Ocultar clave")
    const icon = triggerEl.querySelector(".password-toggle-icon")
    if (icon) icon.textContent = visible ? "◉" : "◌"
}

function abrirModalRecuperacionAcceso() {
    modalTitulo.innerText = "Recuperar acceso"
    modalContenido.innerHTML = `
      <div class="empty-state empty-state-compact">
        <div class="empty-state-icon" aria-hidden="true">🔐</div>
        <div class="empty-state-title">Recuperar acceso</div>
        <div class="empty-state-text">Solicita a un administrador de tu institución que restablezca tu clave.</div>
        <button type="button" class="secondary" onclick="cerrarModal()">Entendido</button>
      </div>
    `
    modal.style.display = "flex"
}

let logoutInProgress = false
async function logout() {
    if (logoutInProgress) return
    logoutInProgress = true

    // 2. Deshabilitar botones de Salir visualmente y bloquear interacciones
    const logoutButtons = ["btnSalirTenant", "btnHeaderLogout", "btnHeaderLogoutLuiz", "btnCuentaLogout"]
    logoutButtons.forEach(id => {
        const btn = document.getElementById(id)
        if (btn) {
            btn.disabled = true
            btn.textContent = "Saliendo..."
        }
    })

    const sesionPrev = obtenerSesionAdminActiva()
    const origenSesion = sesionPrev.origen || ""
    const usuarioPrev = sesionPrev.usuario || ""
    const rolPrev = sesionPrev.rol || ""
    const tenantIdPrev = sesionPrev.tenantId || tenantActivoId || ""

    // 3. Capturar path actual y preparar redirección
    let destino = window.location.pathname
    if (accesoDirectoInstitucion && origenSesion === "staff_root") {
        destino = "/"
    }

    const urlObj = new URL(window.location.href)
    urlObj.pathname = destino
    urlObj.searchParams.set("logout", "1")
    urlObj.searchParams.set("t", Date.now().toString())
    const destinoFinal = urlObj.pathname + urlObj.search

    // 6. Limpiar localStorage/sessionStorage de sesión de inmediato (sincrónico)
    resetEstadoSesionAdminUI()

    // 7. Limpiar variables globales (sincrónico, sin aplicar layouts visuales intermedios)
    sesionAdminActiva = crearSesionAdminVacia()

    // Helper para ejecutar promesas asíncronas con un timeout corto
    const runWithTimeout = (promise, ms) => {
        return new Promise(resolve => {
            const timer = setTimeout(() => {
                console.warn(`[logout] Timeout reached: ${ms}ms`);
                resolve(null);
            }, ms);
            promise.then(
                res => {
                    clearTimeout(timer);
                    resolve(res);
                },
                err => {
                    clearTimeout(timer);
                    console.warn(`[logout] Promise rejected:`, err);
                    resolve(null);
                }
            );
        });
    };

    // 4. Intentar registrarActividad en background con timeout máximo de 800ms
    if (sesionPrev?.autenticado) {
        const registrarPromise = registrarActividad("logout_admin", {
            origen: origenSesion
        }, {
            usuario: usuarioPrev,
            rol: rolPrev,
            tenantId: tenantIdPrev
        });
        await runWithTimeout(registrarPromise, 800);
    }

    // 5. Intentar supabaseClient.auth.signOut() con timeout máximo de 1200ms
    if (haySupabase()) {
        const signOutPromise = supabaseClient.auth.signOut();
        await runWithTimeout(signOutPromise, 1200);
    }

    // 8. window.location.replace para evitar volver atrás con el botón del navegador
    window.location.replace(destinoFinal)
}

/* Legacy public attendance flow removed.
   The only public attendance flow now lives in /asistencia/index.html. */

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
        .order("fecha", { ascending: false })
        .order("hora", { ascending: false })
    const scopedData = filtrarDataTenantActivo(data)
    renderTabla((scopedData || []).filter(d => d.estado !== "retirado"))
    await cargarAlertasReporte()
}

function renderTabla(data) {
    const activos = (data || [])
        .filter(r => r.estado !== "retirado")
        .slice()
        .sort((a, b) => {
            const aKey = `${a.fecha || ""} ${formatearHoraVisible(a.hora || "")}`
            const bKey = `${b.fecha || ""} ${formatearHoraVisible(b.hora || "")}`
            return bKey.localeCompare(aKey)
        })
    const hayFiltroUbo = !!String(filtroUbo?.value || "").trim()
    const clavesAlerta = obtenerClavesAlertaDispositivo(activos)
    cacheReportes = []

    if (!activos.length) {
        tabla.innerHTML = buildEmptyStateHTML(
            "No hay registros disponibles",
            "Ajusta los filtros para consultar asistencias registradas.",
            "🔎"
        )
        return
    }

    let html = `
  <table>
    <thead>
      <tr>
        <th>DNI</th>
        <th>Nombre</th>
        <th>UBO</th>
        <th>Jornada</th>
        <th>Sección aspirante</th>
        <th>Modalidad</th>
        <th>Fecha</th>
        <th>Hora</th>
        <th>Origen</th>
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
            jornada: normalizarTipoJornada(r.tipo_jornada),
            seccion: r.seccion || "",
            modalidad: resolverModalidadRegistro(r),
            fecha: r.fecha || "",
            hora: formatearHoraVisible(r.hora || ""),
            origen: normalizarOrigenRegistroLabel(r.origen_registro),
            import_batch_id: r.import_batch_id || "",
            fuente_importacion: r.fuente_importacion || "",
            archivo_origen: r.archivo_origen || "",
            importado_en: r.importado_en || "",
            importado_por: r.importado_por || "",
            alerta: hayAlerta ? "DNI distinto en dispositivo" : "Sin alerta"
        })

        html += `
      <tr>
        <td>${r.dni}</td>
        <td>${r.nombre}</td>
        <td>${r.ubo}</td>
        <td>${formatearTipoJornadaAmigable(r.tipo_jornada)}</td>
        <td>${formatearSeccionRegistro(r.seccion, r.tipo_jornada)}</td>
        <td>${formatearModalidadAmigable(resolverModalidadRegistro(r)) || "-"}</td>
        <td>${r.fecha}</td>
        <td>${formatearHoraVisible(r.hora)}</td>
        <td>${escapeHtml(normalizarOrigenRegistroLabel(r.origen_registro) || "-")}</td>
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

function obtenerEtiquetaTipoAlerta(tipo) {
    const normalizado = String(tipo || "").trim().toLowerCase()
    if (normalizado === "dni_en_otro_dispositivo") return "Dispositivo no habitual"
    if (normalizado === "fuera_rango_gps") return "Fuera de rango GPS"
    return normalizado ? normalizado.replace(/_/g, " ") : "-"
}

async function cargarAlertasReporte() {
    let q = withTenantScope(supabaseClient
        .from("asistencia_alertas")
        .select("*")
        .eq("curso_id", cursoActualId || 1)
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
        .order("fecha", { ascending: false })
        .order("hora", { ascending: false })

    if (error) {
        console.warn("No se pudo cargar asistencia_alertas:", error.message)
        tablaAlertasContenido.innerHTML = buildEmptyStateHTML(
            "No se pudieron cargar alertas",
            "Intenta nuevamente o revisa la conexion con el servidor.",
            "⚠️"
        )
        return
    }

    const scopedData = filtrarDataTenantActivo(data)

    if (!scopedData || scopedData.length === 0) {
        tablaAlertasContenido.innerHTML = buildEmptyStateHTML(
            "Sin alertas registradas",
            "No se encontraron alertas para el periodo consultado.",
            "🔍"
        )
        return
    }

    const alertasUnicas = []
    const claves = new Set()
        ; (scopedData || []).forEach(r => {
            const key = [
                r.fecha || "",
                r.hora || "",
                r.dni || "",
                r.tipo || "",
                r.detalle || ""
            ].join("|")
            if (claves.has(key)) return
            claves.add(key)
            alertasUnicas.push(r)
        })

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

    alertasUnicas.forEach(r => {
        html += `
      <tr>
        <td>${r.fecha || ""}</td>
        <td>${r.hora || ""}</td>
        <td>${r.dni || ""}</td>
        <td>${r.nombre || ""}</td>
        <td>${r.ubo || ""}</td>
        <td>${r.seccion || ""}</td>
        <td>${obtenerEtiquetaTipoAlerta(r.tipo)}</td>
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

    tabla.innerHTML = buildEmptyStateHTML(
        "No hay registros disponibles",
        "Ajusta los filtros para consultar asistencias registradas.",
        "🔎"
    )
    tablaAlertasContenido.innerHTML = buildEmptyStateHTML(
        "Sin alertas registradas",
        "Ajusta los filtros para consultar un periodo con actividad.",
        "🔍"
    )

}

async function cargarDashboardStaffOperativo() {
    const target = document.getElementById("staffOpsRecentTable")
    const rangeLabel = document.getElementById("staffOpsRangeLabel")
    const kPresentes = document.getElementById("staffOpsPresentesHoy")
    const kAdjuntos = document.getElementById("staffOpsAdjuntosHoy")
    const kApoyos = document.getElementById("staffOpsApoyosHoy")
    const kUltHora = document.getElementById("staffOpsUltimaHora")
    const kUltDetalle = document.getElementById("staffOpsUltimaDetalle")
    if (!target || !rangeLabel) return

    const { hoy, from, to } = obtenerRangoStaffDashboard()
    rangeLabel.textContent = `${from} → ${to}`

    if (!haySupabase() || !tenantActivoId) {
        target.innerHTML = buildEmptyStateHTML("Sin conexión disponible", "No se pudo cargar el dashboard staff.", "⚠️", true)
        return
    }

    let presentesQ = withTenantScope(supabaseClient.from("staff_asistencias").select("id", { count: "exact", head: true }).eq("fecha", hoy).eq("curso_id", cursoActualId || 1))
    let adjuntosQ = withTenantScope(supabaseClient.from("staff_asistencias").select("id", { count: "exact", head: true }).eq("fecha", hoy).eq("tipo_staff", "ADJUNTO").eq("curso_id", cursoActualId || 1))
    let apoyosQ = withTenantScope(supabaseClient.from("staff_asistencias").select("id", { count: "exact", head: true }).eq("fecha", hoy).eq("tipo_staff", "APOYO").eq("curso_id", cursoActualId || 1))
    let ultimaQ = withTenantScope(
        supabaseClient
            .from("staff_asistencias")
            .select("fecha,hora_ingreso,codigo_bombero,nombre,tipo_staff,ubo_origen,tenant_id,curso_id")
            .eq("curso_id", cursoActualId || 1)
            .order("fecha", { ascending: false })
            .order("hora_ingreso", { ascending: false })
            .limit(1)
    )
    let recientesQ = withTenantScope(
        supabaseClient
            .from("staff_asistencias")
            .select("fecha,hora_ingreso,codigo_bombero,nombre,tipo_staff,jornada,ubo_origen,tenant_id,curso_id")
            .eq("curso_id", cursoActualId || 1)
            .gte("fecha", from)
            .lte("fecha", to)
            .order("fecha", { ascending: false })
            .order("hora_ingreso", { ascending: false })
            .limit(10)
    )

    if (dashUbo?.value) {
        presentesQ = presentesQ.eq("ubo_origen", dashUbo.value)
        adjuntosQ = adjuntosQ.eq("ubo_origen", dashUbo.value)
        apoyosQ = apoyosQ.eq("ubo_origen", dashUbo.value)
        ultimaQ = ultimaQ.eq("ubo_origen", dashUbo.value)
        recientesQ = recientesQ.eq("ubo_origen", dashUbo.value)
    }

    const [
        { count: presentesCount },
        { count: adjuntosCount },
        { count: apoyosCount },
        { data: ultimaData, error: ultimaError },
        { data: recientesData, error: recientesError }
    ] = await Promise.all([presentesQ, adjuntosQ, apoyosQ, ultimaQ, recientesQ])

    if (kPresentes) kPresentes.textContent = String(presentesCount || 0)
    if (kAdjuntos) kAdjuntos.textContent = String(adjuntosCount || 0)
    if (kApoyos) kApoyos.textContent = String(apoyosCount || 0)

    const ultima = filtrarDataTenantActivo(ultimaData || [])[0] || null
    if (kUltHora) kUltHora.textContent = ultima?.hora_ingreso || "--:--"
    if (kUltDetalle) kUltDetalle.textContent = ultima ? `${ultima.nombre || "Staff"} · ${ultima.codigo_bombero || "-"}` : "Sin registros recientes."

    if (ultimaError || recientesError) {
        target.innerHTML = buildEmptyStateHTML("Sin datos staff", "No se pudo cargar el resumen operativo staff.", "⚠️", true)
        cacheDashboardStaff = []
        return
    }

    const recientes = filtrarDataTenantActivo(recientesData || [])
    cacheDashboardStaff = recientes
    if (!recientes.length) {
        target.innerHTML = buildEmptyStateHTML("Sin asistencias recientes", "No hay asistencias staff en el rango operativo consultado.", "👨‍🚒", true)
        return
    }

    const fotoMap = await cargarFotosStaffPorCodigos(recientes.map(r => r.codigo_bombero))
    let html = `<div class="staff-ops-list">`
    recientes.forEach(item => {
        const meta = fotoMap[normalizarCodigoBombero(item.codigo_bombero)] || {}
        html += `
          <div class="staff-ops-item">
            <div class="staff-ops-item-main">
              ${renderStaffAvatarCompact({ ...item, ...meta })}
              <div class="staff-ops-item-copy">
                <strong>${escapeHtml(item.nombre || "Staff")}</strong>
                <span>${escapeHtml(item.codigo_bombero || "-")} · ${escapeHtml(normalizarTextoSimple(item.tipo_staff) || "APOYO")}</span>
              </div>
            </div>
            <div class="staff-ops-item-meta">
              <strong>${escapeHtml(item.hora_ingreso || "--:--")}</strong>
              <span>${escapeHtml(item.jornada || "-")}</span>
            </div>
          </div>
        `
    })
    html += `</div>`
    target.innerHTML = html
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
        .eq("curso_id", cursoActualId || 1)
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
        .select("fecha,hora,dni,nombre,ubo,seccion,detalle,device_id,tenant_id,curso_id")
        .eq("curso_id", cursoActualId || 1)
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
        const evaluacion = evaluarSemaforoDashboard(registros)
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
            horaInicio: evaluacion.horaInicio || "-",
            tipoJornada: formatearTipoJornadaAmigable(evaluacion.tipoJornada),
            modalidad: formatearModalidadAmigable(evaluacion.modalidad) || "-",
            estadoAsistencia: formatearEstadoAsistenciaDashboard(evaluacion.estadoAsistencia)
        })

        const esTardanza = evaluacion.motivo === "estado_tardanza"
            || evaluacion.motivo === "tardanza_moderada"
            || evaluacion.motivo === "tardanza_alta"
        const esFueraHorarioODia = evaluacion.motivo === "estado_fuera_de_horario"
            || evaluacion.motivo === "fuera_de_dia_configurado"
            || evaluacion.motivo === "hora_invalida_para_seccion"

        if (esTardanza) rojoTardanza++
        if (esFueraHorarioODia) rojoFueraDia++

        if (esTardanza || esFueraHorarioODia || estado === "rojo") {
            if (!uboMap[a.ubo]) {
                uboMap[a.ubo] = { total: 0, tardanza: 0, fueraDia: 0, otros: 0 }
            }
            uboMap[a.ubo].total++
            if (esTardanza) {
                uboMap[a.ubo].tardanza++
            } else if (esFueraHorarioODia) {
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
        html = buildEmptyStateHTML(
            "Sin riesgo acumulado",
            "No se encontraron registros en rojo para el rango seleccionado.",
            "📉",
            true
        )
    }

    topUbo.innerHTML = html
    semaforoInfo.innerText = "Semáforo: usa primero estado_asistencia guardado por backend (Puntual, Tardanza, Fuera de horario). Solo si el registro no tiene estado_asistencia, aplica fallback legacy por hora/días."
    riesgoInfo.innerText = "Riesgo por UBO: acumulado de aspirantes con tardanza o fuera de horario/día en el rango filtrado."

    try {
        await cargarDashboardStaffOperativo()
    } catch (e) {
        console.warn("No se pudo cargar dashboard staff operativo:", e)
        const target = document.getElementById("staffOpsRecentTable")
        if (target) {
            target.innerHTML = buildEmptyStateHTML(
                "Sin datos staff",
                "No se pudo cargar el bloque operativo staff.",
                "⚠️",
                true
            )
        }
    }
}

function verAlertasDispositivo() {
    const data = window.detalleAlertasDispositivo || []

    if (!data.length) {
        modalTitulo.innerText = "Alertas de Dispositivo"
        modalContenido.innerHTML = buildEmptyStateHTML(
            "Sin alertas de dispositivo",
            "No se encontraron alertas para el rango seleccionado.",
            "🔒"
        )
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

    if (!data.length) {
        modalTitulo.innerText = "UBO " + ubo
        modalContenido.innerHTML = buildEmptyStateHTML(
            "Sin registros para esta UBO",
            "No se encontraron registros en rojo para esta UBO en el rango seleccionado.",
            "📍"
        )
        modal.style.display = "flex"
        return
    }

    let html = `
  <table>
    <tr>
      <th>DNI</th>
      <th>Nombre</th>
      <th>UBO</th>
      <th>Sección</th>
      <th>Jornada</th>
      <th>Modalidad</th>
      <th>Estado</th>
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
        <td>${r.tipoJornada || "-"}</td>
        <td>${r.modalidad || "-"}</td>
        <td>${r.estadoAsistencia || "-"}</td>
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
        if (!tablaStaffReportes.innerHTML.trim() || /Sin registros consultados/i.test(tablaStaffReportes.innerHTML)) cargarReportesStaff()
    }

    if (vista === "config") {
        document.getElementById("vistaConfig").style.display = "block"
        cargarUbos()
        cargarConfigCurso()
        cargarAspirantesCargados()
        cargarStaffInstruccion()
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

    if (!data.length) {
        modalTitulo.innerText = "Semáforo " + color.toUpperCase()
        modalContenido.innerHTML = buildEmptyStateHTML(
            "Sin registros para este semaforo",
            "No se encontraron registros para este semaforo en el rango seleccionado.",
            "🚦"
        )
        modal.style.display = "flex"
        return
    }

    let html = `
  <table>
    <tr>
      <th>DNI</th>
      <th>Nombre</th>
      <th>UBO</th>
      <th>Sección</th>
      <th>Jornada</th>
      <th>Modalidad</th>
      <th>Estado</th>
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
        <td>${x.tipoJornada || "-"}</td>
        <td>${x.modalidad || "-"}</td>
        <td>${x.estadoAsistencia || "-"}</td>
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

function cerrarModalPorBackdrop(event) {
    if (event?.target?.id === "modal") {
        cerrarModal()
    }
}

// cerrar con ESC
document.addEventListener("keydown", e => {
    if (e.key === "Escape") {
        cerrarModal()
        cerrarCuentaModal()
        cerrarAccesoAdminInstitucional()
        if (tutorialActivo && typeof cerrarTutorial === "function") {
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
        id: cursoActualId || 1,
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
                id: cursoActualId || 1,
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
            await guardarCursoBaseEnSupabase({
                id: cursoActualId || 1,
                nombre: (cursoNombre.value || "").toUpperCase(),
                fecha_inicio: cursoInicio.value || null,
                fecha_fin: cursoFin.value || null
            })
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
    await guardarCursoBaseEnSupabase({
        id: cursoActualId || 1,
        nombre: (cursoNombre.value || "").toUpperCase(),
        fecha_inicio: cursoInicio.value || null,
        fecha_fin: cursoFin.value || null
    })
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
            await q.eq("curso_id", cursoActualId || 1)
                .eq("seccion", oldSeccion)
        }

        let qAct = withTenantScope(supabaseClient.from("curso_secciones").delete())
        const { error: errorDeleteActual } = await qAct
            .eq("curso_id", cursoActualId || 1)
            .eq("seccion", item.seccion)
        if (errorDeleteActual && !esTablaNoExiste(errorDeleteActual)) {
            throw errorDeleteActual
        }

        const payloadSeccion = withTenantPayload({
            curso_id: cursoActualId || 1,
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
                    curso_id: cursoActualId || 1,
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
                .eq("curso_id", cursoActualId || 1)
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
        tablaSeccionesCurso.innerHTML = buildEmptyTableRow(
            5,
            "Sin secciones sincronizadas",
            "No se encontraron reglas activas en curso_jornada_reglas para el curso activo.",
            "🗂️"
        )
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
        <td>${s.activa ? "Sí" : "No"}</td>
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
            await qSede.eq("curso_id", cursoActualId || 1)
                .eq("seccion", oldSeccion)
        }

        for (const sec of seccionesObjetivo) {
            let qActSede = withTenantScope(supabaseClient.from("curso_sedes_ubo").delete())
            const { error: errorDeleteActual } = await qActSede
                .eq("curso_id", cursoActualId || 1)
                .eq("seccion", sec)
            if (errorDeleteActual && !esTablaNoExiste(errorDeleteActual)) {
                throw errorDeleteActual
            }

            const payloadSede = withTenantPayload({
                curso_id: cursoActualId || 1,
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
                        curso_id: cursoActualId || 1,
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
                .eq("curso_id", cursoActualId || 1)
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
        tablaSedesUbo.innerHTML = buildEmptyTableRow(
            6,
            "Módulo próximamente",
            "La asignación de UBO sede por sección se habilitará en una próxima versión.",
            "🧭"
        )
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
    semaforoInfo.innerText = "Semáforo: usa estado_asistencia backend y fallback legacy si el histórico no lo tiene."
    riesgoInfo.innerText = "Riesgo UBO: tardanza o fuera de horario/día por UBO."

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
        const { error } = await qClrSec
            .eq("curso_id", cursoActualId || 1)
            .neq("seccion", "DUMMY_HACK_DELETE_ALL")
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
        const { error } = await qClrSede
            .eq("curso_id", cursoActualId || 1)
            .neq("seccion", "DUMMY_HACK_DELETE_ALL")
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


cursoNombre?.addEventListener("input", () => {
    cursoNombre.value = cursoNombre.value.toUpperCase()
})

secCursoNombre?.addEventListener("input", () => {
    secCursoNombre.value = secCursoNombre.value.toUpperCase().replace(/\s+/g, "")
})

window.addEventListener("resize", () => {
    if (estaInputDniMovilActivo() || hayCampoEditableActivo()) return
    clearTimeout(resizeTimer)
    resizeTimer = setTimeout(aplicarLayout, 160)
})

window.addEventListener("orientationchange", () => {
    if (estaInputDniMovilActivo() || hayCampoEditableActivo()) return
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

// ESC key to close modal
window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        const modal = document.getElementById('cuentaModal');
        if (modal && modal.style.display === 'flex') {
            cerrarCuentaModal();
        }
    }
});
