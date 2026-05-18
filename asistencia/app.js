const supabaseUrl = "https://kcapmyovaigjntaqeqwn.supabase.co"
const supabaseKey = "sb_publishable_oObf3s5mQ4sfmJ03JKQrnQ__8Rmb63F"

const supabaseClient = window.supabase?.createClient
    ? window.supabase.createClient(supabaseUrl, supabaseKey)
    : null

let tenantActivoId = ""
let cursoActualId = 1
let cursoQRValido = false
let cursoValidadoEnSesion = false
let dniMovil = ""
let seccion = ""
let cursoConfigCache = null
let cursoSecciones = []
let debounceTimerAutocompletar = null
let retornoPostRegistroTimer = 0
let validacionCursoAspirante = { dni: "", permitido: true, legacy: false, bloqueado: false }
let perfilAspiranteActual = { dni: "", seccion: "" }
let contextoAsistenciaActual = null
let sincronizacionPendientesEnCurso = false
let ultimoEstadoCurso = { code: "idle", message: "" }
const OFFLINE_QUEUE_KEY = "asistia_aspirantes_offline_queue_v1"

let tenantLabel
let stepIngreso
let formulario
let mobileDniInicio
let nombres
let apellidos
let ubo
let aspiranteLegacyFields
let mensaje
let mobileSectionsContainer
let pendingCounter

function debugContextLog(...args) {
    console.log("[asistIA-context-debug]", ...args)
}

function actualizarDebugContextGlobal() {
    window.__asistIAContextDebug = {
        getContext: () => contextoAsistenciaActual,
        hasRPC: () => tieneContextoRPCActivo(),
        getHTML: () => mobileSectionsContainer?.innerHTML,
        getState: () => ({
            dniMovil,
            seccion,
            tenantActivoId,
            cursoQRValido,
            cursoActualId
        })
    }
}

function haySupabase() {
    return !!supabaseClient
}

function enlazarIds() {
    tenantLabel = document.getElementById("tenantLabel")
    stepIngreso = document.getElementById("stepIngreso")
    formulario = document.getElementById("formulario")
    mobileDniInicio = document.getElementById("mobileDniInicio")
    nombres = document.getElementById("nombres")
    apellidos = document.getElementById("apellidos")
    ubo = document.getElementById("ubo")
    aspiranteLegacyFields = document.getElementById("aspiranteLegacyFields")
    mensaje = document.getElementById("mensaje")
    mobileSectionsContainer = document.getElementById("mobileSectionsContainer")
    pendingCounter = document.getElementById("pendingCounter")
    actualizarDebugContextGlobal()
}

function detectarTenantDesdeRuta() {
    const segments = String(window.location.pathname || "").split("/").filter(Boolean)
    const idxAsistencia = segments.indexOf("asistencia")
    if (idxAsistencia > 0) {
        return String(segments[idxAsistencia - 1] || "").trim().toLowerCase()
    }
    if (segments[0] && segments[0] !== "asistencia") {
        return String(segments[0] || "").trim().toLowerCase()
    }
    const params = new URLSearchParams(window.location.search || "")
    return String(params.get("tenant") || "").trim().toLowerCase()
}

function aplicarTenantEnUI() {
    const institucion = String(tenantActivoId || "").trim().replace(/-/g, " ").toUpperCase()
    const label = institucion ? `Institución: ${institucion}` : "Institución no detectada"
    if (tenantLabel) tenantLabel.textContent = label
    document.title = tenantActivoId ? `${tenantActivoId} - asistIA Asistencia` : "asistIA Asistencia"
}

function setMensaje(texto, tipo = "") {
    if (!mensaje) return
    mensaje.className = "message-box"
    mensaje.innerText = texto || ""
    if (!texto) return
    if (tipo) mensaje.classList.add(tipo)
}

function esErrorConexion(error) {
    const texto = String(error?.message || error || "").toLowerCase()
    return /failed to fetch|fetch failed|networkerror|network request failed|load failed|timeout|temporarily unavailable|connection|offline/i.test(texto)
}

function mensajeAmigable(error, fallback = "Ocurrió un problema al procesar la solicitud.") {
    if (esErrorConexion(error)) return "No se pudo conectar con asistIA. Verifica tu conexión e inténtalo nuevamente."
    return fallback
}

function escapeHTML(value = "") {
    return String(value || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\"/g, "&quot;")
        .replace(/'/g, "&#39;")
}

function aplicarReadonlyVisual(input, readOnly = false) {
    if (!input) return
    input.readOnly = !!readOnly
    input.classList.toggle("is-readonly", !!readOnly)
}

function debeOcultarMensajePublico(item) {
    const code = String(item?.code || "").trim().toLowerCase()
    const message = String(item?.message || item || "").trim().toLowerCase()
    return code === "device_id_ausente" || message === "no se recibió identificador de dispositivo."
}

function deduplicarMensajes(messages = []) {
    const seen = new Set()
    return messages.filter(item => {
        const key = String(item || "").replace(/\.+$/, "").trim().toLowerCase()
        if (!key || seen.has(key)) return false
        seen.add(key)
        return true
    })
}

function normalizarMensajePublicoFinal(texto = "") {
    const partes = String(texto || "")
        .split("|")
        .map(item => String(item || "").trim())
        .filter(Boolean)
    return deduplicarMensajes(partes).join(" | ")
}

function construirClaveMensajePublico(item) {
    const code = String(item?.code || "").trim().toLowerCase()
    const message = String(item?.message || item || "").trim().toLowerCase()
    return code ? `${code}|${message}` : message
}

function mostrarPasoMovil(paso) {
    if (stepIngreso) stepIngreso.style.display = paso === "ingreso" ? "flex" : "none"
}

function cancelarRetornoPostRegistro() {
    if (retornoPostRegistroTimer) {
        window.clearTimeout(retornoPostRegistroTimer)
        retornoPostRegistroTimer = 0
    }
}

function limpiarDni(valor = "") {
    return String(valor || "").replace(/\D/g, "").slice(0, 8)
}

function esTablaNoExiste(error) {
    return /does not exist|42P01/i.test(String(error?.message || ""))
}

function withTenantScope(query) {
    if (!tenantActivoId) return query
    return query.eq("tenant_id", tenantActivoId)
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
        if (match?.[1]) return decodeURIComponent(String(match[1] || "").trim())
        return ""
    }
}

function obtenerFechaHoraLima(fechaBase = new Date()) {
    const dtf = new Intl.DateTimeFormat("en-CA", {
        timeZone: "America/Lima",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false
    })

    const parts = Object.fromEntries(
        dtf.formatToParts(fechaBase)
            .filter(part => part.type !== "literal")
            .map(part => [part.type, part.value])
    )

    return {
        fecha: `${parts.year}-${parts.month}-${parts.day}`,
        hora: `${parts.hour}:${parts.minute}:${parts.second}`,
        timestamp: fechaBase.toISOString(),
        weekday: new Intl.DateTimeFormat("en-US", {
            timeZone: "America/Lima",
            weekday: "long"
        }).format(fechaBase).toLowerCase()
    }
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

function formatearTipoJornadaAmigable(valor) {
    const jornada = String(valor || "").trim().toUpperCase()
    if (jornada === "DOMINICAL" || jornada === "DOMINICAL_GRUPAL") return "Dominical grupal"
    if (jornada === "SECCION" || jornada === "SECCION_REGULAR") return "Regular de sección"
    if (jornada === "GENERAL") return "General (legacy)"
    return jornada || "Regular de sección"
}

function formatearModalidadAmigable(valor) {
    const modalidad = normalizarModalidad(valor)
    if (modalidad === "VIRTUAL") return "Virtual"
    if (modalidad === "PRESENCIAL") return "Presencial"
    return ""
}

function formatearEstadoAsistenciaAmigable(valor) {
    const estado = String(valor || "").trim().toUpperCase()
    if (estado === "PUNTUAL") return "Puntual"
    if (estado === "TARDANZA") return "Tardanza"
    if (estado === "FUERA_DE_HORARIO") return "Fuera de horario"
    return ""
}

function normalizarEstadoAsistencia(valor) {
    const estado = String(valor || "").trim().toUpperCase()
    return estado || null
}

function tieneContextoRPCActivo() {
    return String(contextoAsistenciaActual?.origen_contexto || "").trim() === "rpc_resolver_contexto_asistencia"
}

function contextoCorrespondeADni(dniValor) {
    const dniNormalizado = limpiarDni(dniValor)
    const dniContexto = limpiarDni(contextoAsistenciaActual?.aspirante?.dni || dniMovil || "")
    return !!dniNormalizado && !!dniContexto && dniNormalizado === dniContexto
}

function obtenerTipoJornadaAspirante(weekday) {
    return weekday === "sunday" ? "DOMINICAL_GRUPAL" : "SECCION_REGULAR"
}

function obtenerSeccionAspiranteDetectada() {
    return esSeccionLegacy(perfilAspiranteActual?.seccion) ? "" : normalizarCodigoSeccion(perfilAspiranteActual?.seccion)
}

function construirContextoLocalAsistencia(fecha = new Date(), seccionRegistro = "") {
    const contexto = resolverContextoAsistencia(fecha, seccionRegistro)
    return {
        seccion: contexto.seccion || null,
        tipo_jornada: contexto.tipo_jornada || null,
        tipo_jornada_label: formatearTipoJornadaAmigable(contexto.jornada_label || contexto.tipo_jornada),
        modalidad: contexto.modalidad || null,
        modalidad_label: formatearModalidadAmigable(contexto.modalidad),
        estado_asistencia: null,
        estado_asistencia_label: "",
        regla_jornada_id: null,
        origen_contexto: "frontend_fallback",
        warnings: [],
        bloqueos: []
    }
}

function obtenerReglaSeccionCurso(seccionRegistro) {
    const codigo = normalizarCodigoSeccion(seccionRegistro)
    if (!codigo) return null
    return (cursoSecciones || []).find(item => normalizarCodigoSeccion(item?.seccion) === codigo) || null
}

function resolverContextoAsistencia(fecha = new Date(), seccionRegistro = "") {
    const ahoraLima = obtenerFechaHoraLima(fecha)
    const esDomingo = ahoraLima.weekday === "sunday"
    const seccionReal = normalizarCodigoSeccion(seccionRegistro)
    const regla = obtenerReglaSeccionCurso(seccionReal)
    return {
        fecha: ahoraLima.fecha,
        hora: ahoraLima.hora,
        timestamp: ahoraLima.timestamp,
        weekday: ahoraLima.weekday,
        esDomingo,
        seccion: seccionReal,
        tipo_jornada: obtenerTipoJornadaAspirante(ahoraLima.weekday),
        modalidad: esDomingo ? "PRESENCIAL" : normalizarModalidad(regla?.modalidad),
        jornada_label: esDomingo ? "DOMINICAL_GRUPAL" : "SECCION_REGULAR"
    }
}

function leerColaPendientes() {
    try {
        const raw = localStorage.getItem(OFFLINE_QUEUE_KEY)
        const data = raw ? JSON.parse(raw) : []
        return Array.isArray(data) ? data : []
    } catch (error) {
        console.warn("No se pudo leer la cola offline:", error)
        return []
    }
}

function guardarColaPendientes(cola) {
    try {
        localStorage.setItem(OFFLINE_QUEUE_KEY, JSON.stringify(Array.isArray(cola) ? cola : []))
        return true
    } catch (error) {
        console.warn("No se pudo guardar la cola offline:", error)
        return false
    }
}

function construirClavePendiente(registro) {
    const tenantId = String(registro?.tenant_id || "").trim().toLowerCase()
    const cursoId = String(registro?.curso_id || "").trim()
    const dni = limpiarDni(registro?.dni)
    const fecha = String(registro?.fecha_local || "").trim()
    return `${tenantId}::${cursoId}::${dni}::${fecha}`
}

function actualizarContadorPendientes() {
    if (!pendingCounter) return
    const cantidad = leerColaPendientes().filter(item => item?.estado_sync === "pendiente").length
    pendingCounter.textContent = cantidad > 0
        ? (cantidad === 1
            ? "1 asistencia pendiente"
            : `${cantidad} asistencias pendientes`)
        : ""
    pendingCounter.hidden = cantidad === 0
    pendingCounter.classList.toggle("has-pending", cantidad > 0)
}

function agregarPendienteOffline(registro) {
    const cola = leerColaPendientes()
    const clave = construirClavePendiente(registro)
    const existe = cola.some(item => construirClavePendiente(item) === clave)

    if (existe) {
        actualizarContadorPendientes()
        return { ok: true, duplicate: true }
    }

    cola.push(registro)
    const guardado = guardarColaPendientes(cola)
    actualizarContadorPendientes()
    return { ok: guardado, duplicate: false }
}

function esErrorTransporteSupabase(error) {
    const texto = String(error?.message || error || "").toLowerCase()
    return !texto || esErrorConexion(texto)
}

function puedeGuardarOfflinePorContingencia() {
    return !!cursoQRValido && !!cursoValidadoEnSesion && !!tenantActivoId && !!(cursoActualId || 1)
}

function actualizarVisibilidadCamposLegacy() {
    if (!aspiranteLegacyFields) return
    aspiranteLegacyFields.hidden = tieneContextoRPCActivo()
}

function resetFormularioAsistencia() {
    cancelarRetornoPostRegistro()
    limpiarCamposAspirante()
    contextoAsistenciaActual = null
    seccion = ""
    seleccionarBotonSeccion("")
    actualizarVisibilidadCamposLegacy()
}

function programarRetornoPostRegistro() {
    cancelarRetornoPostRegistro()
    retornoPostRegistroTimer = window.setTimeout(() => {
        retornoPostRegistroTimer = 0
        const params = new URLSearchParams(window.location.search || "")
        const tokenCurso = obtenerCursoTokenDesdeURL()
        if (tenantActivoId) params.set("tenant", tenantActivoId)
        if (tokenCurso) params.set("curso", tokenCurso)
        params.set("v", String(Date.now()))
        window.location.replace(`/asistencia/index.html?${params.toString()}`)
    }, 3200)
}

function crearRegistroOffline({ dniRegistro, nombresValor, apellidosValor, seccionRegistro, modalidadRegistro, deviceId }) {
    const contexto = contextoAsistenciaActual || construirContextoLocalAsistencia(new Date(), seccionRegistro)
    const fechaHora = resolverContextoAsistencia(new Date(), seccionRegistro)
    const nombreCompleto = `${String(nombresValor || "").trim()} ${String(apellidosValor || "").trim()}`
        .replace(/\s+/g, " ")
        .trim()

    return {
        dni: dniRegistro,
        nombre: nombreCompleto || nombresValor || null,
        tenant_id: tenantActivoId,
        curso_id: cursoActualId || 1,
        qr_token: obtenerCursoTokenDesdeURL(),
        fecha_local: fechaHora.fecha,
        hora_local: fechaHora.hora,
        timestamp_local: fechaHora.timestamp,
        latitud: null,
        longitud: null,
        seccion: contexto.seccion || null,
        tipo_jornada: contexto.tipo_jornada || fechaHora.tipo_jornada,
        modalidad: normalizarModalidad(modalidadRegistro) || contexto.modalidad || null,
        estado_asistencia: normalizarEstadoAsistencia(contexto.estado_asistencia),
        regla_jornada_id: contexto.regla_jornada_id || null,
        origen_contexto: contexto.origen_contexto || "frontend_fallback",
        device_id: deviceId || getDeviceId(),
        origen_registro: "offline",
        estado_sync: "pendiente",
        created_local_at: new Date().toISOString()
    }
}

async function sincronizarPendientes({ notificar = false } = {}) {
    if (sincronizacionPendientesEnCurso || !haySupabase() || !navigator.onLine) {
        actualizarContadorPendientes()
        return
    }

    const cola = leerColaPendientes()
    if (!cola.length) {
        actualizarContadorPendientes()
        return
    }

    sincronizacionPendientesEnCurso = true
    let sincronizados = 0
    const restantes = []

    try {
        for (const item of cola) {
            try {
                const { data, error } = await supabaseClient.rpc("rpc_registrar_asistencia", {
                    p_dni: limpiarDni(item?.dni),
                    p_tenant_id: String(item?.tenant_id || "").trim(),
                    p_seccion: String(item?.seccion || "GENERAL").trim() || "GENERAL",
                    p_latitud: item?.latitud == null ? 0 : Number(item.latitud),
                    p_longitud: item?.longitud == null ? 0 : Number(item.longitud),
                    p_device_id: String(item?.device_id || getDeviceId()).trim(),
                    p_timestamp_local: item?.timestamp_local || item?.created_local_at || new Date().toISOString(),
                    p_curso_id: Number(item?.curso_id || 1) || 1,
                    p_origen_registro: String(item?.origen_registro || "offline").trim() || "offline"
                })

                if (error || !data?.success) {
                    restantes.push(item)
                    continue
                }

                sincronizados += 1
            } catch (error) {
                restantes.push(item)
            }
        }
    } finally {
        guardarColaPendientes(restantes)
        sincronizacionPendientesEnCurso = false
        actualizarContadorPendientes()
    }

    if (notificar && sincronizados > 0) {
        setMensaje(
            sincronizados === 1
                ? "✅ Asistencia sincronizada correctamente."
                : `✅ ${sincronizados} asistencias sincronizadas correctamente.`,
            "ok"
        )
        return
    }

    if (notificar && !sincronizados && restantes.length > 0) {
        setMensaje("No se pudo sincronizar. Se intentará nuevamente cuando haya conexión.", "warning")
    }
}

async function guardarAsistenciaOffline({ dniRegistro, nombresValor, apellidosValor, seccionRegistro, modalidadRegistro, motivo }) {
    if (!puedeGuardarOfflinePorContingencia()) {
        setMensaje(motivo || "⚠ No se pudo registrar la asistencia en este momento.", "error")
        return false
    }

    const resultado = agregarPendienteOffline(crearRegistroOffline({
        dniRegistro,
        nombresValor,
        apellidosValor,
        seccionRegistro,
        modalidadRegistro,
        deviceId: getDeviceId()
    }))

    if (!resultado.ok) {
        setMensaje("Ocurrió un problema al procesar la solicitud.", "error")
        return false
    }

    if (resultado.duplicate) {
        setMensaje("Sin conexión. Esta asistencia ya estaba guardada en este dispositivo.", "warning")
    } else {
        setMensaje("Sin conexión. Asistencia guardada en este dispositivo. Se sincronizará al volver a abrir asistIA con internet.", "warning")
    }

    resetFormularioAsistencia()
    return true
}

function extraerMensajesContexto(items) {
    if (!Array.isArray(items)) return []
    const seen = new Set()
    return items
        .filter(item => !debeOcultarMensajePublico(item))
        .filter(item => {
            const key = construirClaveMensajePublico(item)
            if (!key || seen.has(key)) return false
            seen.add(key)
            return true
        })
        .map(item => String(item?.message || item || "").trim())
        .filter(Boolean)
}

async function resolverContextoAsistenciaRPC(dniLimpio) {
    if (!haySupabase() || !tenantActivoId || !cursoQRValido) {
        debugContextLog("resolverContextoAsistenciaRPC: skip precondicion", {
            haySupabase: haySupabase(),
            tenantActivoId: !!tenantActivoId,
            cursoQRValido,
            dni: dniLimpio
        })
        return null
    }
    const tokenCurso = obtenerCursoTokenDesdeURL()
    debugContextLog("resolverContextoAsistenciaRPC: inicio", {
        dni: dniLimpio,
        tokenCursoExiste: !!tokenCurso,
        tenantActivoId,
        cursoQRValido,
        cursoActualId
    })
    if (!tokenCurso) {
        debugContextLog("resolverContextoAsistenciaRPC: fallback por token ausente", { dni: dniLimpio })
        return null
    }

    try {
        const { data, error } = await supabaseClient.rpc("rpc_resolver_contexto_asistencia", {
            p_qr_token: tokenCurso,
            p_dni: dniLimpio,
            p_timestamp: new Date().toISOString()
        })

        debugContextLog("resolverContextoAsistenciaRPC: respuesta", {
            dni: dniLimpio,
            error: error ? String(error.message || error) : null,
            data
        })

        if (error) {
            if (/does not exist|42883|rpc_resolver_contexto_asistencia/i.test(String(error.message || ""))) {
                debugContextLog("resolverContextoAsistenciaRPC: fallback por RPC inexistente", {
                    dni: dniLimpio,
                    error: String(error.message || error)
                })
                return null
            }
            debugContextLog("resolverContextoAsistenciaRPC: error no recuperable", {
                dni: dniLimpio,
                error: String(error.message || error)
            })
            throw error
        }

        debugContextLog("resolverContextoAsistenciaRPC: retorno final", {
            dni: dniLimpio,
            success: !!data?.success,
            permitido: !!data?.permitido
        })
        return data && typeof data === "object" ? data : null
    } catch (error) {
        if (esErrorConexion(error)) {
            debugContextLog("resolverContextoAsistenciaRPC: fallback por error de red", {
                dni: dniLimpio,
                error: String(error?.message || error)
            })
            return null
        }
        debugContextLog("resolverContextoAsistenciaRPC: throw catch final", {
            dni: dniLimpio,
            error: String(error?.message || error)
        })
        throw error
    }
}

function aplicarContextoResueltoEnFormulario(contexto) {
    debugContextLog("aplicarContextoResueltoEnFormulario: entrada", { contexto })
    if (!contexto || typeof contexto !== "object") return

    const aspirante = contexto.aspirante && typeof contexto.aspirante === "object"
        ? contexto.aspirante
        : null

    if (aspirante) {
        nombres.value = String(aspirante.nombres || nombres.value || "").trim()
        apellidos.value = String(aspirante.apellidos || apellidos.value || "").trim()
        ubo.value = String(aspirante.ubo || ubo.value || "").trim()
        aplicarReadonlyVisual(nombres, true)
        aplicarReadonlyVisual(apellidos, true)
        aplicarReadonlyVisual(ubo, true)
    }

    const seccionContexto = normalizarCodigoSeccion(contexto.seccion)
    if (seccionContexto) {
        perfilAspiranteActual = { dni: dniMovil || "", seccion: seccionContexto }
        seccion = seccionContexto
        seleccionarBotonSeccion(seccion)
    }

    contextoAsistenciaActual = {
        aspirante: aspirante
            ? {
                dni: limpiarDni(aspirante.dni || dniMovil || ""),
                nombres: String(aspirante.nombres || "").trim(),
                apellidos: String(aspirante.apellidos || "").trim(),
                ubo: String(aspirante.ubo || "").trim()
            }
            : null,
        seccion: seccionContexto || null,
        tipo_jornada: String(contexto.jornada_codigo || "").trim().toUpperCase() || null,
        tipo_jornada_label: String(contexto.jornada_label || "").trim() || formatearTipoJornadaAmigable(contexto.jornada_codigo),
        modalidad: normalizarModalidad(contexto.modalidad),
        modalidad_label: String(contexto.modalidad_label || "").trim() || formatearModalidadAmigable(contexto.modalidad),
        estado_asistencia: normalizarEstadoAsistencia(contexto.estado_asistencia),
        estado_asistencia_label: String(contexto.estado_asistencia || "").trim()
            ? formatearEstadoAsistenciaAmigable(contexto.estado_asistencia)
            : "",
        regla_jornada_id: contexto.regla_jornada_id || null,
        origen_contexto: String(contexto.origen_contexto || "rpc_resolver_contexto_asistencia").trim(),
        warnings: Array.isArray(contexto.warnings) ? contexto.warnings : [],
        bloqueos: Array.isArray(contexto.bloqueos) ? contexto.bloqueos : []
    }
    actualizarVisibilidadCamposLegacy()
    actualizarDebugContextGlobal()
    debugContextLog("aplicarContextoResueltoEnFormulario: contexto aplicado", {
        contextoAsistenciaActual,
        hasRPC: tieneContextoRPCActivo()
    })
}

function construirResumenContextualHTML({ title, nombreCompleto, contexto, seccionDetectada }) {
    const institucion = String(tenantActivoId || "").trim().replace(/-/g, " ").toUpperCase() || "Institución no detectada"
    const seccionValor = contexto?.seccion || seccionDetectada || "Pendiente de resolver"
    const jornadaValor = contexto?.tipo_jornada_label || formatearTipoJornadaAmigable(contexto?.jornada_label || contexto?.tipo_jornada) || "Pendiente de resolver"
    const modalidadValor = contexto?.modalidad_label || formatearModalidadAmigable(contexto?.modalidad) || "Pendiente de resolver"
    const estadoValor = contexto?.estado_asistencia
        ? (contexto?.estado_asistencia_label || formatearEstadoAsistenciaAmigable(contexto.estado_asistencia))
        : "Pendiente de resolver"

    return `
        <div class="context-card">
            <div class="context-card-head">
                <p class="context-title">${escapeHTML(title)}</p>
                ${nombreCompleto ? `<p class="context-person">${escapeHTML(nombreCompleto)}</p>` : ""}
            </div>
            <div class="context-grid">
                <div class="context-item">
                    <span class="context-item-label">Institución</span>
                    <span class="context-item-value">${escapeHTML(institucion)}</span>
                </div>
                <div class="context-item">
                    <span class="context-item-label">Sección</span>
                    <span class="context-item-value">${escapeHTML(seccionValor)}</span>
                </div>
                <div class="context-item">
                    <span class="context-item-label">Jornada asignada</span>
                    <span class="context-item-value">${escapeHTML(jornadaValor)}</span>
                </div>
                <div class="context-item">
                    <span class="context-item-label">Modalidad</span>
                    <span class="context-item-value">${escapeHTML(modalidadValor)}</span>
                </div>
                <div class="context-item">
                    <span class="context-item-label">Estado esperado</span>
                    <span class="context-item-value">${escapeHTML(estadoValor)}</span>
                </div>
            </div>
        </div>
    `
}

async function resolverCursoPorToken(token) {
    cursoQRValido = false
    ultimoEstadoCurso = { code: "invalid_token", message: "Acceso no válido. Escanee el código QR oficial del curso." }
    if (!token) return false
    if (!haySupabase() || !tenantActivoId) {
        ultimoEstadoCurso = { code: "supabase_unavailable", message: "No se pudo cargar la información." }
        return false
    }

    try {
        const { data, error } = await supabaseClient.rpc("rpc_validar_curso_qr", {
            p_qr_token: token,
            p_tenant_id: tenantActivoId
        })

        if (error) {
            ultimoEstadoCurso = !navigator.onLine || esErrorTransporteSupabase(error)
                ? { code: "offline", message: "No se pudo conectar con asistIA. Verifica tu conexión e inténtalo nuevamente." }
                : { code: "rpc_failed", message: "No se pudo cargar la información." }
            cursoQRValido = false
            return false
        }

        if (!data?.success) {
            ultimoEstadoCurso = { code: "invalid_token", message: "Acceso no válido. Escanee el código QR oficial del curso." }
            cursoQRValido = false
            return false
        }

        cursoActualId = Number(data.curso_id || 1) || 1
        cursoQRValido = true
        cursoValidadoEnSesion = true
        ultimoEstadoCurso = { code: "ok", message: "" }
        return true
    } catch (e) {
        ultimoEstadoCurso = !navigator.onLine || esErrorTransporteSupabase(e)
            ? { code: "offline", message: "No se pudo conectar con asistIA. Verifica tu conexión e inténtalo nuevamente." }
            : { code: "unexpected", message: "No se pudo cargar la información." }
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
    return resolverCursoPorToken(token)
}

function normalizarCursoBaseSupabase(row) {
    return {
        id: Number(row?.id || 1) || 1,
        nombre: String(row?.nombre || "").trim(),
        fecha_inicio: row?.fecha_inicio || null,
        fecha_fin: row?.fecha_fin || null
    }
}

async function cargarCursoBaseDesdeSupabase() {
    if (!haySupabase()) return null

    let q = withTenantScope(
        supabaseClient
            .from("cursos")
            .select("id,nombre,tenant_id,estado,fecha_inicio,fecha_fin")
    )

    const { data, error } = await q
        .eq("estado", "activo")
        .eq("id", cursoActualId || 1)
        .limit(1)

    if (error) {
        if (esTablaNoExiste(error)) return null
        return null
    }

    const row = Array.isArray(data) ? data[0] : null
    return row ? normalizarCursoBaseSupabase(row) : null
}

async function cargarConfigCurso() {
    if (!haySupabase()) return

    const cursoBase = await cargarCursoBaseDesdeSupabase()

    const { data: configData, error: configError } = await withTenantScope(
        supabaseClient.from("curso_configuracion").select("*")
    ).maybeSingle()

    cursoConfigCache = configError
        ? (cursoBase ? {
            nombre_curso: cursoBase.nombre || "",
            fecha_inicio: cursoBase.fecha_inicio || null,
            fecha_fin: cursoBase.fecha_fin || null,
            gps_activo: false,
            radio_m: 50
        } : null)
        : (configData ? Object.assign({}, configData, {
            nombre_curso: configData.nombre_curso || cursoBase?.nombre || ""
        }) : (cursoBase ? {
            nombre_curso: cursoBase.nombre || "",
            fecha_inicio: cursoBase.fecha_inicio || null,
            fecha_fin: cursoBase.fecha_fin || null,
            gps_activo: false,
            radio_m: 50
        } : null))

    let dataSecciones = []
    let errorSecciones = null

    ;({ data: dataSecciones, error: errorSecciones } = await withTenantScope(
        supabaseClient
            .from("curso_secciones")
            .select("seccion, modalidad, dias, hora_inicio, curso_id, tenant_id")
            .eq("curso_id", cursoActualId || 1)
            .order("seccion", { ascending: true })
    ))

    if (errorSecciones) {
        console.warn("No se pudo cargar curso_secciones:", errorSecciones.message || errorSecciones)
    }

    if (errorSecciones && /curso_id/i.test(String(errorSecciones.message || ""))) {
        const fallback = await withTenantScope(
            supabaseClient
                .from("curso_secciones")
                .select("seccion, modalidad, dias, hora_inicio, tenant_id")
                .order("seccion", { ascending: true })
        )
        dataSecciones = fallback.data || []
        errorSecciones = fallback.error
    }

    cursoSecciones = errorSecciones ? [] : (dataSecciones || []).map(item => ({
        seccion: normalizarCodigoSeccion(item.seccion),
        modalidad: normalizarModalidad(item.modalidad || "PRESENCIAL"),
        dias: Array.isArray(item.dias) ? item.dias : [],
        hora_inicio: item.hora_inicio || ""
    }))
}

function seleccionarBotonSeccion(valor) {
    document.querySelectorAll(".mobile-section-btn").forEach(btn => {
        btn.classList.toggle("active", btn.dataset.seccion === valor)
    })
}

function setSeccion(valor) {
    seccion = normalizarCodigoSeccion(valor)
    seleccionarBotonSeccion(seccion)
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

function renderSeccionesMovil() {
    if (!mobileSectionsContainer) return

    actualizarVisibilidadCamposLegacy()
    const seccionDetectada = obtenerSeccionAspiranteDetectada()
    const contextoRemoto = contextoAsistenciaActual
    const usarContextoRPC = tieneContextoRPCActivo()
    debugContextLog("renderSeccionesMovil: inicio", {
        hasRPC: usarContextoRPC,
        seccionDetectada,
        contextoRemoto
    })
    seccion = normalizarCodigoSeccion((usarContextoRPC ? contextoRemoto?.seccion : "") || seccionDetectada) || ""
    seleccionarBotonSeccion(seccion)
    mobileSectionsContainer.innerHTML = ""
    const contexto = usarContextoRPC
        ? contextoRemoto
        : (contextoRemoto || construirContextoLocalAsistencia(new Date(), seccionDetectada))
    const title = cursoConfigCache?.nombre_curso || "Curso"
    const nombreCompleto = `${String(nombres?.value || "").trim()} ${String(apellidos?.value || "").trim()}`
        .replace(/\s+/g, " ")
        .trim()
    let html = construirResumenContextualHTML({
        title,
        nombreCompleto,
        contexto,
        seccionDetectada
    })

    if (usarContextoRPC) {
        mobileSectionsContainer.innerHTML = html
        debugContextLog("renderSeccionesMovil: render RPC", {
            hasRPC: usarContextoRPC,
            htmlPreview: String(mobileSectionsContainer.innerHTML || "").replace(/\s+/g, " ").slice(0, 280)
        })
        return
    }

    if (!cursoSecciones.length) {
        if (!contexto?.seccion && !seccionDetectada) {
            html += `<p class="context-note">No hay secciones configuradas para este curso.</p>`
        }
        mobileSectionsContainer.innerHTML = html
        debugContextLog("renderSeccionesMovil: render sin secciones", {
            hasRPC: usarContextoRPC,
            htmlPreview: String(mobileSectionsContainer.innerHTML || "").replace(/\s+/g, " ").slice(0, 280)
        })
        return
    }

    if (contextoRemoto?.seccion || seccionDetectada) {
        mobileSectionsContainer.innerHTML = html
        debugContextLog("renderSeccionesMovil: render legacy sin selector", {
            hasRPC: usarContextoRPC,
            htmlPreview: String(mobileSectionsContainer.innerHTML || "").replace(/\s+/g, " ").slice(0, 280)
        })
        return
    }

    html += contexto.esDomingo
        ? `<p class="context-note">Selecciona tu sección de aspirante. Compatibilidad temporal para jornada dominical.</p>`
        : `<p class="context-note">Selecciona tu sección de aspirante para completar el registro.</p>`

    cursoSecciones.forEach(sec => {
        const dias = Array.isArray(sec.dias) ? sec.dias.join(", ") : ""
        const modalidadLabel = formatearModalidadAmigable(sec.modalidad)
        const label = `Sección ${sec.seccion}${dias ? ` · ${dias}` : ""}${modalidadLabel ? ` · ${modalidadLabel}` : ""}`
        html += `<button class="mobile-section-btn" type="button" data-seccion="${sec.seccion}">${label}</button>`
    })

    mobileSectionsContainer.innerHTML = html
    mobileSectionsContainer.querySelectorAll(".mobile-section-btn").forEach(btn => {
        btn.addEventListener("click", () => setSeccion(btn.dataset.seccion || ""))
    })
    debugContextLog("renderSeccionesMovil: render legacy con selector", {
        hasRPC: usarContextoRPC,
        secciones: cursoSecciones.map(sec => sec.seccion),
        htmlPreview: String(mobileSectionsContainer.innerHTML || "").replace(/\s+/g, " ").slice(0, 280)
    })
}

async function ingresarMovilInicio() {
    cancelarRetornoPostRegistro()
    const dniLimpio = limpiarDni(mobileDniInicio?.value)
    if (mobileDniInicio) mobileDniInicio.value = dniLimpio
    debugContextLog("ingresarMovilInicio: inicio", {
        dni: dniLimpio,
        cursoQRValido,
        tenantActivoId,
        cursoActualId
    })

    if (!dniLimpio) {
        setMensaje("⚠ Ingresa tu DNI para continuar", "error")
        return
    }

    if (!cursoQRValido) {
        setMensaje("Acceso no válido. Escanee el código QR oficial del curso.", "error")
        return
    }

    dniMovil = dniLimpio
    try {
        clearTimeout(debounceTimerAutocompletar)
        await cargarConfigCurso()
        debugContextLog("ingresarMovilInicio: config cargada", {
            cursoSecciones: cursoSecciones.map(sec => sec.seccion),
            cursoConfig: cursoConfigCache ? { nombre_curso: cursoConfigCache.nombre_curso || "" } : null
        })
        contextoAsistenciaActual = null
        const contextoRPC = await resolverContextoAsistenciaRPC(dniLimpio)

        if (contextoRPC?.success === true) {
            if (!contextoRPC.permitido) {
                const msgBloqueo = String(contextoRPC.message || extraerMensajesContexto(contextoRPC.bloqueos)[0] || "No se pudo resolver el contexto de asistencia.").trim()
                formulario.style.display = "none"
                if (stepIngreso) stepIngreso.style.display = "flex"
                setMensaje(msgBloqueo, "error")
                return
            }

            aplicarContextoResueltoEnFormulario(contextoRPC)
            const warnings = extraerMensajesContexto(contextoRPC.warnings)
            const estadoAmigable = formatearEstadoAsistenciaAmigable(contextoRPC.estado_asistencia)
            if (contextoRPC.estado_asistencia === "TARDANZA") {
                warnings.unshift(`Registro en ${estadoAmigable.toLowerCase()}`)
            } else if (contextoRPC.estado_asistencia === "FUERA_DE_HORARIO") {
                warnings.unshift(`Registro ${estadoAmigable.toLowerCase()}`)
            }
            if (warnings.length > 0) {
                setMensaje(warnings.join(" | "), "warning")
            } else {
                setMensaje("")
            }
        } else {
            debugContextLog("ingresarMovilInicio: fallback sin contexto RPC usable", {
                dni: dniLimpio,
                contextoRPC
            })
            setMensaje("")
        }

        renderSeccionesMovil()
        debugContextLog("ingresarMovilInicio: post-render", {
            hasRPC: tieneContextoRPCActivo(),
            contextoAsistenciaActual,
            htmlPreview: String(mobileSectionsContainer?.innerHTML || "").replace(/\s+/g, " ").slice(0, 280)
        })
        if (stepIngreso) stepIngreso.style.display = "none"
        formulario.style.display = "flex"
    } catch (error) {
        debugContextLog("ingresarMovilInicio: error", {
            dni: dniLimpio,
            error: String(error?.message || error)
        })
        console.error("Error preparando formulario de asistencia:", error)
        setMensaje("No se pudo cargar la información.", "error")
    }
}

function volverInicio() {
    cancelarRetornoPostRegistro()
    formulario.style.display = "none"
    if (mobileDniInicio) mobileDniInicio.value = dniMovil
    mostrarPasoMovil("ingreso")
    setMensaje("")
}

function getDeviceId() {
    let id = localStorage.getItem("dev")
    if (!id) {
        id = `dev-${Math.random().toString(36).slice(2, 12)}`
        localStorage.setItem("dev", id)
    }
    return id
}

async function procesarAutocompletadoDni(dniValue) {
    const dniLimpio = limpiarDni(dniValue)
    const preservarContextoRPC = tieneContextoRPCActivo() && contextoCorrespondeADni(dniLimpio)
    debugContextLog("procesarAutocompletadoDni: input", {
        dni: dniLimpio,
        preservarContextoRPC,
        hasRPC: tieneContextoRPCActivo()
    })

    if (mobileDniInicio && document.activeElement === mobileDniInicio) {
        mobileDniInicio.value = dniLimpio
    }

    if (dniLimpio.length !== 8) {
        if (!preservarContextoRPC) contextoAsistenciaActual = null
        limpiarCamposAspirante(!preservarContextoRPC)
        debugContextLog("procesarAutocompletadoDni: dni incompleto", {
            dni: dniLimpio,
            preservarContextoRPC
        })
        setMensaje("")
        return
    }

    clearTimeout(debounceTimerAutocompletar)
    debounceTimerAutocompletar = window.setTimeout(async () => {
        if (!haySupabase() || !tenantActivoId) return

        try {
            debugContextLog("procesarAutocompletadoDni: lookup inicio", {
                dni: dniLimpio,
                tenantActivoId,
                cursoActualId
            })
            const cursoEsperado = Number(cursoActualId || 1) || 1
            let data = null
            let error = null

            ;({ data, error } = await supabaseClient
                .from("aspirantes")
                .select("nombres, apellidos, ubo, curso_id, seccion")
                .eq("dni", dniLimpio)
                .eq("tenant_id", tenantActivoId)
                .single())

            if (error && /seccion/i.test(String(error.message || ""))) {
                const fallback = await supabaseClient
                    .from("aspirantes")
                    .select("nombres, apellidos, ubo, curso_id")
                    .eq("dni", dniLimpio)
                    .eq("tenant_id", tenantActivoId)
                    .single()
                data = fallback.data
                error = fallback.error
            }

            if (error || !data) {
                if (!preservarContextoRPC) contextoAsistenciaActual = null
                perfilAspiranteActual = { dni: "", seccion: "" }
                limpiarCamposAspirante(!preservarContextoRPC)
                debugContextLog("procesarAutocompletadoDni: aspirante no encontrado", {
                    dni: dniLimpio,
                    error: error ? String(error.message || error) : null,
                    preservarContextoRPC
                })
                setMensaje("⚠ El DNI ingresado no existe en el padrón de la institución.", "warning")
                return
            }

            const cursoAspirante = data.curso_id == null ? null : Number(data.curso_id)

            if (cursoAspirante != null && cursoAspirante !== cursoEsperado) {
                if (!preservarContextoRPC) contextoAsistenciaActual = null
                perfilAspiranteActual = { dni: "", seccion: "" }
                validacionCursoAspirante = {
                    dni: dniLimpio,
                    permitido: false,
                    legacy: false,
                    bloqueado: true
                }
                limpiarCamposAspirante(false)
                debugContextLog("procesarAutocompletadoDni: curso distinto", {
                    dni: dniLimpio,
                    cursoAspirante,
                    cursoEsperado
                })
                setMensaje("⚠ El aspirante no pertenece al curso de este QR.", "error")
                return
            }

            if (cursoAspirante == null) {
                console.warn("Aspirante sin curso_id; compatibilidad legacy aplicada para DNI:", dniLimpio)
            }

            validacionCursoAspirante = {
                dni: dniLimpio,
                permitido: true,
                legacy: cursoAspirante == null,
                bloqueado: false
            }
            perfilAspiranteActual = {
                dni: dniLimpio,
                seccion: esSeccionLegacy(data.seccion) ? "" : normalizarCodigoSeccion(data.seccion)
            }
            if (!preservarContextoRPC) contextoAsistenciaActual = null

            nombres.value = data.nombres || ""
            apellidos.value = data.apellidos || ""
            ubo.value = data.ubo || ""

            nombres.readOnly = true
            apellidos.readOnly = true
            ubo.readOnly = true
            nombres.style.backgroundColor = "#f3f6fb"
            apellidos.style.backgroundColor = "#f3f6fb"
            ubo.style.backgroundColor = "#f3f6fb"
            if (formulario?.style.display !== "none" && !preservarContextoRPC) {
                renderSeccionesMovil()
            }
            debugContextLog("procesarAutocompletadoDni: lookup exitoso", {
                dni: dniLimpio,
                seccionPerfil: perfilAspiranteActual.seccion,
                preservarContextoRPC,
                hasRPC: tieneContextoRPCActivo()
            })
            setMensaje("")
        } catch (e) {
            console.error("Error validando DNI de aspirante:", e)
            if (!preservarContextoRPC) contextoAsistenciaActual = null
            perfilAspiranteActual = { dni: "", seccion: "" }
            limpiarCamposAspirante(!preservarContextoRPC)
            debugContextLog("procesarAutocompletadoDni: error", {
                dni: dniLimpio,
                preservarContextoRPC,
                error: String(e?.message || e)
            })
            setMensaje(mensajeAmigable(e, "No se pudo cargar la información."), "error")
        }
    }, 300)
}

function limpiarCamposAspirante(resetValidacion = true) {
    nombres.value = ""
    apellidos.value = ""
    ubo.value = ""

    aplicarReadonlyVisual(nombres, false)
    aplicarReadonlyVisual(apellidos, false)
    aplicarReadonlyVisual(ubo, false)

    if (resetValidacion) {
        validacionCursoAspirante = { dni: "", permitido: true, legacy: false, bloqueado: false }
        perfilAspiranteActual = { dni: "", seccion: "" }
        contextoAsistenciaActual = null
    }
    actualizarVisibilidadCamposLegacy()
}

function esRpcV2NoDisponible(error) {
    const texto = String(error?.message || error || "")
    return /rpc_registrar_asistencia_v2|does not exist|42883/i.test(texto)
}

function construirWarningsRegistro(data, contextoAsistencia) {
    const warnings = extraerMensajesContexto(data?.warnings)
    const estado = String(
        data?.contexto?.estado_asistencia
        || contextoAsistencia?.estado_asistencia
        || ""
    ).trim().toUpperCase()

    if (estado === "TARDANZA") {
        warnings.unshift("Registro en tardanza")
    } else if (estado === "FUERA_DE_HORARIO") {
        warnings.unshift("Registro fuera de horario")
    }

    return deduplicarMensajes(warnings.filter(Boolean))
}

async function intentarRegistrarAsistenciaV2({ dniRegistro, deviceId }) {
    const tokenCurso = obtenerCursoTokenDesdeURL()

    if (!tokenCurso) {
        throw new Error("QR/token de curso no disponible para rpc_registrar_asistencia_v2.")
    }

    const timestamp = new Date().toISOString()

    debugContextLog("guardarAsistencia: intento v2", {
        dni: dniRegistro,
        tokenCursoExiste: !!tokenCurso,
        deviceId,
        cursoActualId,
        tenantActivoId
    })

    const { data, error } = await supabaseClient.rpc("rpc_registrar_asistencia_v2", {
        p_qr_token: tokenCurso,
        p_dni: dniRegistro,
        p_timestamp: timestamp,
        p_device_id: deviceId,
        p_latitud: null,
        p_longitud: null,
        p_origen_registro: "mobile_public"
    })

    debugContextLog("guardarAsistencia: respuesta v2", {
        dni: dniRegistro,
        error: error ? String(error.message || error) : null,
        data
    })

    if (error) throw error

    return data
}

async function intentarRegistrarAsistenciaLegacy({ dniRegistro, seccionRegistro, deviceId }) {
    debugContextLog("guardarAsistencia: intento legacy", {
        dni: dniRegistro,
        seccionRegistro,
        deviceId,
        cursoActualId,
        tenantActivoId
    })

    const { data, error } = await supabaseClient.rpc("rpc_registrar_asistencia", {
        p_dni: dniRegistro,
        p_tenant_id: tenantActivoId,
        p_seccion: seccionRegistro,
        p_latitud: 0,
        p_longitud: 0,
        p_device_id: deviceId,
        p_timestamp_local: new Date().toISOString(),
        p_curso_id: cursoActualId || 1,
        p_origen_registro: "mobile_public_legacy"
    })

    debugContextLog("guardarAsistencia: respuesta legacy", {
        dni: dniRegistro,
        error: error ? String(error.message || error) : null,
        data
    })

    if (error) throw error

    return data
}

async function guardarAsistencia() {
    const dniRegistro = limpiarDni(dniMovil || mobileDniInicio?.value)
    const nombresValor = String(nombres.value || "").trim()
    const apellidosValor = String(apellidos.value || "").trim()
    const uboValor = String(ubo.value || "").replace(/\D/g, "")
    const seccionBase = seccion || obtenerSeccionAspiranteDetectada()
    const contextoAsistencia = contextoAsistenciaActual || construirContextoLocalAsistencia(new Date(), seccionBase)
    const seccionRegistro = normalizarCodigoSeccion(contextoAsistencia.seccion || seccionBase)
    const deviceId = getDeviceId()

    if (!dniRegistro) {
        setMensaje("⚠ DNI no válido", "error")
        return
    }

    if (!cursoQRValido) {
        setMensaje("Acceso no válido. Escanee el código QR oficial del curso.", "error")
        return
    }

    if (validacionCursoAspirante?.dni === dniRegistro && validacionCursoAspirante?.bloqueado) {
        setMensaje("⚠ El aspirante no pertenece al curso de este QR.", "error")
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

    if (!seccionRegistro) {
        setMensaje("⚠ Selecciona una sección", "error")
        return
    }

    if (!haySupabase()) {
        await guardarAsistenciaOffline({
            dniRegistro,
            nombresValor,
            apellidosValor,
            seccionRegistro,
            modalidadRegistro: contextoAsistencia.modalidad,
            motivo: "No se pudo conectar con asistIA. Verifica tu conexión e inténtalo nuevamente."
        })
        return
    }

    if (!navigator.onLine) {
        await guardarAsistenciaOffline({
            dniRegistro,
            nombresValor,
            apellidosValor,
            seccionRegistro,
            modalidadRegistro: contextoAsistencia.modalidad,
            motivo: "No se pudo conectar con asistIA. Verifica tu conexión e inténtalo nuevamente."
        })
        return
    }

    try {
        let data = null
        let usoLegacy = false

        try {
            data = await intentarRegistrarAsistenciaV2({
                dniRegistro,
                deviceId
            })
        } catch (errorV2) {
            console.warn("Fallback legacy:", errorV2)

            debugContextLog("guardarAsistencia: fallback legacy", {
                dni: dniRegistro,
                error: String(errorV2?.message || errorV2),
                rpcV2NoDisponible: esRpcV2NoDisponible(errorV2)
            })

            usoLegacy = true
        }

        if (usoLegacy) {
            data = await intentarRegistrarAsistenciaLegacy({
                dniRegistro,
                seccionRegistro,
                deviceId
            })
        }

        if (!data?.success) {
            setMensaje(
                normalizarMensajePublicoFinal(String(data?.message || "Ocurrió un problema al procesar la solicitud.")),
                "error"
            )
            programarRetornoPostRegistro()
            return
        }

        if (!data?.registrado && data?.code === "asistencia_duplicada") {
            setMensaje(
                normalizarMensajePublicoFinal(String(data?.message || "El aspirante ya registró asistencia hoy.")),
                "warning"
            )
            programarRetornoPostRegistro()
            return
        }

        if (!data?.registrado && data?.code && data?.code !== "ok") {
            setMensaje(
                normalizarMensajePublicoFinal(String(data?.message || "No se pudo registrar la asistencia.")),
                "error"
            )
            programarRetornoPostRegistro()
            return
        }

        const warnings = construirWarningsRegistro(data, contextoAsistencia)

        if (warnings.length > 0) {
            setMensaje(
                normalizarMensajePublicoFinal(`✅ Asistencia registrada. ${warnings.join(" | ")}`),
                "warning"
            )
        } else {
            setMensaje(normalizarMensajePublicoFinal("✅ Asistencia registrada correctamente."), "ok")
        }

        // Limpiar el estado visual posterior al registro ocultando los contenedores interactivos
        if (formulario) formulario.style.display = "none"
        if (stepIngreso) stepIngreso.style.display = "none"

        debugContextLog("guardarAsistencia: registro exitoso", {
            dni: dniRegistro,
            usoLegacy,
            data
        })

        programarRetornoPostRegistro()
    } catch (e) {
        const guardadoOffline = await guardarAsistenciaOffline({
            dniRegistro,
            nombresValor,
            apellidosValor,
            seccionRegistro,
            modalidadRegistro: contextoAsistencia.modalidad,
            motivo: !navigator.onLine || esErrorTransporteSupabase(e)
                ? "No se pudo conectar con asistIA. Verifica tu conexión e inténtalo nuevamente."
                : "Ocurrió un problema al procesar la solicitud."
        })
        if (!guardadoOffline) {
            console.error("Error inesperado registrando asistencia:", e)
            setMensaje(mensajeAmigable(e, "Ocurrió un problema al procesar la solicitud."), "error")
        }
    }
}

function bindEventos() {
    document.getElementById("btnIngresarInicio")?.addEventListener("click", ingresarMovilInicio)
    document.getElementById("btnRegistrar")?.addEventListener("click", guardarAsistencia)
    document.getElementById("btnVolver")?.addEventListener("click", volverInicio)

    mobileDniInicio?.addEventListener("input", () => procesarAutocompletadoDni(mobileDniInicio.value))

    mobileDniInicio?.addEventListener("keydown", (event) => {
        if (event.key === "Enter") ingresarMovilInicio()
    })
}

async function init() {
    enlazarIds()
    bindEventos()
    actualizarContadorPendientes()

    tenantActivoId = detectarTenantDesdeRuta()
    aplicarTenantEnUI()

    if (!tenantActivoId) {
        setMensaje("⚠ No se pudo identificar la institución en la ruta.", "error")
        return
    }

    if (!haySupabase()) {
        setMensaje("No se pudo conectar con asistIA.", "error")
        return
    }

    const cursoValido = await resolverCursoDesdeURL()
    mostrarPasoMovil("ingreso")

    if (!cursoValido || !cursoQRValido) {
        setMensaje(ultimoEstadoCurso.message || "Acceso no válido. Escanee el código QR oficial del curso.", "error")
        if (mobileDniInicio) mobileDniInicio.disabled = true
        document.getElementById("btnIngresarInicio")?.setAttribute("disabled", "disabled")
        return
    }

    void sincronizarPendientes()
}

window.addEventListener("load", () => {
    void init()
})

window.addEventListener("online", () => {
    if (!leerColaPendientes().length) return
    void sincronizarPendientes({ notificar: true })
})

window.addEventListener("offline", () => {
    setMensaje("Sin conexión. Si registras asistencia, se guardará en este dispositivo.", "warning")
})
