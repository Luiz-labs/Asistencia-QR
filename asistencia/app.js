const supabaseUrl = "https://kcapmyovaigjntaqeqwn.supabase.co"
const supabaseKey = "sb_publishable_oObf3s5mQ4sfmJ03JKQrnQ__8Rmb63F"

const supabaseClient = window.supabase?.createClient
    ? window.supabase.createClient(supabaseUrl, supabaseKey)
    : null

let tenantActivoId = ""
let cursoActualId = 1
let cursoQRValido = false
let dniMovil = ""
let seccion = ""
let cursoConfigCache = null
let cursoSecciones = []
let debounceTimerAutocompletar = null
let validacionCursoAspirante = { dni: "", permitido: true, legacy: false, bloqueado: false }

let tenantLabel
let stepIngreso
let formulario
let mobileDniInicio
let nombres
let apellidos
let ubo
let mensaje
let mobileSectionsContainer

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
    mensaje = document.getElementById("mensaje")
    mobileSectionsContainer = document.getElementById("mobileSectionsContainer")
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
    const label = tenantActivoId ? `Institución: ${tenantActivoId}` : "Institución no detectada"
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

function mostrarPasoMovil(paso) {
    if (stepIngreso) stepIngreso.style.display = paso === "ingreso" ? "flex" : "none"
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

async function resolverCursoPorToken(token) {
    cursoQRValido = false
    if (!token || !haySupabase() || !tenantActivoId) return false

    try {
        const { data, error } = await supabaseClient.rpc("rpc_validar_curso_qr", {
            p_qr_token: token,
            p_tenant_id: tenantActivoId
        })

        if (error || !data?.success) {
            cursoQRValido = false
            return false
        }

        cursoActualId = Number(data.curso_id || 1) || 1
        cursoQRValido = true
        return true
    } catch (e) {
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
            .select("*")
            .eq("curso_id", cursoActualId || 1)
            .order("seccion", { ascending: true })
    ))

    if (errorSecciones && /curso_id/i.test(String(errorSecciones.message || ""))) {
        const fallback = await withTenantScope(
            supabaseClient
                .from("curso_secciones")
                .select("*")
                .order("seccion", { ascending: true })
        )
        dataSecciones = fallback.data || []
        errorSecciones = fallback.error
    }

    cursoSecciones = errorSecciones ? [] : (dataSecciones || []).map(item => ({
        seccion: String(item.seccion || "").trim().toUpperCase(),
        modalidad: String(item.modalidad || "Presencial").trim(),
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
    seccion = valor
    seleccionarBotonSeccion(valor)
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

    seccion = ""
    seleccionarBotonSeccion("")
    mobileSectionsContainer.innerHTML = ""

    if (esDomingoLima()) {
        mobileSectionsContainer.innerHTML = `
            <p class="step-copy">Jornada dominical general</p>
            <p class="tenant-label">Hoy no es necesario elegir sección. El registro se guardará como GENERAL.</p>
        `
        return
    }

    if (!cursoSecciones.length) {
        mobileSectionsContainer.innerHTML = `<p class="tenant-label">No hay secciones configuradas para este curso.</p>`
        return
    }

    const title = cursoConfigCache?.nombre_curso || "Curso"
    let html = `<p class="step-copy">${title}</p>`
    cursoSecciones.forEach(sec => {
        const dias = Array.isArray(sec.dias) ? sec.dias.join(", ") : ""
        const label = `Sección ${sec.seccion}${dias ? ` · ${dias}` : ""}${sec.modalidad ? ` · ${sec.modalidad}` : ""}`
        html += `<button class="mobile-section-btn" type="button" data-seccion="${sec.seccion}">${label}</button>`
    })

    mobileSectionsContainer.innerHTML = html
    mobileSectionsContainer.querySelectorAll(".mobile-section-btn").forEach(btn => {
        btn.addEventListener("click", () => setSeccion(btn.dataset.seccion || ""))
    })
}

async function ingresarMovilInicio() {
    const dniLimpio = limpiarDni(mobileDniInicio?.value)
    if (mobileDniInicio) mobileDniInicio.value = dniLimpio

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
        await cargarConfigCurso()
        renderSeccionesMovil()
        setMensaje("")
        if (stepIngreso) stepIngreso.style.display = "none"
        formulario.style.display = "flex"
    } catch (error) {
        setMensaje("⚠ No se pudo preparar el formulario de asistencia.", "error")
    }
}

function volverInicio() {
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

    if (mobileDniInicio && document.activeElement === mobileDniInicio) {
        mobileDniInicio.value = dniLimpio
    }

    if (dniLimpio.length !== 8) {
        limpiarCamposAspirante()
        setMensaje("")
        return
    }

    clearTimeout(debounceTimerAutocompletar)
    debounceTimerAutocompletar = window.setTimeout(async () => {
        if (!haySupabase() || !tenantActivoId) return

        try {
            const cursoEsperado = Number(cursoActualId || 1) || 1
            const { data, error } = await supabaseClient
                .from("aspirantes")
                .select("nombres, apellidos, ubo, curso_id")
                .eq("dni", dniLimpio)
                .eq("tenant_id", tenantActivoId)
                .single()

            if (error || !data) {
                limpiarCamposAspirante()
                setMensaje("⚠ El DNI ingresado no existe en el padrón de la institución.", "warning")
                return
            }

            const cursoAspirante = data.curso_id == null ? null : Number(data.curso_id)

            if (cursoAspirante != null && cursoAspirante !== cursoEsperado) {
                validacionCursoAspirante = {
                    dni: dniLimpio,
                    permitido: false,
                    legacy: false,
                    bloqueado: true
                }
                limpiarCamposAspirante(false)
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

            nombres.value = data.nombres || ""
            apellidos.value = data.apellidos || ""
            ubo.value = data.ubo || ""

            nombres.readOnly = true
            apellidos.readOnly = true
            ubo.readOnly = true
            nombres.style.backgroundColor = "#f3f6fb"
            apellidos.style.backgroundColor = "#f3f6fb"
            ubo.style.backgroundColor = "#f3f6fb"
            setMensaje("")
        } catch (e) {
            limpiarCamposAspirante()
            setMensaje("⚠ No se pudo validar el DNI en este momento.", "error")
        }
    }, 300)
}

function limpiarCamposAspirante(resetValidacion = true) {
    nombres.value = ""
    apellidos.value = ""
    ubo.value = ""

    nombres.readOnly = false
    apellidos.readOnly = false
    ubo.readOnly = false

    nombres.style.backgroundColor = ""
    apellidos.style.backgroundColor = ""
    ubo.style.backgroundColor = ""

    if (resetValidacion) {
        validacionCursoAspirante = { dni: "", permitido: true, legacy: false, bloqueado: false }
    }
}

async function guardarAsistencia() {
    const dniRegistro = limpiarDni(dniMovil || mobileDniInicio?.value)
    const nombresValor = String(nombres.value || "").trim()
    const apellidosValor = String(apellidos.value || "").trim()
    const uboValor = String(ubo.value || "").replace(/\D/g, "")
    const seccionRegistro = esDomingoLima(new Date()) ? "GENERAL" : seccion

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

    try {
        const { data, error } = await supabaseClient.rpc("rpc_registrar_asistencia", {
            p_dni: dniRegistro,
            p_tenant_id: tenantActivoId,
            p_seccion: seccionRegistro,
            p_latitud: 0,
            p_longitud: 0,
            p_device_id: getDeviceId(),
            p_timestamp_local: new Date().toISOString(),
            p_curso_id: cursoActualId || 1
        })

        if (error) {
            setMensaje("⚠ Error de comunicación con el servidor", "error")
            return
        }

        if (!data?.success) {
            setMensaje(`⚠ ${data?.message || "No se pudo registrar la asistencia."}`, "error")
            return
        }

        if (data.warning) {
            const warnMsgs = Array.isArray(data.warnings) ? data.warnings.join(" | ") : "Atención requerida"
            setMensaje(`✅ Registrado con alerta: ${warnMsgs}`, "warning")
        } else {
            setMensaje("✅ Registrado", "ok")
        }

        limpiarCamposAspirante()
        seccion = ""
        seleccionarBotonSeccion("")
    } catch (e) {
        setMensaje("⚠ Error inesperado al registrar asistencia", "error")
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

    tenantActivoId = detectarTenantDesdeRuta()
    aplicarTenantEnUI()

    if (!tenantActivoId) {
        setMensaje("⚠ No se pudo identificar la institución en la ruta.", "error")
        return
    }

    if (!haySupabase()) {
        setMensaje("⚠ No se pudo iniciar la conexión con el servidor.", "error")
        return
    }

    const cursoValido = await resolverCursoDesdeURL()
    mostrarPasoMovil("ingreso")

    if (!cursoValido || !cursoQRValido) {
        setMensaje("Acceso no válido. Escanee el código QR oficial del curso.", "error")
        if (mobileDniInicio) mobileDniInicio.disabled = true
        document.getElementById("btnIngresarInicio")?.setAttribute("disabled", "disabled")
    }
}

window.addEventListener("load", () => {
    void init()
})
