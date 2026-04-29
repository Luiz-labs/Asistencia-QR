import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

type ProvisionPayload = {
  usuario?: string;
  clave?: string;
  correo?: string;
  tenant_id?: string;
  rol?: string;
  nombres?: string;
  apellidos?: string;
  dni?: string;
  celular?: string;
  perfil_id?: string;
  previous_usuario?: string;
  activo?: boolean;
};

function json(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });
}

function normalizeRole(role: string) {
  const raw = String(role || "").trim().toLowerCase();
  return raw === "super_admin" || raw === "superusuario" ? "superusuario" : "administrador";
}

function normalizeProfileId(id: string) {
  const raw = String(id || "").trim().toLowerCase();
  return raw
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function normalizeEmail(usuario: string, correo: string) {
  const clean = String(correo || "").trim().toLowerCase();
  if (clean && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean)) return clean;
  const user = String(usuario || "").trim().toLowerCase();
  return `${user}@asistia.local`;
}

async function findAuthUserByEmail(adminClient: ReturnType<typeof createClient>, email: string) {
  let page = 1;
  while (page <= 10) {
    const { data, error } = await adminClient.auth.admin.listUsers({
      page,
      perPage: 1000,
    });
    if (error) throw error;
    const match = (data?.users || []).find((item) =>
      String(item.email || "").trim().toLowerCase() === email
    );
    if (match) return match;
    if ((data?.users || []).length < 1000) break;
    page += 1;
  }
  return null;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return json(405, { ok: false, error: "Method not allowed." });
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY") || "";
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
  const authHeader = req.headers.get("Authorization") || "";

  if (!supabaseUrl || !anonKey || !serviceRoleKey) {
    return json(500, { ok: false, error: "Missing Supabase environment variables." });
  }

  if (!authHeader.startsWith("Bearer ")) {
    return json(401, { ok: false, error: "Missing bearer token." });
  }

  const client = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: authHeader } },
  });
  const admin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  try {
    const { data: authData, error: authError } = await client.auth.getUser();
    if (authError || !authData?.user?.id) {
      return json(401, { ok: false, error: "Unauthorized." });
    }

    const callerId = String(authData.user.id || "").trim();
    const { data: callerProfile, error: callerProfileError } = await admin
      .from("profiles")
      .select("id, role, tenant_id, is_active")
      .eq("id", callerId)
      .single();

    if (callerProfileError || !callerProfile) {
      return json(403, { ok: false, error: "Caller profile not found." });
    }
    if (callerProfile.is_active === false) {
      return json(403, { ok: false, error: "Caller profile is inactive." });
    }

    const callerRole = normalizeRole(String(callerProfile.role || ""));
    if (callerRole !== "superusuario" && callerRole !== "administrador") {
      return json(403, { ok: false, error: "Insufficient permissions." });
    }

    const raw = (await req.json()) as ProvisionPayload;
    const usuario = String(raw.usuario || "").trim().toLowerCase();
    const previousUsuario = String(raw.previous_usuario || "").trim().toLowerCase();
    const clave = String(raw.clave || "").trim();
    const nombres = String(raw.nombres || "").trim();
    const apellidos = String(raw.apellidos || "").trim();
    const dni = String(raw.dni || "").replace(/\D/g, "");
    const celular = String(raw.celular || "").replace(/\D/g, "");
    const rol = normalizeRole(String(raw.rol || "administrador"));
    const tenantId = String(raw.tenant_id || "").trim().toLowerCase();
    const perfilId = normalizeProfileId(String(raw.perfil_id || "administrador")) || "administrador";
    const activo = raw.activo !== false;
    const correo = normalizeEmail(usuario, String(raw.correo || ""));
    const nombreCompleto = `${nombres} ${apellidos}`.trim() || usuario;

    if (!usuario || !clave || !nombres || !apellidos || !dni) {
      return json(400, { ok: false, error: "Missing required fields." });
    }
    if (dni.length !== 8) {
      return json(400, { ok: false, error: "DNI must have 8 digits." });
    }
    if (!perfilId) {
      return json(400, { ok: false, error: "Invalid perfil_id." });
    }
    if (rol === "administrador" && !tenantId) {
      return json(400, { ok: false, error: "tenant_id is required for institutional admins." });
    }
    if (callerRole !== "superusuario") {
      const callerTenant = String(callerProfile.tenant_id || "").trim().toLowerCase();
      if (rol !== "administrador" || !callerTenant || tenantId !== callerTenant) {
        return json(403, { ok: false, error: "You can only provision admins for your own tenant." });
      }
    }

    const { data: perfilRow, error: perfilError } = await admin
      .from("perfiles_luiz")
      .select("id, estado")
      .eq("id", perfilId)
      .eq("estado", "activo")
      .single();

    if (perfilError || !perfilRow) {
      return json(400, { ok: false, error: "perfil_id does not exist or is inactive." });
    }

    let existingRow = null as Record<string, unknown> | null;
    if (previousUsuario && previousUsuario !== usuario) {
      const { data } = await admin
        .from("usuarios_admin")
        .select("id, usuario, auth_user_id")
        .eq("usuario", previousUsuario)
        .maybeSingle();
      existingRow = data;
    }
    if (!existingRow) {
      const { data } = await admin
        .from("usuarios_admin")
        .select("id, usuario, auth_user_id")
        .eq("usuario", usuario)
        .maybeSingle();
      existingRow = data;
    }

    let authUser = null as { id: string; email?: string | null } | null;
    const existingAuthUserId = String(existingRow?.auth_user_id || "").trim();
    if (existingAuthUserId) {
      const { data: existingAuthData, error: existingAuthError } = await admin.auth.admin.getUserById(existingAuthUserId);
      if (!existingAuthError && existingAuthData?.user) {
        authUser = {
          id: existingAuthData.user.id,
          email: existingAuthData.user.email,
        };
      }
    }
    if (!authUser) {
      authUser = await findAuthUserByEmail(admin, correo);
    }

    if (authUser?.id) {
      const { data: updatedAuth, error: updateAuthError } = await admin.auth.admin.updateUserById(authUser.id, {
        email: correo,
        password: clave,
        email_confirm: true,
        user_metadata: {
          usuario,
          nombres,
          apellidos,
          dni,
          celular,
          tenant_id: tenantId,
          perfil_id: perfilId,
        },
        app_metadata: {
          role: rol,
          tenant_id: tenantId,
        },
      });
      if (updateAuthError || !updatedAuth?.user?.id) {
        return json(500, { ok: false, error: updateAuthError?.message || "Could not update auth user." });
      }
      authUser = {
        id: updatedAuth.user.id,
        email: updatedAuth.user.email,
      };
    } else {
      const { data: createdAuth, error: createAuthError } = await admin.auth.admin.createUser({
        email: correo,
        password: clave,
        email_confirm: true,
        user_metadata: {
          usuario,
          nombres,
          apellidos,
          dni,
          celular,
          tenant_id: tenantId,
          perfil_id: perfilId,
        },
        app_metadata: {
          role: rol,
          tenant_id: tenantId,
        },
      });
      if (createAuthError || !createdAuth?.user?.id) {
        return json(500, { ok: false, error: createAuthError?.message || "Could not create auth user." });
      }
      authUser = {
        id: createdAuth.user.id,
        email: createdAuth.user.email,
      };
    }

    const roleDb = rol === "superusuario" ? "super_admin" : "administrador";
    const userPayload = {
      nombre: nombreCompleto,
      nombres,
      apellidos,
      dni,
      correo,
      celular,
      usuario,
      clave,
      rol: roleDb,
      activo,
      tenant_id: tenantId || null,
      auth_user_id: authUser.id,
    };

    if (existingRow?.id) {
      const { error: updateUserError } = await admin
        .from("usuarios_admin")
        .update(userPayload)
        .eq("id", existingRow.id);
      if (updateUserError) {
        return json(500, { ok: false, error: updateUserError.message });
      }
    } else {
      const { error: insertUserError } = await admin
        .from("usuarios_admin")
        .insert([userPayload]);
      if (insertUserError) {
        return json(500, { ok: false, error: insertUserError.message });
      }
    }

    if (previousUsuario && previousUsuario !== usuario) {
      const { data: previousMap } = await admin
        .from("usuarios_perfiles_luiz")
        .select("usuario")
        .eq("usuario", previousUsuario)
        .maybeSingle();
      if (previousMap?.usuario) {
        const { error: updateMapError } = await admin
          .from("usuarios_perfiles_luiz")
          .update({ usuario, perfil_id: perfilId })
          .eq("usuario", previousUsuario);
        if (updateMapError) {
          return json(500, { ok: false, error: updateMapError.message });
        }
      } else {
        const { error: insertMapError } = await admin
          .from("usuarios_perfiles_luiz")
          .upsert([{ usuario, perfil_id: perfilId }], { onConflict: "usuario" });
        if (insertMapError) {
          return json(500, { ok: false, error: insertMapError.message });
        }
      }
    } else {
      const { error: mapError } = await admin
        .from("usuarios_perfiles_luiz")
        .upsert([{ usuario, perfil_id: perfilId }], { onConflict: "usuario" });
      if (mapError) {
        return json(500, { ok: false, error: mapError.message });
      }
    }

    const { error: profileUpsertError } = await admin
      .from("profiles")
      .upsert([{
        id: authUser.id,
        email: correo,
        full_name: nombreCompleto,
        role: rol,
        tenant_id: tenantId || null,
        is_active: activo,
      }], { onConflict: "id" });

    if (profileUpsertError) {
      return json(500, { ok: false, error: profileUpsertError.message });
    }

    return json(200, {
      ok: true,
      usuario,
      correo,
      tenant_id: tenantId,
      rol,
      perfil_id: perfilId,
      auth_user_id: authUser.id,
    });
  } catch (error) {
    console.error("provision-admin-user error", error);
    return json(500, {
      ok: false,
      error: error instanceof Error ? error.message : "Unexpected error.",
    });
  }
});
