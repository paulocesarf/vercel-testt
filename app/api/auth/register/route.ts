import { type NextRequest, NextResponse } from "next/server"
import { cookies } from "next/headers"
import { createClient } from "@supabase/supabase-js"
import crypto from "crypto"

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { username, password, recaptchaToken } = body

    // Verificar se todos os campos necessários estão presentes
    if (!username || !password || !recaptchaToken) {
      return NextResponse.json({ success: false, message: "All fields are required" }, { status: 400 })
    }

    // Verificar reCAPTCHA
    const recaptchaResponse = await fetch(`${request.nextUrl.origin}/api/verify-recaptcha`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: recaptchaToken }),
    })

    const recaptchaData = await recaptchaResponse.json()
    if (!recaptchaData.success) {
      return NextResponse.json({ success: false, message: "CAPTCHA verification failed" }, { status: 400 })
    }

    // Criar cliente Supabase
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!
    const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ADMIN_KEY || ""

    const supabase = createClient(supabaseUrl, supabaseServiceKey, {
      auth: {
        persistSession: false,
      },
    })

    // Verificar se o username já existe
    const { data: existingUsers, error: fetchError } = await supabase
      .from("profiles")
      .select("username")
      .eq("username", username)
      .limit(1)

    if (fetchError) {
      return NextResponse.json({ success: false, message: "Error checking username availability" }, { status: 500 })
    }

    if (existingUsers && existingUsers.length > 0) {
      return NextResponse.json({ success: false, message: "This username is already taken" }, { status: 400 })
    }

    // Gerar um email único baseado no username, mas não previsível
    const hashedUsername = crypto.createHash("sha256").update(username).digest("hex").substring(0, 8)
    const email = `user_${hashedUsername}@${process.env.AUTH_EMAIL_DOMAIN || "secure-domain.com"}`

    // Criar o usuário
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          username,
        },
      },
    })

    if (error) {
      return NextResponse.json({ success: false, message: error.message }, { status: 400 })
    }

    if (data.user) {
      // Criar perfil do usuário
      const { error: profileError } = await supabase.from("profiles").insert([
        {
          id: data.user.id,
          username,
          role: "user",
        },
      ])

      if (profileError) {
        return NextResponse.json({ success: false, message: "Error creating user profile" }, { status: 500 })
      }

      // Definir o cookie de sessão se houver uma sessão
      if (data.session) {
        const cookieStore = cookies()

        cookieStore.set("sb-access-token", data.session.access_token, {
          path: "/",
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          maxAge: data.session.expires_in,
          sameSite: "lax",
        })

        cookieStore.set("sb-refresh-token", data.session.refresh_token, {
          path: "/",
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          maxAge: 60 * 60 * 24 * 30, // 30 dias
          sameSite: "lax",
        })
      }
    }

    return NextResponse.json({
      success: true,
      user: {
        id: data.user?.id,
        username,
      },
    })
  } catch (error) {
    console.error("Registration error:", error)
    return NextResponse.json({ success: false, message: "An error occurred during registration" }, { status: 500 })
  }
}
