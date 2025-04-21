import { type NextRequest, NextResponse } from "next/server"
import { cookies } from "next/headers"
import { createClient } from "@supabase/supabase-js"
// Importar a função de utilidade
import { checkUserExists, generateSecureEmail } from "@/lib/auth-utils"

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { username, password, recaptchaToken } = body

    // Verificar se todos os campos necessários estão presentes
    if (!username || !password || !recaptchaToken) {
      return NextResponse.json({ success: false, message: "All fields are required" }, { status: 400 })
    }

    // Verificar reCAPTCHA
    try {
      const recaptchaResponse = await fetch(`${request.nextUrl.origin}/api/verify-recaptcha`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: recaptchaToken }),
      })

      if (!recaptchaResponse.ok) {
        const errorText = await recaptchaResponse.text()
        console.error("reCAPTCHA verification failed:", errorText)
        return NextResponse.json(
          { success: false, message: `CAPTCHA verification failed: ${errorText}` },
          { status: 400 },
        )
      }

      const recaptchaData = await recaptchaResponse.json()
      if (!recaptchaData.success) {
        console.error("reCAPTCHA verification failed:", recaptchaData)
        return NextResponse.json({ success: false, message: "CAPTCHA verification failed" }, { status: 400 })
      }
    } catch (recaptchaError) {
      console.error("Error during reCAPTCHA verification:", recaptchaError)
      return NextResponse.json({ success: false, message: "Error verifying CAPTCHA" }, { status: 500 })
    }

    // Verificar variáveis de ambiente
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
    const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ADMIN_KEY

    if (!supabaseUrl || !supabaseServiceKey) {
      console.error("Missing Supabase environment variables:", {
        hasUrl: !!supabaseUrl,
        hasKey: !!supabaseServiceKey,
      })
      return NextResponse.json(
        {
          success: false,
          message: "Server configuration error",
        },
        { status: 500 },
      )
    }

    // Criar cliente Supabase
    const supabase = createClient(supabaseUrl, supabaseServiceKey, {
      auth: {
        persistSession: false,
      },
    })

    // Substituir a geração de email por:
    // Verificar se o usuário existe antes de tentar fazer login
    const { exists, error: existsError } = await checkUserExists(username)

    if (existsError) {
      console.error("Error checking if user exists:", existsError)
      return NextResponse.json({ success: false, message: "Error verifying user" }, { status: 500 })
    }

    if (!exists) {
      console.warn(`Login attempt for non-existent user: ${username}`)
      return NextResponse.json({ success: false, message: "Invalid credentials" }, { status: 401 })
    }

    // Gerar email seguro
    const emailDomain = process.env.AUTH_EMAIL_DOMAIN || "secure-domain.com"
    const email = generateSecureEmail(username, emailDomain)

    console.log("Attempting login with email:", email.replace(/^(user_)(.{3})(.*)(@.*)$/, "$1$2***$4"))

    // Tentar fazer login
    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
      })

      if (error) {
        console.error("Supabase auth error:", error)
        return NextResponse.json({ success: false, message: "Invalid credentials" }, { status: 401 })
      }

      if (!data.session) {
        console.error("No session returned from Supabase")
        return NextResponse.json({ success: false, message: "Authentication failed" }, { status: 401 })
      }

      // Definir o cookie de sessão
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

      return NextResponse.json({
        success: true,
        user: {
          id: data.user.id,
          username,
        },
      })
    } catch (authError) {
      console.error("Error during Supabase authentication:", authError)
      return NextResponse.json({ success: false, message: "Authentication error" }, { status: 500 })
    }
  } catch (error) {
    console.error("Login error:", error)
    return NextResponse.json(
      {
        success: false,
        message: "An error occurred during login",
        error: process.env.NODE_ENV === "development" ? String(error) : undefined,
      },
      { status: 500 },
    )
  }
}
