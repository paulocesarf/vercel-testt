import { type NextRequest, NextResponse } from "next/server"
import { createRouteHandlerClient } from "@supabase/auth-helpers-nextjs"
import { cookies } from "next/headers"
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
    const supabase = createRouteHandlerClient({ cookies })

    // Gerar um email único baseado no username, mas não previsível
    const hashedUsername = crypto.createHash("sha256").update(username).digest("hex").substring(0, 8)
    const email = `user_${hashedUsername}@${process.env.AUTH_EMAIL_DOMAIN || "secure-domain.com"}`

    // Tentar fazer login
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    })

    if (error) {
      // Não revelar informações específicas sobre o erro
      return NextResponse.json({ success: false, message: "Invalid credentials" }, { status: 401 })
    }

    return NextResponse.json({
      success: true,
      user: {
        id: data.user.id,
        username,
      },
    })
  } catch (error) {
    console.error("Login error:", error)
    return NextResponse.json({ success: false, message: "An error occurred during login" }, { status: 500 })
  }
}
