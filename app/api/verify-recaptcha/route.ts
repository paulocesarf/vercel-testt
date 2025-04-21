import { type NextRequest, NextResponse } from "next/server"

// Segredo do reCAPTCHA - deve ser armazenado como variável de ambiente
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { token } = body

    if (!token) {
      return NextResponse.json({ success: false, message: "Token is required" }, { status: 400 })
    }

    // Verificar o token com a API do Google
    const response = await fetch(
      `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${token}`,
      { method: "POST" },
    )

    const data = await response.json()

    // Adicionar verificações adicionais
    if (!data.success) {
      console.error("reCAPTCHA verification failed:", data)
      return NextResponse.json({ success: false, message: "CAPTCHA verification failed" }, { status: 400 })
    }

    // Verificar score (se estiver usando reCAPTCHA v3)
    if (data.score && data.score < 0.5) {
      return NextResponse.json({ success: false, message: "CAPTCHA score too low" }, { status: 400 })
    }

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error("Error verifying reCAPTCHA:", error)
    return NextResponse.json({ success: false, message: "Internal server error" }, { status: 500 })
  }
}
