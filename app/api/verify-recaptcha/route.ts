import { type NextRequest, NextResponse } from "next/server"

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { token } = body

    if (!token) {
      return NextResponse.json({ success: false, message: "Token is required" }, { status: 400 })
    }

    // Verificar se a chave secreta do reCAPTCHA está configurada
    const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY
    if (!RECAPTCHA_SECRET_KEY) {
      console.error("RECAPTCHA_SECRET_KEY is not configured")
      return NextResponse.json({ success: false, message: "reCAPTCHA not configured properly" }, { status: 500 })
    }

    // Verificar o token com a API do Google
    try {
      const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${token}`

      const response = await fetch(verifyUrl, { method: "POST" })

      if (!response.ok) {
        const errorText = await response.text()
        console.error("Google reCAPTCHA API error:", errorText)
        return NextResponse.json(
          {
            success: false,
            message: "Error contacting reCAPTCHA service",
          },
          { status: 500 },
        )
      }

      const data = await response.json()
      console.log("reCAPTCHA verification response:", data)

      // Verificar resultado
      if (!data.success) {
        console.error("reCAPTCHA verification failed:", data["error-codes"])
        return NextResponse.json(
          {
            success: false,
            message: "CAPTCHA verification failed",
            errors: data["error-codes"],
          },
          { status: 400 },
        )
      }

      // Verificar score (se estiver usando reCAPTCHA v3)
      if (data.score !== undefined && data.score < 0.5) {
        console.warn("reCAPTCHA score too low:", data.score)
        return NextResponse.json(
          {
            success: false,
            message: "CAPTCHA score too low",
            score: data.score,
          },
          { status: 400 },
        )
      }

      return NextResponse.json({ success: true })
    } catch (fetchError) {
      console.error("Error fetching from Google reCAPTCHA API:", fetchError)
      return NextResponse.json(
        {
          success: false,
          message: "Error verifying CAPTCHA with Google",
        },
        { status: 500 },
      )
    }
  } catch (error) {
    console.error("Error verifying reCAPTCHA:", error)
    return NextResponse.json(
      {
        success: false,
        message: "Internal server error",
        error: process.env.NODE_ENV === "development" ? String(error) : undefined,
      },
      { status: 500 },
    )
  }
}
