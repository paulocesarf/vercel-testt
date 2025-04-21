import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"
import { createMiddlewareClient } from "@supabase/auth-helpers-nextjs"

// Limite de tentativas de login por IP
const loginAttempts = new Map<string, { count: number; timestamp: number }>()
const MAX_ATTEMPTS = 5
const LOCKOUT_TIME = 15 * 60 * 1000 // 15 minutos em milissegundos

export async function middleware(req: NextRequest) {
  const res = NextResponse.next()
  const supabase = createMiddlewareClient({ req, res })

  // Verificar se é uma requisição de login ou registro
  if (
    (req.nextUrl.pathname === "/api/verify-recaptcha" ||
      req.nextUrl.pathname === "/api/auth/login" ||
      req.nextUrl.pathname === "/api/auth/register") &&
    req.method === "POST"
  ) {
    // Obter IP do cliente (use X-Forwarded-For em produção)
    const ip = req.headers.get("x-forwarded-for") || "unknown-ip"

    // Verificar se o IP está bloqueado
    const ipData = loginAttempts.get(ip)
    if (ipData) {
      const timeSinceLastAttempt = Date.now() - ipData.timestamp

      // Se ainda estiver no período de bloqueio
      if (ipData.count >= MAX_ATTEMPTS && timeSinceLastAttempt < LOCKOUT_TIME) {
        return new NextResponse(
          JSON.stringify({
            error: "Too many attempts. Please try again later.",
          }),
          { status: 429, headers: { "Content-Type": "application/json" } },
        )
      }

      // Resetar contador se já passou o tempo de bloqueio
      if (timeSinceLastAttempt >= LOCKOUT_TIME) {
        loginAttempts.set(ip, { count: 1, timestamp: Date.now() })
      } else {
        // Incrementar contador
        loginAttempts.set(ip, {
          count: ipData.count + 1,
          timestamp: Date.now(),
        })
      }
    } else {
      // Primeiro acesso deste IP
      loginAttempts.set(ip, { count: 1, timestamp: Date.now() })
    }
  }

  return res
}

export const config = {
  matcher: ["/api/verify-recaptcha", "/api/auth/login", "/api/auth/register"],
}
