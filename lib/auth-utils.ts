import { createClient } from "@supabase/supabase-js"
import crypto from "crypto"

export function generateSecureEmail(username: string, domain = "secure-domain.com") {
  const hashedUsername = crypto.createHash("sha256").update(username).digest("hex").substring(0, 8)
  return `user_${hashedUsername}@${domain}`
}

export async function checkUserExists(username: string) {
  try {
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
    const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ADMIN_KEY

    if (!supabaseUrl || !supabaseServiceKey) {
      console.error("Missing Supabase environment variables")
      return { exists: false, error: "Server configuration error" }
    }

    const supabase = createClient(supabaseUrl, supabaseServiceKey)

    // Verificar se o username existe na tabela profiles
    const { data, error } = await supabase.from("profiles").select("usuarios").eq("usuarios", username).limit(1)

    if (error) {
      console.error("Error checking if user exists:", error)
      return { exists: false, error: "Database error" }
    }

    return { exists: data && data.length > 0, error: null }
  } catch (error) {
    console.error("Error in checkUserExists:", error)
    return { exists: false, error: "Server error" }
  }
}
