"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { zodResolver } from "@hookform/resolvers/zod"
import { useForm } from "react-hook-form"
import { z } from "zod"
import { Loader2 } from "lucide-react"
import ReCAPTCHA from "react-google-recaptcha"

import { Button } from "@/components/ui/button"
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"

const formSchema = z.object({
  username: z.string().min(1, {
    message: "Username is required.",
  }),
  password: z.string().min(1, {
    message: "Password is required.",
  }),
})

export default function LoginPage() {
  const router = useRouter()
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [recaptchaToken, setRecaptchaToken] = useState<string | null>(null)
  const [debugInfo, setDebugInfo] = useState<string | null>(null)

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      username: "",
      password: "",
    },
  })

  const handleRecaptchaChange = (token: string | null) => {
    setRecaptchaToken(token)
    if (token) {
      setError(null) // Limpar erros quando o reCAPTCHA for preenchido
    }
  }

  async function onSubmit(values: z.infer<typeof formSchema>) {
    setIsLoading(true)
    setError(null)
    setDebugInfo(null)

    try {
      // Verificar reCAPTCHA
      if (!recaptchaToken) {
        throw new Error("Please complete the CAPTCHA")
      }

      // Usar nossa API segura para login
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: values.username,
          password: values.password,
          recaptchaToken,
        }),
      })

      const responseText = await response.text()
      let data

      try {
        data = JSON.parse(responseText)
      } catch (e) {
        console.error("Failed to parse response as JSON:", responseText)
        throw new Error("Server returned an invalid response")
      }

      if (!response.ok) {
        if (process.env.NODE_ENV === "development") {
          setDebugInfo(JSON.stringify(data, null, 2))
        }
        throw new Error(data.message || "Invalid username or password")
      }

      router.push("/dashboard")
      router.refresh()
    } catch (error: any) {
      setError(error.message || "Invalid username or password. Please try again.")
      console.error(error)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center gradient-bg p-4">
      <div className="w-full max-w-md space-y-10">
        {/* Title and Subtitle */}
        <div className="text-center">
          <h1 className="text-3xl font-bold text-white">Sign In</h1>
          <p className="text-white/70 mt-2">Sign in to access all features.</p>
        </div>

        <div className="bg-black/40 p-10 rounded-xl backdrop-blur-md border border-white/20 shadow-lg">
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-white text-sm font-medium">Username</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="Your username"
                        {...field}
                        className="bg-black/50 border-white/20 text-white focus:ring-2 focus:ring-primary focus:outline-none"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="text-white text-sm font-medium">Password</FormLabel>
                    <FormControl>
                      <Input
                        type="password"
                        placeholder="Your password"
                        {...field}
                        className="bg-black/50 border-white/20 text-white focus:ring-2 focus:ring-primary focus:outline-none"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="flex justify-center">
                <ReCAPTCHA sitekey="6Lcg4x8rAAAAAGftG8e4C6gMZhaHXjjF3N85i-a5" onChange={handleRecaptchaChange} />
              </div>

              {error && (
                <div className="text-red-400 text-sm font-medium text-center p-2 bg-red-400/10 rounded-md border border-red-400/20">
                  {error}
                </div>
              )}

              {debugInfo && process.env.NODE_ENV === "development" && (
                <div className="text-xs font-mono bg-gray-800 p-2 rounded-md overflow-auto max-h-32 text-white/70">
                  <pre>{debugInfo}</pre>
                </div>
              )}

              <Button
                type="submit"
                className="w-full py-3 text-lg font-semibold rounded-lg transition-transform transform hover:scale-105"
                variant="gradient"
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                    Signing in...
                  </>
                ) : (
                  "Login"
                )}
              </Button>

              <div className="text-center text-sm text-white/70">
                You don't have an account yet?{" "}
                <Link href="/register" className="text-primary font-medium hover:underline">
                  Sign up
                </Link>
              </div>
            </form>
          </Form>
        </div>
      </div>
    </div>
  )
}
