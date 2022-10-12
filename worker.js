import { jwtVerify, SignJWT } from 'jose'
import { nanoid } from 'nanoid'

export const api = {
  icon: '🚀',
  name: 'jwt.do',
  description: 'JWT Token Generation & Verification API',
  url: 'https://jwt.do/api',
  type: 'https://apis.do/security',
  endpoints: {
    generate: 'https://jwt.do/generate',
    verify: 'https://jwt.do/verify',
  },
  site: 'https://jwt.do',
  login: 'https://jwt.do/login',
  signup: 'https://jwt.do/signup',
  subscribe: 'https://jwt.do/subscribe',
  repo: 'https://github.com/drivly/jwt.do',
}

export const gettingStarted = [
  `If you don't already have a JSON Viewer Browser Extension, get that first:`,
  `https://extensions.do`,
]

export const examples = {
  generate: 'https://jwt.do/generate?accountId=1234&secret=secret&issuer=jwt.do&scope=user:read&expirationTTL=2h',
  verify: 'https://jwt.do/verify?token=:token&secret=secret&issuer=jwt.do',
}

export default {
  fetch: async (req, env) => {
    try {
      const url = new URL(req.url)
      const query = Object.fromEntries(url.searchParams)
      if (url.pathname === "/generate") return json({ api, token: await generate(query) })
      else if (url.pathname === "/verify") return json({ api, data: await verify(query) })
      else return json({ api, gettingStarted, examples })
    } catch (error) {
      return json({ api, error }, 400)
    }
  }
}

const json = (obj, status) => new Response(JSON.stringify(obj, null, 2), { headers: { 'content-type': 'application/json; charset=utf-8' }, status })

async function generate({ accountId, secret, issuer = undefined, scope = undefined, expirationTTL = undefined }) {
  let signJwt = new SignJWT({ accountId, scope })
    .setProtectedHeader({ alg: 'HS256' })
    .setJti(nanoid())
    .setIssuedAt()
  if (issuer) signJwt = signJwt.setIssuer(issuer)
  if (expirationTTL) signJwt = signJwt.setExpirationTime(expirationTTL)
  return await signJwt.sign(new Uint8Array(await crypto.subtle.digest('SHA-512', new TextEncoder().encode(secret))))
}

async function verify({ token, secret, issuer = undefined }) {
  const hash = await crypto.subtle.digest('SHA-512', new TextEncoder().encode(secret))
  return await jwtVerify(token, new Uint8Array(hash), { issuer })
}