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
      if (url.pathname === "/generate") return json({ api, token: await generate({ apikey: getAPIKey(req, query), ...query }) })
      else if (url.pathname === "/verify") return json({ api, data: await verify(query) })
      else return json({ api, gettingStarted, examples })
    } catch (error) {
      return json({ api, error }, 400)
    }
  }
}

const json = (obj, status) => new Response(JSON.stringify(obj, null, 2), { headers: { 'content-type': 'application/json; charset=utf-8' }, status })

function getAPIKey(req, query) {
  const apikey = query.apikey
  if (apikey) {
    delete query.apikey
    return apikey
  }
  const auth = req.headers.get('authorization')?.split(' ')
  return req.headers.get('x-api-key') || auth?.[1] || auth?.[0]
}

/**
 * Generates a JWT
 * @param {Object} query 
 * @param {*} query.accountId The unique identifier for the account
 * @param {string|undefined} query.secret The secret used to encode and verify the JWT
 * @param {string|undefined} query.apikey The API key used to determine the accountId and claims
 * @param {string|undefined} query.issuer The identity of the JWT issuer
 * @param {string|undefined} query.scope Permissions scopes granted by the JWT
 * @param {string|number|undefined} query.expirationTTL The JWT expiration timestamp as a number or a timespan string
 * @param {Object|undefined} query.claims Additional claims to include in the JWT payload
 * @returns A JWT generated from the query
 * @throws The JWT could not be generated from the query
 */
async function generate({ accountId, apikey, secret, issuer, scope, expirationTTL, ...claims }) {
  if (apikey) {
    const { profile, profile: { id } } = await env.APIKEYS.fetch(req).then(res => res.json())
    delete profile.id
    accountId = id
    claims = { ...profile, ...claims }
  }
  let signJwt = new SignJWT({ accountId, scope, ...claims })
    .setProtectedHeader({ alg: 'HS256' })
    .setJti(nanoid())
    .setIssuedAt()
  if (issuer) signJwt = signJwt.setIssuer(issuer)
  if (expirationTTL) signJwt = signJwt.setExpirationTime(expirationTTL)
  return await signJwt.sign(new Uint8Array(await crypto.subtle.digest('SHA-512', new TextEncoder().encode(secret))))
}

/**
 * Verifies a JWT
 * @param {Object} query
 * @param {string} query.token The JWT to be verified
 * @param {string|undefined} query.secret The secret used to encode and verify the JWT
 * @param {string|undefined} query.issuer The issuer of the JWT
 * @returns The decoded payload and header
 * @throws The JWT is not valid
 */
async function verify({ token, secret, issuer }) {
  const hash = await crypto.subtle.digest('SHA-512', new TextEncoder().encode(secret))
  return await jwtVerify(token, new Uint8Array(hash), { issuer })
}