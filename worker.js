export const api = {
  icon: '🚀',
  name: 'jwt.do',
  description: 'JWT Token Generation & Verification API',
  url: 'https://jwt.do/api',
  type: 'https://apis.do/security',
  endpoints: {
    listCategories: 'https://jwt.do/api',
    getCategory: 'https://jwt.do/:type',
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
  listItems: 'https://templates.do/worker',
}

export default {
  fetch: async (req, env) => {
    const { user, hostname, pathname, rootPath, pathSegments, query } = await env.CTX.fetch(req).then(res => res.json())
    if (rootPath) return json({ api, gettingStarted, examples, user })
    
    // TODO: Implement this
    const [ resource, id ] = pathSegments
    const data = { resource, id, hello: user.city }
    
    return json({ api, data, user })
  }
}

const json = obj => new Response(JSON.stringify(obj, null, 2), { headers: { 'content-type': 'application/json; charset=utf-8' }})
