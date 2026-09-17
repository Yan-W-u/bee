const http = require('http')
const fs = require('fs')
const path = require('path')

const PORT = 8080
const DIST_DIR = path.join(__dirname, 'frontend', 'dist')

const mimeTypes = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
}

function getMime(filePath) {
  const ext = path.extname(filePath).toLowerCase()
  return mimeTypes[ext] || 'application/octet-stream'
}

const spaRoutes = [
  '/login', '/dashboard', '/flows', '/vulns', '/remediation',
  '/swarm', '/providers', '/settings', '/chat', '/oauth',
  '/templates', '/resources', '/knowledges',
]

function isSpaRoute(urlPath) {
  if (urlPath === '/') return true
  for (const prefix of spaRoutes) {
    if (urlPath === prefix || urlPath.startsWith(prefix + '/')) {
      return true
    }
  }
  return false
}

function serveFile(res, filePath) {
  try {
    const content = fs.readFileSync(filePath)
    res.writeHead(200, { 'Content-Type': getMime(filePath) })
    res.end(content)
  } catch {
    res.writeHead(200, { 'Content-Type': 'text/html' })
    res.end(fs.readFileSync(path.join(DIST_DIR, 'index.html')))
  }
}

const server = http.createServer((req, res) => {
  const urlPath = new URL(req.url, `http://localhost:${PORT}`).pathname

  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  res.setHeader('Access-Control-Allow-Credentials', 'true')

  if (req.method === 'OPTIONS') {
    res.writeHead(204)
    res.end()
    return
  }

  if (urlPath.startsWith('/api/')) {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ status: 'success', data: {} }))
    return
  }

  if (urlPath === '/graphql') {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ data: {} }))
    return
  }

  if (isSpaRoute(urlPath)) {
    res.writeHead(200, { 'Content-Type': 'text/html' })
    res.end(fs.readFileSync(path.join(DIST_DIR, 'index.html')))
    return
  }

  const filePath = path.join(DIST_DIR, urlPath)
  serveFile(res, filePath)
})

server.listen(PORT, () => {
  console.log('')
  console.log('PentAGI is running!')
  console.log('Open http://localhost:' + PORT)
  console.log('')
})
