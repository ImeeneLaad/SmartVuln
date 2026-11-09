import express from 'express'
import cookieParser from 'cookie-parser'
import helmet from 'helmet'

import { health } from './routes/health.js'
import { listProducts, searchProducts } from './routes/products.js'
import { searchPage } from './routes/search.js'
import { login, profile } from './routes/auth.js'
import { download } from './routes/files.js'
import { go } from './routes/redirect.js'
import { lookup } from './routes/tools.js'

const app = express()
const PORT = Number(process.env.PORT || 3000)

// Don't advertise the framework, and send security headers on every response.
app.disable('x-powered-by')
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,  // explicit, strict policy: only this site's own resources
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'"],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}))
app.use(express.urlencoded({ extended: false }))
app.use(express.json())
app.use(cookieParser())
app.use(express.static('public'))

app.get('/health', health)
app.get('/api/products', listProducts)
app.get('/api/products/search', searchProducts)
app.get('/search', searchPage)
app.post('/login', login)
app.get('/profile', profile)
app.get('/download', download)
app.get('/go', go)
app.get('/api/tools/lookup', lookup)

// Own 404 page, so responses keep the CSP set by helmet (Express's built-in 404 replaces it).
app.use((req, res) => {
  res.status(404).type('text/plain').send('Not found')
})

// Log the details on the server; never send stack traces or internal errors to visitors.
app.use((err, req, res, next) => {
  console.error(err)
  res.status(500).type('text/plain').send('Something went wrong.')
})

app.listen(PORT, () => console.log(`LabShop listening on port ${PORT}`))
