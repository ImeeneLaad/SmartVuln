import express from 'express'
import cookieParser from 'cookie-parser'

import { health } from './routes/health.js'
import { listProducts, searchProducts } from './routes/products.js'
import { searchPage } from './routes/search.js'
import { login, profile } from './routes/auth.js'
import { download } from './routes/files.js'
import { go } from './routes/redirect.js'
import { lookup } from './routes/tools.js'

const app = express()
const PORT = Number(process.env.PORT || 3000)

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

app.use((err, req, res, next) => {
  res.status(500).type('text/plain').send(`Internal error: ${err.code || ''} ${err.message}\n\n${err.stack}`)
})

app.listen(PORT, () => console.log(`LabShop listening on port ${PORT}`))
