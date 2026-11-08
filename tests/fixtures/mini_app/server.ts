import { searchProducts } from './routes/search'
import * as login from './routes/login'
const app = express()
app.get('/rest/products/search', searchProducts())
app.post('/rest/user/login', login.login())
app.use('/ftp', serveIndex('ftp'))
