const express = require('express')
const app = express()
app.use(express.static('public'))
app.listen(4000)
const app2 = express()
app2.use(express.static('public2'))
app2.listen(4001)