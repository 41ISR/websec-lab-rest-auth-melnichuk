const express = require('express')
const db = require('./db')
const jwt = require('jsonwebtoken')
const bcr = require('bcryptjs')

const app = express()
const SECRET = process.env.SECRET || 'oemchng'

const auth = (req, res, next) => {
    const authHeader = req.headers.authorization
    if(!authHeader) return res.status(401).json({error: "No token given"})
    if(!(authHeader.split(" "[1]))) return res.status(401).json({error: "Invalid token format"})
    
    try {
        const token = authHeader.split(" ")[1]
        const decoded = jwt.verify(token, SECRET)
        req.user = decoded
        next()
    } catch (error) {
        console.error(error);
        return res.status(500).json({error: "Token error occured"})
    }
}

app.use(express.json())

// --------------

app.post('/api/auth/register', (req, res) => {
    try {
        const {username, email, password} = req.body
        if (!email || !username || !password) return req.status(400).json({error: "Not all necessery data provided"})
        let role = "user"

        const check = db.prepare(`
            SELECT username, email FROM users WHERE username = ? OR email = ?`).get(username, email)
        if(check) return res.status(401).json({error: "User with this data is already created"})

        const syntSalt = bcr.genSaltSync(10)
        const hash = bcr.hashSync(password, syntSalt)

        const query = db.prepare(`INSERT INTO users (username, email, password, role) VALUES (?,?,?,?)`)
        const info = query.run(username, email, hash, role)
        
        const newUser = db.prepare(`SELECT * FROM users WHERE id = ?`).get(info.lastInsertRowid)
        const {password: b, ...resp} = newUser

        return res.status(200).json({"message": "User created successfully","user": resp})
    } catch (err) {
        console.error(err);
        return res.status(401).json({"error": "Unexpected error occured"})
    }
})
app.post('/api/auth/login', (req, res) => {
    try {
        const {username, password} = req.body
        if (!username || !password) return res.status(400).json({error: "Not all necessary data provided"})
        
        const user = db.prepare(`SELECT * FROM users WHERE username = ?`).get(username)
        if(!user) return res.status(401).json({error: "Invalid data. Try again"})

        const valid = bcr.compareSync(password, user.password)
        if(!valid) return res.status(401).json({error: "Invalid data. Try again"})

        const token = jwt.sign({...user}, SECRET, {expiresIn: '24h'})
        const {password: b, ...resp} = user

        return res.status(200).json({"token": token, "user": resp})
    } catch (err) {
        console.error(err);
        return res.status(401).json({error: "Unexpected error occured"})
    }
})
app.get('/api/auth/profile', auth, (req, res) => {
    const {password, exp, iat, ...resp} = req.user

    return res.status(200).json({...resp})
})

// ------------

app.get('/api/books', (req, res) => {
    let query = "SELECT * FROM books "
    let param
    
    if(req.query.genre && req.query.genre !== "") {query += "WHERE genre = ?"; param = req.query.genre;}
    else if(req.query.author && req.query.author !== "") {query += "WHERE author = ?"; param = req.query.author;}

    let data
    if(param){data = db.prepare(query).all(param)}
    else{data = db.prepare(query).all()}

    return res.status(200).json(data)
})
app.get('/api/books/:id', (req, res) => {
    try {
        const {id} = req.params
        const query = db.prepare(`
            SELECT * FROM books WHERE books.id = ?
            `)
        const result = query.get(id)
        if(!result) return res.status(404).json({error: "Book not found"})

        const revs = db.prepare(`
            SELECT id, userId, rating, comment FROM reviews WHERE bookId = ?`).all(id)
        
        return res.status(200).json({...result, "reviews": revs})
    } catch (err) {
        console.error(err);
        return res.status(401).json({error: "Unexpected error occured"})
    }
})
app.post('/api/books', auth, (req, res) => {
    try {
        const {title, author, year, genre} = req.body
        if(!title || !author || !year || !genre) return res.status(401).json({error: "Not all necessary data provided"})
        let description = ""

        if(!req.body.description) {description = ""}
        else {description = req.body.description}
        
        const query = db.prepare(`
            INSERT INTO books (title, author, year, genre, createdBy, description) VALUES (?, ?, ?, ?, ?, ?)
            `)
        const info = query.run(title, author, year, genre, req.user.id, description)

        const newBook = db.prepare(`
            SELECT * FROM books WHERE id = ?
            `).get(info.lastInsertRowid)

        return res.status(201).json({"message": "Book created successfully", book: newBook})
    } catch (err) {
        console.error(err);
        return res.status(401).json({error: "An unexpected error occured"})
    }
})
app.put('/api/books/:id', auth, (req, res) => {
    try {
        const {id} = req.params
        const book = db.prepare(`
            SELECT * FROM books WHERE id = ?`).get(id)
        if(!book) return res.status(404).json({error: "Book not found"})
        if(req.user.role !== "admin" && book.createdBy !== req.user.id) return res.status(403).json({error: "Not allowed"})
        
        let columns = []
        let vars = []
        if(req.body.title){columns.push('title = ?'); vars.push(req.body.title)}
        if(req.body.author){columns.push('author = ?'); vars.push(req.body.author)}
        if(req.body.year){columns.push('year = ?'); vars.push(req.body.year)}
        if(req.body.genre){columns.push('genre = ?'); vars.push(req.body.genre)}
        if(req.body.description){columns.push('description = ?'); vars.push(req.body.description)}

        const query = db.prepare(`
            UPDATE books SET `+columns.join(', ')+` WHERE id = ?`)

        const result = query.run(vars.map((el) => el), id)

        const updBook = db.prepare(`
            SELECT * FROM books WHERE id = ?`).get(id)
        return res.status(200).json({message: "Book updated successfully!", book: updBook})
    } catch (err) {
        console.error(err);
        return res.status(401).json({error: "Unexpected error occured"})
    }
})
app.delete('/api/books/:id', auth, (req, res) => {
    try {
        const {id} = req.params
        const book = db.prepare(`
            SELECT * FROM books WHERE id = ?`).get(id)
        if(!book) return res.status(404).json({error: "Book not found"})
        if(req.user.role !== "admin" && req.user.id !== book.createdBy) return res.status(403).json({error: "Not allowed"})
        
        const result = db.prepare(`
            DELETE FROM books WHERE id = ?`).run(id)
        return res.status(200).json({message: "Book deleted successfully :)"})
    } catch (err) {
        console.error(err);
        return res.status(401).json({error: "Unexpected error occured"})
    }
})

// ---------------

app.post('/api/books/:id/reviews', auth, (req, res) => {
    try {
        const {id} = req.params
        const check = db.prepare(`
            SELECT * FROM books WHERE id = ?`).get(id)
        if(!check) return res.status(404).json({error: "Book not found"})

        const {rating, comment} = req.body
        if(!comment) comment = ""
        if(rating > 5 || rating < 1 || !/^\d+$/.test(rating)) return res.status(403).json({error: "Incorrect data"})
        
        const query = db.prepare(`
            INSERT INTO reviews (bookId, userId, rating, comment) VALUES (?,?,?,?)`)
        const info = query.run(id, req.user.id, rating, comment)
        const newRev = db.prepare(`
            SELECT * FROM reviews WHERE id = ?`).get(info.lastInsertRowid)
        
        return res.status(201).json({message: "Review added successfully", review: newRev})
    } catch (err) {
        console.error(err);
        return res.status(401).json({error: "Unexpected error occured"})
    }
})
app.get('/api/books/:id/reviews', (req, res) => {
    try {
        const {id} = req.params
        const check = db.prepare(`
            SELECT * FROM books WHERE id = ?`).get(id)
        if(!check) return res.status(404).json({error: "Book not found"})

        const data = db.prepare(`
            SELECT * FROM reviews WHERE bookId = ?`).all(id)
        return res.status(200).json(data)
    } catch (err) {
        console.error(err);
        return res.status(401).json({error: "Unexpected error occured"})
    }
})
app.delete('/api/reviews/:id', auth, (req, res) => {
    try {
        const {id} = req.params
        const rev = db.prepare(`
            SELECT * FROM reviews WHERE id = ?`).get(id)
        if(!rev) return res.status(404).json({error: "Review not found"})
            console.log(req.user.role,rev.userId, req.user.id);    
        if(req.user.role !== "admin" && rev.userId != req.user.id) return res.status(403).json({error: "Not allowed"})

        const result = db.prepare(`
            DELETE FROM reviews WHERE id = ?`).run(id)
        return res.status(200).json({message: "Review deleted successfully"})
    } catch (err) {
        console.error(err);
        return res.status(401).json({error: "Unexpected error occured"})
    }
})

// ----------

app.get('/api/admin/users', auth, (req, res) => {
    try {
        if(req.user.role !== "admin") return res.status(403).json({error: "Not allowed"})

        const data = db.prepare(`
            SELECT * FROM users`).all()
        
        return res.status(200).json(data)
    } catch (err) {
        console.error(err);
        return res.status(401).json({error: "Unexpected error occured"})
    }
})
app.put("/api/admin/users/:id", auth, (req, res) => {
    try {
        if(req.user.role !== "admin") return res.status(403).json({error: "Not allowed"})
        
        const {role} = req.body
        const {id} = req.params

        const check = db.prepare(`
            SELECT * FROM users WHERE id = ?`).get(id)
        if(!check) return res.status(404).json({error: "User not found"})
        
        const result = db.prepare(`
            UPDATE users SET role = ? WHERE id = ?`).run(role, id)
        return res.status(200).json({message: "User's role updated successfully"})
    } catch (err) {
        console.error(err);
        return res.status(401).json({error: "Unexpected error occured"})
    }
})
app.delete('/api/admin/users/:id', auth, (req, res) => {
    try {
        if(req.user.role !== "admin") return res.status(403).json({error: "Not allowed"})
        const {id} = req.params
        const check = db.prepare(`
            SELECT * FROM users WHERE id = ?`).get(id)
        if(!check) return res.status(404).json({error: "User not found"})
        
        const result = db.prepare(`
            DELETE FROM users WHERE id = ?`).run(id)
        return res.status(200).json({message: "User deleted successfully"})
    } catch (err) {
        console.error(err);
        return res.status(401).json({error: "Unexpected error occured"})
    }
})

// ----------

app.listen('3000', () => {
    console.log("Server is running on port 3000");
})