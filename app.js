require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// CONFIG JSON 
app.use(express.json())

// IMPORTANDO MODEL P/ USO
const User = require('./models/User')

// INICIO - ROTA PUBLICA P/ USUARIOS
app.get('/', (req,res) => {
    res.status(200).json({msg: 'Conectado'})
})

// ROTAS PRIVADA

app.get('/user/:id', checkToken, async (req,res) => {
    const id = req.params.id

    // CHECHANDO NO BANCO SE O USUARIO EXISTE 

    const user = await User.findById(id, '-password')

    if(!user) {
        return res.status(404).json({msg: 'Usuario não encontrado!'})
    }

    res.status(200).json({user})
})

function checkToken (req, res, next) {

    const autHeader = req.headers['authorization']
    const token = autHeader && autHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({msg: 'ERRO!'})
    }

    try {

        const secret = process.env.SECRET

        jwt.verify(token, secret)
        next()
        
    } catch (error) {
        res.status(400).json({msg: 'Token invalido!'})
    }


}

// ROTA P/ REGISTRO DE USUARIOS

app.post('/auth/register', async (req,res) => {

    const {name, email, password, confirmpassword} = req.body

    // VALIDAÇÃO DE DADOS
    if(!name) {
        return res.status(422).json({msg: 'Nome obrigatorio!'})
    }
    if(!email) {
        return res.status(422).json({msg: 'E-mail obrigatorio!'})
    }
    if(!password) {
        return res.status(422).json({msg: 'Senha obrigatoria!'})
    }

    if(password !== confirmpassword) {
        return res.status(422).json({msg: 'Senhas diferentes!'})
    }

    // CHECANDO SE O USUARIO JA POSSUIO CADASTRO

    const userExist = await User.findOne({email: email})

    if(userExist) {
        return res.status(422).json({msg: 'E-mail já cadastrado!'})
    }

    // CRIANDO SENHA

    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)


    // CRIANDO USUARIO 

    const user = new User ({
        name,
        email,
        password: passwordHash
    })

    try {

        await user.save()
        res.status(201).json({msg: 'Cadastro realizado com sucesso!'})
        
    } catch (error) {
        console.log(error)
        res.status(500).json({msg: 'Erro servidor!'})

    }

})

// ROTAS P/ LOGIN 

app.post('/auth/login', async (req,res) => {

    const{email,password} = req.body

    if(!email) {
        return res.status(422).json({msg: 'E-mail obrigatorio!'})
    }
    if(!password) {
        return res.status(422).json({msg: 'Senha obrigatoria!'})
    }

// CHECANDO USUARIOS JÁ CADASTRADOS

const user = await User.findOne({email: email})

    if(!user) {
        return res.status(404).json({msg: 'Usuario não encontrado!'})
    }

// CHECANDO SENHAS

const checkpassword = await bcrypt.compare(password, user.password)

if(!checkpassword) {
    return res.status(404).json({msg: 'Senha invalida!'})
}


try {

    const secret = process.env.secret
    const token = jwt.sign({
        id: user._id
    }, secret)

    res.status(200).json({msg: 'Autenticação feita com sucesso!', token})
    
} catch (error) {
    console.log(error)
    res.status(500).json({msg: 'Erro servidor!'})
}

})



// CREDENCIAIS P/ CONEXÃO MONGODB

const dbuser = process.env.DB_USER
const dbpass = process.env.DB_PASS



mongoose.connect(`mongodb+srv://${dbuser}:${dbpass}@next-js.wcva0pz.mongodb.net/DBJWT?retryWrites=true&w=majority`)
    .then(() => {
        console.log('Conectado ao MongoDB')
    })
    .catch((err) => console.log(err))

app.listen(3000)