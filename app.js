
//IMPORTACOES
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

//CRIANDO APP COM EXPRESS;
const app = express();
//CHAMDANDO A TABELA USERS DO BANCO DE DADOS - MONGODB
const User = require('./models/User');
//DEFININDO PARA O APP ACEITAR JSON
app.use(express.json());

app.get("/", (req , res)=>{ // ROTA DE BOAS VINDAS
    res.status(200).json({msg: 'BEM VINDO A API - YAN'})
})

app.post("/auth/register", async(req, res)=>{ // ROTA PARA CRIACAO DE USUARIO
    const {name, email, password, confirm_password } = req.body;
    if(!name){
        return res.status(422).json({msg: "Preencha seu nome de usuario! (name) : (SEU NOME) -> entre aspas"})
    }
    if(!email){
        return res.status(422).json({msg: "Preencha seu email! (email) : (SEU EMAIL) -> entre aspas"})
    }
    if(!password){
        return res.status(422).json({msg: "Preencha sua senha!  (password) : (SUA SENHA) -> entre aspas"})
    }
    if(!confirm_password){
        return res.status(422).json({msg: "Preencha sua confirmacao de senha! (confirm_password) : (CONFIRMACAO DE SENHA) -> entre aspas"})
    }
    if(password !== confirm_password){
        return res.status(422).json({msg: "As senhas nao conferem! digite a confirmacao igual a primeira senha!"})
    }

    const usuario_existe = await User.findOne({ email: email }); //verificacao se ja existe no banco
    if(usuario_existe){
        return res.status(422).json({msg: "ESTE EMAIL JA ESTA CADASTRADO EM NOSSO BANCO DE DADOS!"})
    }


    //CRIACAO DA CRIPTOGRAFIA DA SENHA PARA O BANCO DE DADOS
    const add_hash = await bcrypt.genSalt(15); //adicionando mais 15 caracteres a senha 
    const hash_pass = await bcrypt.hash(password, add_hash);

    const user = new User({ //ADICIONANDO USUARIO AO BANCO MONGO-DB
        name,
        email, 
        password: hash_pass, //ADICIONANDO A SENHA CRIPTOGRAFADA AO BANCO, AS OUTRAS VARIAVEIS NAO PRECISAM POIS SEU NOME E IGUAL AS DA CONST {}
    })

    try{
        await user.save();
        res.status(201).json({
            msg: "Usuario criado com sucesso! :)"
        })

    }catch(err){
        res.status(500).json({
            msg: "Aconteceu um erro interno, tente mais tarde, lamentamos o ocorrido! :(",
        })
    }
});


app.post("/auth/login/", async (req , res) =>{
    const { email, password } = req.body;
    if(!email){
        return res.status(422).json({msg: "Preencha seu email! (email) : (SEU EMAIL) -> entre aspas"})
    }
    if(!password){
        return res.status(422).json({msg: "Preencha sua senha!  (password) : (SUA SENHA) -> entre aspas"})
    }

    const user = await User.findOne({email: email});
    
    if(!user){
        return res.status(404).json({msg: "Usuario nao foi encontrado no banco de dados!"})
    }

    const verify_password = await bcrypt.compare(password, user.password);

    if(!verify_password){
        return res.status(422).json({msg: "A senha digitada nao esta correta!"})
    }

    try{
        const SECRET = process.env.SECRET;
        const token = jwt.sign({
            id: user._id,
            email: email
        }, SECRET, );

        res.status(200).json({msg: "O usuario foi authenticado com sucesso!", token})
    }catch(err){
        console.log(err);
    }

});


//ROTA PRIVADA DA API
app.get("/user/:id", check_token, async (req, res) =>{ // URL DINAMICA COM GET + FUNCAO PARA VER SE O TOKEN CHEGOU PELO HEADER HTTP
    const id = req.params.id;
    const user = await User.findById(id, '-password');//BUNCANDO TODOS ELEMENTO SELECIONANDOS PELO ID DO USUARIO QUE E ENVIADO POR AUTH/LOGIN 

    if(!user){
        return res.status(404).json({ msg: 'O parametro do ID usuario nao confere com o banco de dados!'})
    }
    res.status(200).json({ user });

    
});


//FUNCAO PARA CHECAR SE O TOKEN EXISTE
function check_token(req, res, next){
    const authHeader = req.headers['authorization']; // pegando token do header http
    const token = authHeader && authHeader.split(" ")[1]; //CONFIRMA SE VEIO O TOKEN PELO HEADER E SEPARA INFORMACOES DESNECESSARIAS DELE

    if(!token){
        return res.status(401).json({ msg: "TOKEN INEXISTENTE, VOCE PRECISA LOGAR!"});
    }

    try{

        const SECRET = process.env.SECRET; 
        jwt.verify(token, SECRET); // VERIFICACAO PARA SABER SE O TOKEN REALMENTE E VALIDO PELA API JSON WEB TOKEN
        next(); 
    }catch(err){
        res.status(400).json({
            msg: "Token Invalido!"
        })
    }
}

const DbUser = process.env.DB_USER; //PEGANDO USUARIO DO BANCO DE DADOS DO ARQUIVO .ENV
const DbPass = process.env.DB_PASS; //PEGANDO SENHA DO BANCO DE DADOS DO ARQUIVO .ENV

//CONECTANDO AO BANCO DE DADOS MONGODB - PASSANDO AS VARIVEIS ACIMAS QUE FORAM BUSCADAS DO .ENV
mongoose.connect(`mongodb+srv://${DbUser}:${DbPass}@cluster0.oczcqnk.mongodb.net/?retryWrites=true&w=majority`).then(()=>{
    app.listen(3000);
    console.log("Conectado ao MongoDB!")
}).catch((err) =>{
    console.log(err);
})
