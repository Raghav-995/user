const express = require("express");
const dotenv = require('dotenv');
const { env } = require("process");
const authRoutes = require("./routes/authRoutes");
const userRoutes = require("./routes/userRoutes")
const path = require('path');
const cors = require('cors');

dotenv.config();

const app = express();

app.use('/uploads', express.static(path.join(__dirname,'controllers', 'uploads')));

app.use(cors());

app.use(express.json());

app.use('/api/auth', authRoutes);

app.use('/', userRoutes);


app.set('view engine', 'ejs');

const filePath = path.resolve(__dirname, 'index.html');

const data = {
    port: process.env.PORT,
}

app.get('/home', (req,res) => {
        // res.send("<center><h2>Server is running successfully!</h2></center>");
        res.render('pages/index', data);
});

app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
})