import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(cors());
// app.options("*", cors());
app.use(express.json());

const prisma = new PrismaClient();

const port = 3001;

const SECRET = process.env.SECRET!;

function getToken(id: number) {
  return jwt.sign({ id: id }, SECRET, {
    expiresIn: "5 mins",
  });
}

async function getCurrentUser(token: string) {
  const decodedData = jwt.verify(token, SECRET);
  const user = await prisma.user.findUnique({
    // @ts-ignore
    where: { id: decodedData.id },
    include: { transactions: true },
  });
  return user;
}

app.post("/sign-in", async (req, res) => {
  console.log(req.body);

  const match = await prisma.user.findUnique({
    where: {
      // @ts-ignore
      email: req.body.email,
    },
    include: { transactions: true },
  });
  console.log(match);
  if (match && bcrypt.compareSync(req.body.password, match.password)) {
    res.send({ user: match, token: getToken(match.id) });
  } else {
    res.send({ error: "error" });
  }
});

app.post("/sign-up", async (req, res) => {
  try {
    const match = await prisma.user.findUnique({
      where: {
        email: req.body.email,
      },
    });
    if (match) {
      res.send({ message: "Email already in use" });
    } else {
      const newUser = await prisma.user.create({
        data: {
          email: req.body.email,
          password: bcrypt.hashSync(req.body.password),
          //   @ts-ignore
          fullName: req.body.fullName,
        },
      });
      res.send({ newUser: newUser, token: getToken(newUser.id) });
    }
  } catch (error) {
    // @ts-ignore
    res.send({ error: error.message });
  }
});

app.post("/validate", async (req, res) => {
  try {
    if (req.headers.authorization) {
      // @ts-ignore
      const user = getCurrentUser(req.headers.authorization);
      // @ts-ignore
      res.send({ user: user, token: getToken(user.id) });
    }
  } catch (error) {
    res.send({ error: "error" });
  }
});

app.listen(port, () => {
  console.log("Howdy!!");
});
