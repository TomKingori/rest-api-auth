const express = require("express");
const swaggerjsdoc = require("swagger-jsdoc");
const swaggerui = require("swagger-ui-express");

const app = express();

app.use(express.json());

const PORT = 3000;

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Rest API Auth",
      version: "1.0",
      description:
        "REST API authentication and authorization with Node.js, using JSON Web Tokens (JWT), Refresh Tokens and Two-Factor Authentication (2FA)",
    },
    servers: [
      {
        url: "http://localhost:3000",
      },
    ],
  },
  apis: ["*./"],
};

app.get("/", (req, res) => {
  res.send("REST API Auth");
});

const specs = swaggerjsdoc(options);
app.use("/api-docs", swaggerui.serve, swaggerui.setup(specs));
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
