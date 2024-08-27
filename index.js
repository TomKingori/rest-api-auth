const express = require("express");
const swaggerjsdoc = require("swagger-jsdoc");
const swaggerui = require("swagger-ui-express");
const registerroutes = require("./routes/register")

const app = express();

app.use(express.json());

const PORT = 3000;

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Rest API Auth",
      version: "1.0",
      description: "A simple Express Auth API",
    },
    servers: [
      {
        url: "http://localhost:3000",
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
    },
  },
  apis: ["./routes/*.js"],
};

app.get("/", (req, res) => {
  res.send("REST API Auth");
});

const specs = swaggerjsdoc(options);
app.use("/api-docs", swaggerui.serve, swaggerui.setup(specs));

app.use("/", registerroutes);

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
