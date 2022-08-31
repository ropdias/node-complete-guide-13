const express = require("express");

const adminController = require("../controllers/admin");
// We can add this middleware before every route that needs protection against a user not logged in:
const isAuth = require("../middleware/is-auth");
// We can add as many as we want in the router.get() function, they are called from left to right

const router = express.Router();

// Middlewares "isAuth" and "adminController.getAddProduct" are called from left to right here
// /admin/add-product => GET
router.get("/add-product", isAuth, adminController.getAddProduct); 

// /admin/products => GET
router.get("/products", isAuth, adminController.getProducts);

// /admin/add-product => POST
router.post("/add-product", isAuth, adminController.postAddProduct);

router.get("/edit-product/:productId", isAuth, adminController.getEditProduct);

// Remember when using post requests you don't need to pass dynamic segment
// and the data can be enclosed in the request body we are sending
router.post("/edit-product", isAuth, adminController.postEditProduct);

router.post("/delete-product", isAuth, adminController.postDeleteProduct);

module.exports = router;
