const Product = require("../models/product");

exports.getAddProduct = (req, res, next) => {
  if (!req.session.isLoggedIn) {
    return res.redirect("/login");
  }
  res.render("admin/edit-product", {
    pageTitle: "Add Product",
    path: "/admin/add-product",
    editing: false,
  });
};

exports.postAddProduct = (req, res, next) => {
  const title = req.body.title;
  const imageUrl = req.body.imageUrl;
  const price = req.body.price;
  const description = req.body.description;
  const product = new Product({
    title: title,
    price: price,
    description: description,
    imageUrl: imageUrl,
    // userId: req.user._id // You can get the ._id directly or:
    userId: req.user, // You can use the object directly and mongoose will get the ._id for you
  });

  product
    .save() // This will be provided by mongoose
    .then((result) => {
      // Technically we don't get a promise but mongoose still gives us a then method
      console.log(`Created Product: ${title} with id: ${result._id}`);
      res.redirect("/admin/products");
    })
    .catch((err) => {
      // And mongoose also gives us a catch method we can call
      console.log(err);
    });
};

exports.getEditProduct = (req, res, next) => {
  // We are already coming from a 'edit-product' route but this was added just to show
  // how to retrieve data from a query param:
  const editMode = req.query.edit;
  if (!editMode) {
    return res.redirect("/");
  }
  const prodId = req.params.productId;
  Product.findById(prodId)
    .then((product) => {
      // If we don't have a product and it's undefined:
      if (!product) {
        // We could retrieve a error page (better user experience) but for now we will just redirect:
        return res.redirect("/");
      }
      res.render("admin/edit-product", {
        pageTitle: "Edit Product",
        path: "/admin/edit-product",
        editing: editMode,
        product: product,
      });
    })
    .catch((err) => console.log(err));
};

exports.postEditProduct = (req, res, next) => {
  // Fetch information from the product
  const prodId = req.body.productId;
  const updatedTitle = req.body.title;
  const updatedPrice = req.body.price;
  const updatedImageUrl = req.body.imageUrl;
  const updatedDesc = req.body.description;

  Product.findById(prodId) // findById() returns a mongoose object where we can call .save()
    .then((product) => {
      if (product.userId.toString() !== req.user._id.toString()) {
        return res.redirect("/");
      }
      product.title = updatedTitle;
      product.price = updatedPrice;
      product.description = updatedDesc;
      product.imageUrl = updatedImageUrl;
      return product
        .save() // if we use the save() here it will not create a new one instead it will update behind the scenes
        .then(() => {
          console.log("UPDATED PRODUCT!");
          res.redirect("/admin/products");
        })
        .catch((err) => console.log(err));
    })
    .catch((err) => console.log(err));
};

exports.getProducts = (req, res, next) => {
  Product.find({ userId: req.user._id })
    // .select("title price -_id") // only the title and price, and explicit excluding the _id
    // .populate("userId", "name") // only the field "name" (the field _id will also be populated)
    .then((products) => {
      res.render("admin/products", {
        prods: products,
        pageTitle: "Admin Products",
        path: "/admin/products",
      });
    })
    .catch((err) => console.log(err));
};

exports.postDeleteProduct = (req, res, next) => {
  // Fetch information from the product
  const prodId = req.body.productId;
  // It's not removing from every cart yet !
  Product.deleteOne({ _id: prodId, userId: req.user._id })
    .then((result) => {
      if (result.deletedCount > 0) {
        console.log("Deleted product and removed it from every cart !"); // It's not removing from every cart yet !
      }
      res.redirect("/admin/products");
    })
    .catch((err) => console.log(err));
};
