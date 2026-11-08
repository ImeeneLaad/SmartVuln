async function loadProducts () {
  const list = document.getElementById('products')
  const res = await fetch('/api/products')
  const products = await res.json()
  list.innerHTML = products
    .map((p) => `<li>${p.name} <span>${p.price.toFixed(2)} €</span><small>${p.description}</small></li>`)
    .join('')
}

loadProducts()
