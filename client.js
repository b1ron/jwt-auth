// a simple JavaScript client to test the endpoints

fetch('http://localhost:8000/login', {
    method: 'POST',
    body: JSON.stringify({ "username": "John Doe" })
})
   .then(response => response.json())
   .then(response => console.log(JSON.stringify(response)))
