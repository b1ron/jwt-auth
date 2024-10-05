// a simple JavaScript client to test the endpoints

let formData = new FormData();
formData.append('username', 'John Doe');

let token = '';

fetch('http://localhost:8000/login', {
    method: 'POST',
    body: formData,
})
.then(response => 
    response.clone().json().catch(() => response.text())
).then(data => {
   // data is now parsed JSON or raw text
    token = data;
    console.log(token);
 });
