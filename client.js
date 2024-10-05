// a simple JavaScript client to test the endpoints

let formData = new FormData();
formData.append('username', 'John Doe');

let token = '';

fetch('http://localhost:8000/login', {
    method: 'POST',
    body: formData,
}).then(function(resp) {
    resp.headers.forEach(function(val, key) { console.log(key + ' -> ' + val); });
});
