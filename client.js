// a simple JavaScript client to test the endpoints

let formData = new FormData();
formData.append('username', 'John Doe');

let token = '';

const login = fetch('http://localhost:8000/login', {
    method: 'POST',
    body: formData,
}).then(function(resp) {
    resp.headers.forEach(function(val, key) { 
        if (key === 'authorization') {
            token = val;
            return token;
        };
    });
});

(async () => {
    await login;
    console.log(token);
  })();
