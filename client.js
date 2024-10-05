// a simple JavaScript client to test the endpoints

let formData = new FormData();
formData.append('username', 'John Doe');

let token = '';

const login = fetch('http://localhost:8000/login', {
    method: 'POST',
    credentials: 'include',
    body: formData,
}).then(function(resp) {
    resp.headers.getSetCookie().forEach(function(cookie) {
        if (cookie.startsWith('refreshToken')) {
            token = cookie.split('=')[1];
            return;
        };
    });
});


const resource = fetch('http://localhost:8000/resource', {
    method: 'GET',
    headers: {
        'Authorization': 'Bearer ' + token,
    },
}).then(function(resp) {
    return resp.text();
});

(async () => {
    await login;
    console.log(token);
  })();
