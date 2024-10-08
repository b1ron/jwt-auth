// a simple JavaScript client to test the endpoints

import Cookies from 'universal-cookie';
const cookies = new Cookies();

let formData = new FormData();
formData.set('username', 'John Doe');
formData.set('password', 'password');

let token = '';

const login = async function() {
    await fetch('http://localhost:8000/login', {
        method: 'POST',
        credentials: 'include',
        contentType: 'application/x-www-form-urlencoded',
        body: formData,
    }).then(function(resp) {
        resp.headers.get('Set-Cookie').split(';').forEach(function(cookie) {
            if (cookie.startsWith('refreshToken')) {
                token = cookie.split('=')[1];
                return;
            };
        });
    });
}

const resource = async function() {
    await fetch('http://localhost:8000/resource', {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + token,
        },
    }).then(function(resp) {
        console.log(resp.status, resp.statusText);
        console.log(resp.headers.get('Content-Type'));
        console.log(cookies.getAll()); // FIXME: cookies.getAll() returns empty object
        return resp.body;
    });
};

login().then(function() {
    resource().then(function(data) {
        console.log(token, data); // FIXME: data is undefined
    });
})
