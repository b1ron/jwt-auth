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
            cookies.set(cookie.split('=')[0], cookie.split('=')[1], { path: '/' });
            if (cookie.startsWith('refreshToken')) {
                token = cookie.split('=')[1];
            };
        });
    });
};

let claims;

const resource = async function() {
    await fetch('http://localhost:8000/resource', {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + token,
        },
    }).then(resp => resp.json()).then(data => { claims = data; });
};

let expire;

// FIXME: this is not working as expected
try {
    expire = async function() {
        // sleep for 10 seconds to allow the token to expire
        await new Promise(resolve => setTimeout(resolve, 1000 * 10));
        await fetch('http://localhost:8000/resource', {
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + token,
            },
        })
    };
    if (expire.ok) {
        console.log('Promise resolved and HTTP status is successful');
    } else {
        if (expire.status === 401) throw new Error('401, unauthorized');
    }
} catch (error) {
    console.error('Fetch', error);
};

login().then(function() {
    resource().then(function() {
        console.log(cookies.getAll());
        console.log(claims); // { iat: 1728418200, name: 'John Doe' }
    }).then(function() {
        expire() // 401, unauthorized
    });
});
