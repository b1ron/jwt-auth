// a simple JavaScript client to test the endpoints

let formData = new FormData();
formData.append('username', 'John Doe');

let token = '';

const login = async function() {
    await fetch('http://localhost:8000/login', {
        method: 'POST',
        credentials: 'include',
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
        // FIXME: 401 Unauthorized
        console.log(resp.status, resp.statusText);
        return resp.text();
    });
};

login().then(function() {
    resource().then(function(data) {
        console.log(token, data);
    });
})
