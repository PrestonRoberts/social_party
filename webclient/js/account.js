// check if the form data is not empty
function checkFormData (data) {
    data.forEach(element => {
        if (element.value === '') {
            return false;
        }
    });

    return true;
}

function register() {
    const email = document.getElementById("register_email").value;
    const username = document.getElementById("register_username").value;
    const password = document.getElementById("register_password").value;

    console.log(email);
    console.log(username);
    console.log(password);

    if(!checkFormData([email, username, password])) {
        // todo missing field values
    }

    // todo check if valid email

    // todo check if valid username

    // todo check if valid password

    // todo send request to server to register user
    // fetch("http://localhost:3000/register", {
    //     method: 'POST',
    //     headers: {
    //         'Accept': 'application/json',
    //         'Content-Type': 'application/json',
    //     },
    //     body: JSON.stringify({
    //         email: email,
    //         username: username,
    //         password: password
    //     })
    // }).then(response => {
    //     response.json();
    //     console.log(response);
    // })

    // todo display error message

    // todo display success message and set user token
}

function login() {
    const username = document.getElementById("login_username").value;
    const password = document.getElementById("login_password").value;

    console.log(username);
    console.log(password);

    if(!checkFormData([username, password])) {
        // todo missing field values
    }

    // todo send request to server to login
    // fetch("http://localhost:3000/login", {
    //     method: 'POST',
    //     headers: {
    //         'Accept': 'application/json',
    //         'Content-Type': 'application/json',
    //         'Access-Control-Allow-Origin': '*'
    //     },
    //     body: JSON.stringify({
    //         username: username,
    //         password: password
    //     })
    // }).then(response => {
    //     response.json();
    //     console.log(response);
    // })

    // todo display error message

    // todo display success message and set user token
}

// todo logout function
function logout() {

}

// todo delete account function 
function deleteAccount() {

}