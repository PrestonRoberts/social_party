// check if the form data is not empty
function checkFormData (data) {
    for (let i = 0; i < data.length; i++) {
      if (data[i].replace(/\s/g, '') === '') {
        return false;
      }
    }
    return true;
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isValidUsername(username) {
    // Check length
    if (username.length < 3 || username.length > 16) {
      return false;
    }
  
    // Check for non-alphanumeric characters
    const usernameRegex = /^[a-zA-Z0-9]+$/;
    if (!usernameRegex.test(username)) {
      return false;
    }
  
    return true;
}

function isStrongPassword(password) {
    // Check length
    if (password.length < 8) {
      return false;
    }
  
    // Check for lowercase letters
    const lowercaseRegex = /[a-z]/;
    if (!lowercaseRegex.test(password)) {
      return false;
    }
  
    // Check for uppercase letters
    const uppercaseRegex = /[A-Z]/;
    if (!uppercaseRegex.test(password)) {
      return false;
    }
  
    // Check for digits
    const digitRegex = /[0-9]/;
    if (!digitRegex.test(password)) {
      return false;
    }
  
    // Check for special characters
    const specialCharRegex = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/;
    if (!specialCharRegex.test(password)) {
      return false;
    }
  
    return true;
}

function register() {
    // reset error message
    document.getElementById("account-msg").textContent = ""

    // get form data
    const email = document.getElementById("register_email").value;
    const username = document.getElementById("register_username").value;
    const password = document.getElementById("register_password").value;

    // check if there are entries for each input
    if(!checkFormData([email, username, password])) {
        document.getElementById("account-msg").textContent = "one or more fields is missing for register form."
        return;
    }

    // check if email is valid
    if (!isValidEmail(email)) {
        document.getElementById("account-msg").textContent = "register email is not valid"
        return;
    }

    // check if valid username
    if (!isValidUsername(username)) {
        document.getElementById("account-msg").textContent = "register username is not valid, must be between 3 and 16 characters and have no special characters."
        return;
    }

    // check if password is strong enough
    if (!isStrongPassword(password)) {
        document.getElementById("account-msg").textContent = `register password is not strong enough, must be 8 or more characters, 
                                                            have at least 1 lowercase character, have at least 1 uppercase character, 
                                                            have at least 1 number, and have at least one special character.`
        return;
    }

    // send request to server to register user
    fetch("http://localhost:3000/register", {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            email: email,
            username: username,
            password: password
        })
    }).then(response => {
        return response.json();
    }).then(data => {
        console.log(data);

        document.getElementById("account-msg").textContent = data.message

        // could not register
        if (!data.success) {
            return
        }

        // register success
        localStorage.setItem("userToken", data.token);
    })
}

function login() {
    const username = document.getElementById("login_username").value;
    const password = document.getElementById("login_password").value;

    console.log(username);
    console.log(password);

    if(!checkFormData([username, password])) {
        document.getElementById("account-msg").textContent = "one or more fields is missing for register form."
        return;
    }

    // todo send request to server to login
    fetch("http://localhost:3000/login", {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({
            username: username,
            password: password
        })
    }).then(response => {
        return response.json();
    }).then(data => {
        console.log(data);

        document.getElementById("account-msg").textContent = data.message

        // could not login
        if (!data.success) {
            return
        }

        // login success
        localStorage.setItem("userToken", data.token);
    })
}

// todo logout function
function logout() {

}

// todo delete account function 
function deleteAccount() {

}