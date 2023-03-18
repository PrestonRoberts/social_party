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
    document.getElementById("register-err").textContent = " "

    // get form data
    const email = document.getElementById("register_email").value.trim();
    const password = document.getElementById("register_password").value.trim();
    const confirm_password = document.getElementById("register_confirm_password").value.trim();

    // check if there are entries for each input
    if(!checkFormData([email, password, confirm_password])) {
        document.getElementById("register-err").textContent = "one or more fields is missing."
        return;
    }

    // check if email is valid
    if (!isValidEmail(email)) {
        document.getElementById("register-err").textContent = "email is not valid"
        return;
    }

    // check if passwords match
    if(password != confirm_password) {
        document.getElementById("register-err").textContent = "passwords do not match"
        return;
    }

    // check if password is strong enough
    if (!isStrongPassword(password)) {
        document.getElementById("register-err").textContent = `password is not strong enough, must be 8 or more characters, 
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
            password: password
        })
    }).then(response => {
        return response.json();
    }).then(data => {
        // display message on screen
        document.getElementById("register-err").textContent = data.message

        // could not register
        if (!data.success) {
            return
        }

        // register success
        localStorage.setItem("userToken", data.token);
    })
}

function login() {
    // reset error message
    document.getElementById("login-err").textContent = " "

    const email = document.getElementById("login_email").value;
    const password = document.getElementById("login_password").value;

    if(!checkFormData([email, password])) {
        document.getElementById("login-err").textContent = "one or more fields is missing."
        return;
    }

    // send request to server to login
    fetch("http://localhost:3000/login", {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({
            email: email,
            password: password
        })
    }).then(response => {
        return response.json();
    }).then(data => {
        // display message on screen
        document.getElementById("login-err").textContent = data.message

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