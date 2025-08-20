function LoginWithToken() {
    $.ajax({
        url: '/token',
        method: 'POST',
        contentType: 'application/json',
        data: {
            username: $('#emailTextbox').val(),
            password: $('#passwordBox').val(),
            grant_type: 'password'
        },

        success: function (response) {
            sessionStorage.setItem("accessToken", response.access_token);
            window.location.href = "/";
        }
    });
}