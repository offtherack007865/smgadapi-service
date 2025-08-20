function LogoutandRemoveToken() {
    $.ajax({
        url: '/api/Account/Logout',
        method: 'POST',
        contentType: 'application/json',
        headers: {
            'Authorization': 'Bearer ' + sessionStorage.getItem('accessToken')
        },
        success: function (response) {
            sessionStorage.removeItem("accessToken");
            window.location.href = "/";
        }
    });
}