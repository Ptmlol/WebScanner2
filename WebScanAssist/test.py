import requests

login_url = "http://192.168.76.11/bWAPP/login.php"
username = "bee"
password = "bug"

session = requests.session()

login_data = {
    'login': 'bee',
    'password': 'buga',
    'form': 'submit',
}
login_response = session.post(login_url, data=login_data)

print(login_response.text)
# test