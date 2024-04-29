import requests
from requests import Session, Request

s = Session()
req = Request('GET', 'https://www.google.com')
prepped = s.prepare_request(req)
