import json, hmac, hashlib, time, requests, base64
from requests.auth import AuthBase

# Create custom authentication for Exchange
class CoinbaseExchangeAuth(AuthBase):
    def __init__(self, api_key, secret_key, passphrase):
        self.api_key = api_key
        self.secret_key = secret_key
        self.passphrase = passphrase

    def __call__(self, request):
        timestamp = str(time.time())
        message = timestamp + request.method + request.path_url + (request.body or b'').decode()
        hmac_key = base64.b64decode(self.secret_key)
        signature = hmac.new(hmac_key, message.encode(), hashlib.sha256)
        signature_b64 = base64.b64encode(signature.digest()).decode()

        request.headers.update({
            'CB-ACCESS-SIGN': signature_b64,
            'CB-ACCESS-TIMESTAMP': timestamp,
            'CB-ACCESS-KEY': self.api_key,
            'CB-ACCESS-PASSPHRASE': self.passphrase,
            'Content-Type': 'application/json'
        })
        return request

class CoinbaseConnection:
    def __init__(self, API_URL, API_KEY, API_SECRET, API_PASS):
        self.url = API_URL    
        self.auth = CoinbaseExchangeAuth(API_KEY, API_SECRET, API_PASS)
        
    def get_accounts(self):
        return requests.get(self.url+'accounts', auth=self.auth)
        
    def get_account_info(self, acc_id):
        return requests.get(self.url+'accounts/'+acc_id, auth=self.auth)
    
    def get_currencies_info(self):
        return requests.get(self.url+'currencies', auth=self.auth)
    
    def convert(self, f, to, amount='0'):
        json_request = {
               "from": f,
               "to": to,
               "amount": amount
            }
        return requests.post(self.url+'conversions', auth=self.auth, json=json_request)
        
    