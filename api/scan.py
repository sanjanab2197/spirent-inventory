import json
from scan_utils import scan_network

def handler(request):
    try:
        data = json.loads(request.body)
        subnet = data.get("subnet")
        if not subnet:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "Subnet is required"})
            }

        result = scan_network(subnet)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(result)
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(e)})
        }
