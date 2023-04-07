def isCoAP(type=None, code=None, msg=None, ):
    if msg.startswith("coap"):
        return True
    else:
        return False
