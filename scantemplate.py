import requests


payloads = ["22*22", "{22*22}", "{{22*22}}", "{{{22*22}}}", "#{22*22}", "${22*22}", "{{=22*22}}", "<%=22*22%>", "[[${22*22}]]"]
url = ""

def templateInjection(payloads):
    vulnerable = False
    responses = []
    for payload in payloads:
        r = requests.post(url, json = payload)
        print(r.text)
        if "484" in r.text:
            vulnerable = True
    return vulnerable


def __main__():
    vulnerable = templateInjection(payloads)
    if vulnerable:
        print("This request might be vulnerable to a Template Injection\n Trying to get the language...")
    
    
    
    else:
        exit()